"""Sentinel detection policy: which rules run, how they are tuned, and what each one does when it fires.

Input: the YAML text of config/sentinel/detection.yaml, delivered as the ConfigMap sentinel-detection
(main.py hot-reloads it) or checked offline with `python -m sbx.sentinel.ctl validate`.
Output: a validated `Policy` (lookups for the engine, a digest of the exact text,
a summary for diffs), or a PolicyError listing every problem.
Trust: the policy text is operator input and is NOT trusted to be safe; it is validated against a
schema and against the FLOOR below, which is compiled into the image.

Detection logic stays in code (rules.py, main.py). Every VALUE comes from the policy file: severities,
response actions, thresholds and allowlists. The code holds no defaults for them; it only knows which
built-in detectors exist and which parameters each one takes (BUILTIN_RULES), so a policy that omits
one is rejected instead of silently running on a value nobody can see. A policy has:

  responses   named response actions, each a list of steps:
                quarantine            the sentinel's own deny policy on the session (sentinel-q-<sid>)
                verify                confirm the quarantine with Hubble (needs quarantine)
                freeze                the sentinel's fleet-wide deny policy (sentinel-freeze)
                notify-control-plane  best effort: control plane revokes the token, snapshots evidence
              Every alert is always recorded in the sentinel's own hash-chained log.
  rules       every built-in rule (D1-D3, EV, S1, S2, S6, POL): severity, response, all its params,
              optional stages, enabled (default true) and mode (default enforce)
              custom match rules: a source, field matchers, an optional count/window threshold

mode: enforce runs the response; monitor records the alert and the steps it WOULD have run.

The FLOOR below is compiled in and cannot be configured away: a broken or careless policy is rejected
and the sentinel keeps its last good one.
"""
from __future__ import annotations

import copy
import hashlib
import re
import time
from collections import defaultdict, deque

import yaml

STEPS = {"quarantine", "verify", "freeze", "notify-control-plane"}
SEVERITIES = ("low", "medium", "high")
MODES = ("enforce", "monitor")
SOURCES = ("gateway", "control-plane", "hubble-sessions", "hubble-platform")
OPS = {"eq", "ne", "in", "not_in", "regex", "gt", "gte", "lt", "lte", "exists", "contains"}

NUMBER = (int, float)
# The built-in detectors implemented in code and the SHAPE of their configuration: parameter name ->
# expected type, and the alert stages a rule emits. No values: those all come from the policy file.
BUILTIN_RULES: dict[str, dict] = {
    "D1": {"params": {}, "stages": ()},
    "D2": {"params": {"default_burst": dict, "deny_reasons": list}, "stages": ("first",)},
    "D3": {"params": {"acting_tools": list, "acting_tool_prefixes": list}, "stages": ()},
    "EV": {"params": {}, "stages": ()},
    "S1": {"params": {"horizon_s": NUMBER, "min_deficit": NUMBER, "min_ratio": NUMBER, "interval_s": NUMBER},
           "stages": ()},
    "S2": {"params": {"world_allowlist": dict}, "stages": ()},
    "S6": {"params": {"grace_s": NUMBER}, "stages": ()},
    "POL": {"params": {}, "stages": ()},           # a rejected policy (raised under the last good one)
}

# ------------------------------------------------------------------------------------------- floor
ALWAYS_ON = {"D1", "EV", "S6", "POL"}          # cannot be disabled or set to monitor
MUST_CONTAIN = {"D1", "S6"}                    # response must quarantine or freeze
PARAM_BOUNDS = {                               # rule -> param path -> (min, max)
    "D2": {"default_burst.count": (1, 50), "default_burst.window_s": (5, 600)},
    "S1": {"horizon_s": (5, 120), "min_deficit": (1, 20), "min_ratio": (0.0, 1.0), "interval_s": (2, 60)},
    "S6": {"grace_s": (1, 10)},
}
RULE_KEYS = {"id", "enabled", "mode", "severity", "response", "params", "stages", "description",
             "type", "source", "match", "threshold", "groupBy", "summary"}
CUSTOM_ID = re.compile(r"^[A-Z][A-Z0-9_-]{1,31}$")
MAX_CUSTOM = 100


class PolicyError(ValueError):
    """A policy that failed validation; `errors` lists every problem found, not just the first."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _lookup_path(d: dict, path: str):
    """d["a"]["b"] for path "a.b"; None if any step is missing."""
    for p in path.split("."):
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


class Policy:
    """A validated detection policy (construct it through load())."""

    def __init__(self, doc: dict, text: str, source: str):
        self.doc, self.text, self.source = doc, text, source
        self.digest = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
        meta = doc.get("metadata") or {}
        self.name, self.version = meta.get("name", "default"), meta.get("version")
        self.responses = dict(doc["spec"]["responses"])
        self.rules: dict[str, dict] = {}
        self.custom: list[dict] = []
        for r in doc["spec"]["rules"]:
            (self.rules.__setitem__(r["id"], copy.deepcopy(r)) if r["id"] in BUILTIN_RULES
             else self.custom.append(dict(r)))
        for r in list(self.rules.values()) + self.custom:
            r.setdefault("enabled", True)
            r.setdefault("mode", "enforce")
        for r in self.custom:
            r["_matchers"] = [(f, _matcher(m)) for f, m in r["match"].items()]

    # --- lookups used by the engine -----------------------------------------------------
    def enabled(self, rule: str) -> bool:
        r = self.rules.get(rule)
        return bool(r and r["enabled"])

    def param(self, rule: str, path: str):
        """A built-in rule's parameter by dotted path, e.g. param("D2", "default_burst.count")."""
        return _lookup_path(self.rules[rule].get("params", {}), path)

    def decide(self, rule: str, stage: str | None) -> dict:
        """-> {severity, mode, response, steps, enabled} for an alert of this rule (and stage)."""
        r = self.rules.get(rule) or next(c for c in self.custom if c["id"] == rule)
        overrides = (r.get("stages") or {}).get(stage or "", {})
        response = overrides.get("response", r["response"])
        return {"severity": overrides.get("severity", r["severity"]), "mode": r["mode"], "response": response,
                "steps": list(self.responses[response]["steps"]), "enabled": r["enabled"]}

    def summary(self) -> dict:
        """The effective settings per rule (what `ctl policy` shows and `ctl validate` diffs)."""
        return {"name": self.name, "version": self.version, "digest": self.digest, "source": self.source,
                "rules": {k: {"enabled": v["enabled"], "mode": v["mode"], "severity": v["severity"],
                              "response": v["response"]} for k, v in self.rules.items()},
                "custom": {c["id"]: {"enabled": c["enabled"], "mode": c["mode"], "severity": c["severity"],
                                     "response": c["response"], "source": c["source"]} for c in self.custom},
                "responses": self.responses}


# ---------------------------------------------------------------------------------------- loading
def load(text: str, source: str = "configmap") -> Policy:
    """Parse + validate against the schema and the floor. Raises PolicyError with every problem."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError([f"not valid YAML: {e}"]) from None
    try:                     # a malformed value must surface as a rejection (POL alert), not a crash
        errs = validate(doc)
        if errs:
            raise PolicyError(errs)
        p = Policy(doc, text, source)
        errs = _validate_effective(p)
    except (TypeError, ValueError, AttributeError, KeyError) as e:
        if isinstance(e, PolicyError):
            raise
        raise PolicyError([f"malformed policy: {type(e).__name__}: {e}"]) from None
    if errs:
        raise PolicyError(errs)
    return p


def validate(doc) -> list[str]:
    """Schema check of the parsed document; returns every error (empty list = valid)."""
    e: list[str] = []
    if not isinstance(doc, dict):
        return ["policy must be a mapping"]
    if doc.get("apiVersion") != "sbx.forgood.ai/v1" or doc.get("kind") != "DetectionPolicy":
        e.append("apiVersion must be sbx.forgood.ai/v1 and kind DetectionPolicy")
    if set(doc) - {"apiVersion", "kind", "metadata", "spec"}:
        e.append(f"unknown top-level fields: {sorted(set(doc) - {'apiVersion', 'kind', 'metadata', 'spec'})}")
    spec = doc.get("spec")
    if not isinstance(spec, dict) or set(spec) - {"responses", "rules"}:
        return e + ["spec must be a mapping with only 'responses' and 'rules'"]
    if not isinstance(spec.get("responses"), dict) or not spec["responses"]:
        e.append("spec.responses must define the response actions (there are no built-in ones)")
    responses = {}
    for name, r in (spec.get("responses") or {}).items():
        if not re.match(r"^[a-z][a-z0-9-]{1,31}$", str(name)):
            e.append(f"response name {name!r} must be lowercase-kebab")
        if not isinstance(r, dict) or set(r) - {"steps", "description"} or not isinstance(r.get("steps"), list):
            e.append(f"response {name}: needs a 'steps' list (and optionally 'description')")
            continue
        bad = set(r["steps"]) - STEPS
        if bad:
            e.append(f"response {name}: unknown steps {sorted(bad)} (allowed: {sorted(STEPS)})")
        if "verify" in r["steps"] and "quarantine" not in r["steps"]:
            e.append(f"response {name}: 'verify' needs 'quarantine'")
        responses[name] = r
    rules = spec.get("rules") or []
    if not isinstance(rules, list):
        return e + ["spec.rules must be a list"]
    seen, n_custom = set(), 0
    for i, r in enumerate(rules):
        where = f"rules[{i}]"
        if not isinstance(r, dict) or "id" not in r:
            e.append(f"{where}: needs an id")
            continue
        rid = r["id"]
        where = f"rule {rid}"
        if rid in seen:
            e.append(f"{where}: duplicate id")
        seen.add(rid)
        if set(r) - RULE_KEYS:
            e.append(f"{where}: unknown fields {sorted(set(r) - RULE_KEYS)}")
        if "enabled" in r and not isinstance(r["enabled"], bool):
            e.append(f"{where}: enabled must be true/false")
        if "mode" in r and r["mode"] not in MODES:
            e.append(f"{where}: mode must be one of {MODES}")
        if "severity" in r and r["severity"] not in SEVERITIES:
            e.append(f"{where}: severity must be one of {SEVERITIES}")
        for k in ("severity", "response"):
            if k not in r:
                e.append(f"{where}: needs {k} (no built-in default)")
        if "response" in r and r["response"] not in responses:
            e.append(f"{where}: unknown response {r['response']!r}")
        for sname, st in (r.get("stages") or {}).items():
            if not isinstance(st, dict) or not {"severity", "response"} <= set(st):
                e.append(f"{where}: stage {sname}: needs severity and response")
                continue
            if st.get("response") and st["response"] not in responses:
                e.append(f"{where}: stage {sname}: unknown response {st['response']!r}")
            if st.get("severity") and st["severity"] not in SEVERITIES:
                e.append(f"{where}: stage {sname}: bad severity")
        if rid in BUILTIN_RULES:
            shape = BUILTIN_RULES[rid]
            if r.get("type") == "match" or "match" in r:
                e.append(f"{where}: built-in rules take params, not match")
            params = r.get("params") or {}
            if set(params) - set(shape["params"]):
                e.append(f"{where}: unknown params {sorted(set(params) - set(shape['params']))}")
            for pname, ptype in shape["params"].items():
                if pname not in params:
                    e.append(f"{where}: needs params.{pname} (no built-in default)")
                elif not isinstance(params[pname], ptype) or isinstance(params[pname], bool):
                    e.append(f"{where}: params.{pname} has the wrong type")
            if set(r.get("stages") or {}) - set(shape["stages"]):
                e.append(f"{where}: unknown stages {sorted(set(r.get('stages') or {}) - set(shape['stages']))}")
            continue
        n_custom += 1
        e += _validate_custom(r, where)
    missing = set(BUILTIN_RULES) - seen
    if missing:
        e.append(f"every built-in rule must be configured (enabled: false to switch one off); missing {sorted(missing)}")
    if n_custom > MAX_CUSTOM:
        e.append(f"at most {MAX_CUSTOM} custom rules")
    return e


def _validate_custom(r: dict, where: str) -> list[str]:
    """Schema check of one custom match rule."""
    e = []
    if not CUSTOM_ID.match(str(r["id"])):
        e.append(f"{where}: custom ids are UPPER-kebab, 2-32 chars, and must not reuse a built-in id")
    if r.get("type") != "match":
        e.append(f"{where}: custom rules need type: match")
    if r.get("source") not in SOURCES:
        e.append(f"{where}: source must be one of {SOURCES}")
    for k in ("severity", "response"):
        if k not in r:
            e.append(f"{where}: needs {k}")
    m = r.get("match")
    if not isinstance(m, dict) or not m:
        e.append(f"{where}: match must be a non-empty mapping of field -> matcher")
    else:
        for f, spec in m.items():
            try:
                _matcher(spec)
            except ValueError as x:
                e.append(f"{where}: match.{f}: {x}")
    t = r.get("threshold")
    if t is not None:
        if not isinstance(t, dict) or set(t) - {"count", "window_s"}:
            e.append(f"{where}: threshold takes count and window_s")
        elif not (1 <= int(t.get("count", 1)) <= 1000 and 1 <= int(t.get("window_s", 60)) <= 3600):
            e.append(f"{where}: threshold count 1-1000, window_s 1-3600")
    if r.get("groupBy", "session") not in ("session", "pod", "global"):
        e.append(f"{where}: groupBy must be session, pod or global")
    return e


def _validate_effective(p: Policy) -> list[str]:
    """The floor, on the merged policy (so omitting a field can't dodge it)."""
    e = []
    for rid in ALWAYS_ON:
        r = p.rules[rid]
        if not r["enabled"] or r["mode"] != "enforce":
            e.append(f"floor: {rid} must stay enabled in enforce mode")
    for rid in MUST_CONTAIN:
        steps = set(p.responses[p.rules[rid]["response"]]["steps"])
        if not steps & {"quarantine", "freeze"}:
            e.append(f"floor: {rid}'s response must quarantine or freeze (got {p.rules[rid]['response']})")
    for rid, bounds in PARAM_BOUNDS.items():
        for path, (lo, hi) in bounds.items():
            v = p.param(rid, path)
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not lo <= v <= hi:
                e.append(f"floor: {rid}.params.{path} must be a number in [{lo}, {hi}] (got {v!r})")
    for c in p.custom:
        steps = set(p.responses[c["response"]]["steps"])
        if "freeze" in steps and c["severity"] != "high":
            e.append(f"floor: rule {c['id']}: only high-severity rules may freeze the fleet")
        if steps & {"quarantine", "verify"} and c["source"] == "hubble-platform":
            e.append(f"floor: rule {c['id']}: platform flows have no session to quarantine")
    return e


# -------------------------------------------------------------------------------- custom matching
def _matcher(spec):
    """-> predicate(value) for one field. Scalar = equals, list = in, mapping = operators (all must hold).
    A list-valued field (e.g. dest_names) matches when any element does."""
    if isinstance(spec, list):
        spec = {"in": spec}
    elif not isinstance(spec, dict):
        spec = {"eq": spec}
    if not spec or set(spec) - OPS:
        raise ValueError(f"operators must be from {sorted(OPS)}")
    preds = []
    for op, arg in spec.items():
        if op == "regex":
            if not isinstance(arg, str) or len(arg) > 200:
                raise ValueError("regex must be a string of at most 200 chars")
            try:
                rx = re.compile(arg)
            except re.error as x:
                raise ValueError(f"bad regex: {x}") from None
            preds.append(lambda v, rx=rx: v is not None and rx.search(str(v)) is not None)
        elif op in ("in", "not_in"):
            if not isinstance(arg, list):
                raise ValueError(f"{op} takes a list")
            vals = {str(a) for a in arg}
            preds.append((lambda v, s=vals: v is not None and str(v) in s) if op == "in"
                         else (lambda v, s=vals: v is None or str(v) not in s))
        elif op in ("gt", "gte", "lt", "lte"):
            if not isinstance(arg, (int, float)):
                raise ValueError(f"{op} takes a number")
            cmp = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b,
                   "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b}[op]
            preds.append(lambda v, c=cmp, a=arg: isinstance(v, (int, float)) and not isinstance(v, bool) and c(v, a))
        elif op == "exists":
            preds.append(lambda v, want=bool(arg): (v is not None) == want)
        elif op == "contains":
            preds.append(lambda v, a=str(arg): v is not None and a in str(v))
        elif op == "eq":
            preds.append(lambda v, a=arg: v == a or (v is not None and str(v) == str(a)))
        elif op == "ne":
            preds.append(lambda v, a=arg: not (v == a or (v is not None and str(v) == str(a))))
    negative = {"not_in", "ne"} >= set(spec) or spec.get("exists") is False

    def pred(v):
        if isinstance(v, list) and not negative:
            return any(all(p(x) for p in preds) for x in v)
        if isinstance(v, list):
            return all(all(p(x) for p in preds) for x in v) if v else all(p(None) for p in preds)
        return all(p(v) for p in preds)
    return pred


def flow_fields(f: dict) -> dict:
    """Friendly names for Hubble flow fields (raw dotted paths work too)."""
    src, dst, l4 = f.get("source", {}), f.get("destination", {}), f.get("l4") or {}
    proto = next(iter(l4), None)
    http = (f.get("l7") or {}).get("http") or {}
    label = lambda labels, k: next((l.split("=", 1)[1] for l in labels if l.startswith(f"k8s:{k}=")), None)  # noqa: E731
    return {"verdict": f.get("verdict"), "direction": f.get("traffic_direction"), "proto": proto,
            "dest_port": (l4.get(proto) or {}).get("destination_port") if proto else None,
            "dest_ip": (f.get("IP") or {}).get("destination"), "dest_names": f.get("destination_names") or [],
            "dest_namespace": dst.get("namespace"), "dest_pod": dst.get("pod_name"),
            "dest_world": "reserved:world" in dst.get("labels", []),
            "drop_reason": f.get("drop_reason_desc"), "src_pod": src.get("pod_name"),
            "src_app": label(src.get("labels", []), "app"), "session": label(src.get("labels", []), "sbx/session"),
            "http_method": http.get("method"), "http_url": http.get("url"), "http_code": http.get("code"),
            "l7_type": (f.get("l7") or {}).get("type")}


class _BlankFormat(dict):
    """format_map() mapping that renders unknown {fields} in a summary template as "?"."""

    def __missing__(self, k):
        return "?"


class CustomRules:
    """Evaluates the policy's custom match rules; keeps per-rule threshold windows."""

    def __init__(self):
        self.windows: dict[tuple, deque] = defaultdict(deque)

    def evaluate(self, pol: Policy, source: str, event: dict, sid: str | None) -> list[dict]:
        """Matches for one event from `source` (a shipped evidence record or a Hubble flow), as dicts
        main.py turns into alerts. Hubble flows also expose the friendly fields of flow_fields()."""
        out = []
        fields = {**flow_fields(event), **event} if source.startswith("hubble") else event
        for r in pol.custom:
            if not r["enabled"] or r["source"] != source:
                continue
            if not all(pred(fields.get(f) if f in fields else _lookup_path(event, f)) for f, pred in r["_matchers"]):
                continue
            t = r.get("threshold") or {}
            count, window = int(t.get("count", 1)), int(t.get("window_s", 60))
            group = {"session": sid, "pod": fields.get("src_pod") or event.get("pod_ip"), "global": "*"}[r.get("groupBy", "session")]
            now = time.time()
            q = self.windows[(r["id"], group)]
            q.append(now)
            while q and now - q[0] > window:
                q.popleft()
            if len(q) < count:
                continue
            q.clear()
            observed = {k: fields.get(k) for k in r["match"] if k in fields}
            summary = (r.get("summary") or f"{r['id']} matched").format_map(_BlankFormat({**fields, "count": count}))
            if count > 1:
                summary += f" ({count} within {window}s)"
            out.append({"rule": r["id"], "session_id": sid, "summary": summary,
                        "observed": {"action": f"custom_{source}", **observed},
                        "evidence": [{"source": source, "seq": event.get("seq"), "time": event.get("time")}],
                        "key": f"{group}|{int(now)}"})
        return out
