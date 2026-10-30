"""Agent specs: registry (baseline-checked, versioned, immutable), parameter validation and
compilation into a per-session policy. Runs always use the latest *registered* version, bound
by digest; nothing reads spec files at run time.

Trust: spec YAML is author input and is trusted only after baseline.check and, where the spec is
new or widens what an agent may do, approval of its exact bytes (digest) by a security approver
other than the author. Run parameters are user input, checked against the spec's declared schema.
Roles come from env: SBX_SPEC_AUTHORS, SBX_SECURITY_APPROVERS. `system:` callers (bootstrap of the
shipped specs) skip the author and approval checks but not the baseline.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re

import jsonschema
import yaml

from sbx.control_plane import baseline

SPECS_DIR = os.environ.get("SPECS_DIR", "/app/agent-specs")
SPEC_AUTHORS = set(filter(None, os.environ.get("SBX_SPEC_AUTHORS", "").split(",")))
SECURITY_APPROVERS = set(filter(None, os.environ.get("SBX_SECURITY_APPROVERS", "secops").split(",")))
NAME_RE = re.compile(r"^[a-z0-9-]{1,63}$")


class SpecError(ValueError):
    """Invalid or rejected spec; `details` lists the individual reasons."""
    def __init__(self, msg: str, details: list | None = None):
        super().__init__(msg)
        self.details = details or []


def digest_of(raw: bytes) -> str:
    """Digest of the exact spec bytes; approvals and runs are bound to it."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def register(store, raw: bytes, by: str) -> dict:
    """Baseline-checks and stores a new spec version. Returns {name, version, digest, warnings}."""
    if by not in SPEC_AUTHORS and not by.startswith("system:"):
        raise PermissionError(f"{by} is not a spec author")
    try:
        spec = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise SpecError(f"not valid YAML: {e}") from None
    if not isinstance(spec, dict):
        raise SpecError("spec must be a mapping")
    name = (spec.get("metadata") or {}).get("name", "")
    prev_row = store.latest_spec(name) if isinstance(name, str) and NAME_RE.match(name) else None
    prev = yaml.safe_load(prev_row["body"]) if prev_row else None
    digest = digest_of(raw)
    if prev_row and prev_row["digest"] == digest:
        return {"name": name, "version": prev_row["version"], "digest": digest, "warnings": [], "unchanged": True}
    errors, warnings = baseline.check(spec, prev)
    if errors:
        raise SpecError("rejected by org baseline", errors)
    reasons = approval_reasons(spec, prev)
    if reasons and not by.startswith("system:"):
        # Two-person rule: an approver other than the author must have approved these exact bytes.
        approvers = [a for a in store.approvers_of(digest) if a in SECURITY_APPROVERS and a != by]
        if not approvers:
            raise SpecError("security approval required", [f"needs approval of digest {digest} by a security "
                                                           f"approver other than {by}: " + "; ".join(reasons)])
        warnings = warnings + [f"approved by {', '.join(approvers)}: " + "; ".join(reasons)]
    store.add_spec(name, spec["metadata"]["version"], digest, raw, by, warnings)
    return {"name": name, "version": spec["metadata"]["version"], "digest": digest, "warnings": warnings}


def approve(store, raw: bytes, by: str) -> dict:
    """A security approver approves the exact spec bytes (digest) ahead of registration."""
    if by not in SECURITY_APPROVERS:
        raise PermissionError(f"{by} is not a security approver")
    spec = yaml.safe_load(raw)
    if not isinstance(spec, dict):
        raise SpecError("spec must be a mapping")
    errors, _ = baseline.check(spec, None)
    if errors:
        raise SpecError("will not approve a spec that fails the org baseline", errors)
    name, version, digest = spec["metadata"]["name"], spec["metadata"]["version"], digest_of(raw)
    store.add_approval(digest, name, version, by)
    return {"name": name, "version": version, "digest": digest, "approved_by": by}


def approval_reasons(spec: dict, prev: dict | None) -> list[str]:
    """Why registering this spec needs a security approval (empty list: it doesn't)."""
    reasons = []
    if prev is None:
        reasons.append("new spec")
    else:
        reasons += widening(prev, spec)
    tools = spec["spec"].get("agentTools", {}).get("allow", [])
    if any(t in baseline.BASELINE["broad_tools"] for t in tools):
        reasons.append("unrestricted Bash")
    if spec["spec"].get("egress", {}).get("writeAllowed"):
        reasons.append("write access to write-capable destinations")
    return reasons


def widening(old: dict, new: dict) -> list[str]:
    """Everything the new version can do that the old one could not, over the whole compiled policy."""
    old_p, new_p = compile_policy(old), compile_policy(new)
    out = []
    for k in ("egress_allow", "egress_write", "model_allow", "grants", "agent_tools"):
        added = sorted(set(new_p[k]) - set(old_p[k]))
        if added:
            out.append(f"new {k} {added}")
    for k in ("image", "runtime_class"):
        if new_p["runtime"][k] != old_p["runtime"][k]:
            out.append(f"runtime.{k} changed")
    for k, conv in (("ttl_s", float), ("idle_s", float), ("cpu", float), ("memory", baseline._mem_gi)):
        if (conv(new_p["runtime"][k]) or 0) > (conv(old_p["runtime"][k]) or 0):
            out.append(f"larger runtime.{k}")
    if new_p["max_tokens"] > old_p["max_tokens"]:
        out.append("larger token budget")
    # The sentinel's D2 rule (denied-request burst): a higher count or shorter window fires later.
    if (new_p["deny_burst"]["count"] > old_p["deny_burst"]["count"]
            or new_p["deny_burst"]["window_s"] < old_p["deny_burst"]["window_s"]):
        out.append("weaker D2 burst threshold")
    if (new_p["output"]["type"] != old_p["output"]["type"]
            or (old_p["output"]["draft"] and not new_p["output"]["draft"])):
        out.append("output type/draft changed")
    removed = sorted(set(old_p["output"]["protected_paths"]) - set(new_p["output"]["protected_paths"]))
    if removed:
        out.append(f"protected paths removed {removed}")
    if set(new["metadata"].get("owners", [])) - set(old["metadata"].get("owners", [])):
        out.append("new owners")
    if new["spec"].get("mcp") != old["spec"].get("mcp"):
        out.append("mcp changed")
    # Not in the compiled policy (repo is a run-time parameter): every new pattern must be covered
    # by an old one.
    if not all(any(fnmatch.fnmatchcase(pattern, old_pattern) for old_pattern in old["spec"]["repo"]["allow"])
               for pattern in new["spec"]["repo"]["allow"]):
        out.append("broader repo.allow")
    return out


def bootstrap(store) -> list[dict]:
    """Registers the specs shipped with the deployment through the same baseline gate."""
    out = []
    for filename in sorted(os.listdir(SPECS_DIR)):
        if filename.endswith(".yaml"):
            raw = open(os.path.join(SPECS_DIR, filename), "rb").read()
            try:
                out.append(register(store, raw, "system:bootstrap"))
            except SpecError as e:
                out.append({"file": filename, "rejected": e.details or str(e)})
    return out


def load(store, name: str) -> tuple[dict, str]:
    """Returns (spec, digest) of the latest registered version."""
    if not NAME_RE.match(name):
        raise SpecError("invalid spec name")
    row = store.latest_spec(name)
    if row is None:
        raise SpecError(f"unknown spec {name}")
    return yaml.safe_load(row["body"]), row["digest"]


def authorize(spec: dict, user: str) -> None:
    """Only the spec's owners may start runs from it."""
    if user not in spec["metadata"].get("owners", []):
        raise PermissionError(f"user {user} may not trigger {spec['metadata']['name']}")


def validate_params(spec: dict, params: dict) -> None:
    """Only declared parameters are accepted; anything else (e.g. 'egress') is rejected."""
    declared = spec["spec"].get("parameters", {})
    schema = {"type": "object", "properties": declared, "required": list(declared), "additionalProperties": False}
    try:
        jsonschema.validate(params, schema)
    except jsonschema.ValidationError as e:
        raise SpecError(f"invalid parameters: {e.message}") from None
    repo = params.get("repo")
    if repo and not any(fnmatch.fnmatchcase(repo, p) for p in spec["spec"]["repo"]["allow"]):
        raise SpecError(f"repo {repo} not allowed by spec")


def _duration_s(value: str) -> int:
    """'90s' / '10m' / '2h' -> seconds; anything else is a SpecError."""
    m = re.fullmatch(r"(\d+)([smh])", str(value))
    if not m:
        raise SpecError(f"bad ttl {value}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


def compile_policy(spec: dict) -> dict:
    """Flattens the spec into what the enforcement points need. Frozen per session."""
    s = spec["spec"]                                    # the YAML `spec:` section
    burst = s.get("detection", {}).get("denyBurst", {"count": 5, "window": "60s"})
    return {
        "egress_allow": list(s.get("egress", {}).get("allow", [])),
        # Hosts that may receive writes and CONNECT: explicitly write-allowed ones, plus allowed hosts the
        # catalogue says don't store what they receive. Everything else in egress_allow is GET/HEAD only.
        "egress_write": sorted(set(s.get("egress", {}).get("writeAllowed", [])) | {
            h for h in s.get("egress", {}).get("allow", [])
            if not baseline.BASELINE["approved_destinations"].get(h, {}).get("accepts_writes", True)}),
        "model_allow": list(s["model"]["allow"]),
        "model_default": s["model"].get("default", s["model"]["allow"][0]),
        "model_small": s["model"].get("small", s["model"]["allow"][0]),
        "max_tokens": int(s["model"]["maxTokens"]),
        "grants": [g["ref"] for g in s.get("secrets", [])],
        "agent_tools": list(s.get("agentTools", {}).get("allow", [])),
        "output": {"type": s["repo"].get("output", {}).get("type", "branch"),
                   "base": s["repo"].get("output", {}).get("base", "main"),
                   "draft": bool(s["repo"].get("output", {}).get("draft", True)),
                   "branch_prefix": s["repo"].get("output", {}).get("branchPrefix", "agent/"),
                   "protected_paths": list(s["repo"].get("output", {}).get("protectedPaths", [".github/", ".git/"]))},
        "deny_burst": {"count": int(burst["count"]), "window_s": _duration_s(burst["window"])},
        "runtime": {
            "image": s["runtime"]["image"],
            "runtime_class": s["runtime"]["runtimeClass"],
            "cpu": str(s["runtime"]["resources"]["cpu"]),
            "memory": str(s["runtime"]["resources"]["memory"]),
            "ttl_s": _duration_s(s["runtime"]["ttl"]),
            "idle_s": _duration_s(s["runtime"].get("idleTimeout", "10m")),
        },
    }
