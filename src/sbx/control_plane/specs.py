"""Agent specs: registry (baseline-checked, versioned, immutable), parameter validation and
compilation into a per-session policy. Runs always use the latest *registered* version, bound
by digest; nothing reads spec files at run time."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re

import jsonschema
import yaml

from sbx.control_plane import baseline

SPECS_DIR = os.environ.get("SPECS_DIR", "/app/specs")
SPEC_AUTHORS = set(filter(None, os.environ.get("SBX_SPEC_AUTHORS", "").split(",")))
SECURITY_APPROVERS = set(filter(None, os.environ.get("SBX_SECURITY_APPROVERS", "secops").split(",")))
NAME_RE = re.compile(r"^[a-z0-9-]{1,63}$")


class SpecError(ValueError):
    def __init__(self, msg: str, details: list | None = None):
        super().__init__(msg)
        self.details = details or []


def digest_of(raw: bytes) -> str:
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
    reasons = []
    if prev is None:
        reasons.append("new spec")
    else:
        reasons += widening(prev, spec)
    tools = spec["spec"].get("agentTools", {}).get("allow", [])
    if any(t in baseline.BASELINE["broad_tools"] for t in tools):
        reasons.append("unrestricted Bash")
    return reasons


def widening(old: dict, new: dict) -> list[str]:
    """Everything the new version can do that the old one could not, over the whole compiled policy."""
    o, n = compile_policy(old), compile_policy(new)
    out = []
    for k in ("egress_allow", "model_allow", "grants", "agent_tools"):
        added = sorted(set(n[k]) - set(o[k]))
        if added:
            out.append(f"new {k} {added}")
    for k in ("image", "runtime_class"):
        if n["runtime"][k] != o["runtime"][k]:
            out.append(f"runtime.{k} changed")
    for k, conv in (("ttl_s", float), ("cpu", float), ("memory", baseline._mem_gi)):
        if (conv(n["runtime"][k]) or 0) > (conv(o["runtime"][k]) or 0):
            out.append(f"larger runtime.{k}")
    if n["max_tokens"] > o["max_tokens"]:
        out.append("larger token budget")
    if (n["deny_burst"]["count"] > o["deny_burst"]["count"]
            or n["deny_burst"]["window_s"] < o["deny_burst"]["window_s"]):
        out.append("weaker D2 burst threshold")
    if n["output"]["type"] != o["output"]["type"] or (o["output"]["draft"] and not n["output"]["draft"]):
        out.append("output type/draft changed")
    removed = sorted(set(o["output"]["protected_paths"]) - set(n["output"]["protected_paths"]))
    if removed:
        out.append(f"protected paths removed {removed}")
    if set(new["metadata"].get("owners", [])) - set(old["metadata"].get("owners", [])):
        out.append("new owners")
    if new["spec"].get("mcp") != old["spec"].get("mcp"):
        out.append("mcp changed")
    if not all(any(fnmatch.fnmatchcase(p, q) for q in old["spec"]["repo"]["allow"])
               for p in new["spec"]["repo"]["allow"]):
        out.append("broader repo.allow")
    return out


def bootstrap(store) -> list[dict]:
    """Registers the specs shipped with the deployment through the same baseline gate."""
    out = []
    for f in sorted(os.listdir(SPECS_DIR)):
        if f.endswith(".yaml"):
            raw = open(os.path.join(SPECS_DIR, f), "rb").read()
            try:
                out.append(register(store, raw, "system:bootstrap"))
            except SpecError as e:
                out.append({"file": f, "rejected": e.details or str(e)})
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


def _seconds(ttl: str) -> int:
    m = re.fullmatch(r"(\d+)([smh])", str(ttl))
    if not m:
        raise SpecError(f"bad ttl {ttl}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


def compile_policy(spec: dict) -> dict:
    """Flattens the spec into what the enforcement points need. Frozen per session."""
    s = spec["spec"]
    burst = s.get("detection", {}).get("denyBurst", {"count": 5, "window": "60s"})
    return {
        "egress_allow": list(s.get("egress", {}).get("allow", [])),
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
        "deny_burst": {"count": int(burst["count"]), "window_s": _seconds(burst["window"])},
        "runtime": {
            "image": s["runtime"]["image"],
            "runtime_class": s["runtime"]["runtimeClass"],
            "cpu": str(s["runtime"]["resources"]["cpu"]),
            "memory": str(s["runtime"]["resources"]["memory"]),
            "ttl_s": _seconds(s["runtime"]["ttl"]),
        },
    }
