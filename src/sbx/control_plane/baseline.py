"""Org baseline for AgentSpecs (policy as code), checked when a spec is registered.

A spec that fails is rejected, never repaired at run time. Rules are deliberately boring and
explicit so an auditor can read them; production would express the same in OPA/Rego and run them
in CI on the spec repo as well as at registration.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re

BASELINE = {
    "image_prefixes": ["sbx/"],
    # Prototype exception: kind-loaded local images have no registry digest, so `sbx/*:dev` tags
    # are accepted. Everything else must be pinned by digest.
    "dev_image_tags": ["dev"],
    "runtime_classes": ["gvisor"],
    "max_ttl_s": 2 * 3600,
    "max_cpu": 4,
    "max_memory_gi": 8,
    "models": ["claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5"],
    "max_tokens": 5_000_000,
    "secret_catalogue": ["anthropic/default"],
    "approved_destinations": ["paste-mock.lab-ext"],    # destinations a spec may allowlist at all
    "repo_access": ["read"],
    "broad_tools": ["Bash", "Bash(*)", "Bash(*:*)"],     # need an explicit risk acceptance
    "policy_keys": ["egress", "secrets", "model", "runtime", "agentTools", "mcp", "detection"],   # repo is a parameter, bounded by spec.repo.allow
    "deny_burst_count": (1, 20),
}

SCHEMA = {
    "type": "object",
    "required": ["apiVersion", "kind", "metadata", "spec"],
    "additionalProperties": False,
    "properties": {
        "apiVersion": {"const": "sbx/v1"},
        "kind": {"const": "AgentSpec"},
        "metadata": {
            "type": "object", "required": ["name", "version", "owners"], "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "pattern": "^[a-z0-9-]{1,63}$"},
                "version": {"type": "integer", "minimum": 1},
                "owners": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "annotations": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
        "spec": {
            "type": "object", "required": ["runtime", "model", "repo", "egress", "secrets", "parameters"],
            "additionalProperties": False,
            "properties": {
                "runtime": {"type": "object", "required": ["image", "runtimeClass", "resources", "ttl"]},
                "model": {"type": "object", "required": ["allow", "maxTokens"]},
                "repo": {"type": "object", "required": ["allow", "access"]},
                "agentTools": {"type": "object"},
                "mcp": {"type": "array"},
                "egress": {"type": "object", "required": ["allow"]},
                "secrets": {"type": "array"},
                "detection": {"type": "object"},
                "parameters": {"type": "object"},
            },
        },
    },
}


def _ttl_s(v) -> int | None:
    m = re.fullmatch(r"(\d+)([smh])", str(v))
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)] if m else None


def _mem_gi(v) -> float | None:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(Mi|Gi)", str(v))
    return float(m.group(1)) / (1024 if m.group(2) == "Mi" else 1) if m else None


def check(spec: dict, previous: dict | None = None) -> tuple[list[str], list[str]]:
    """Returns (errors, warnings). `previous` is the latest registered version of the same spec."""
    import jsonschema

    errors: list[str] = []
    warnings: list[str] = []
    try:
        jsonschema.validate(spec, SCHEMA)
    except jsonschema.ValidationError as e:
        return [f"schema: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"], []
    s, meta = spec["spec"], spec["metadata"]
    ann = meta.get("annotations", {})
    B = BASELINE

    # runtime
    img = s["runtime"]["image"]
    if not any(img.startswith(p) for p in B["image_prefixes"]):
        errors.append(f"runtime.image {img}: not from an approved registry prefix {B['image_prefixes']}")
    if "@sha256:" not in img:
        tag = img.rsplit(":", 1)[1] if ":" in img.rsplit("/", 1)[-1] else "latest"
        if tag in B["dev_image_tags"]:
            warnings.append(f"runtime.image {img}: tag, not digest (accepted under the local-dev exception)")
        else:
            errors.append(f"runtime.image {img}: must be pinned by digest (@sha256:...)")
    if s["runtime"]["runtimeClass"] not in B["runtime_classes"]:
        errors.append(f"runtime.runtimeClass {s['runtime']['runtimeClass']}: must be one of {B['runtime_classes']}")
    ttl = _ttl_s(s["runtime"]["ttl"])
    if ttl is None or ttl > B["max_ttl_s"]:
        errors.append(f"runtime.ttl {s['runtime']['ttl']}: must be <= {B['max_ttl_s'] // 3600}h")
    res = s["runtime"].get("resources", {})
    try:
        if float(res.get("cpu", 0)) > B["max_cpu"]:
            errors.append(f"runtime.resources.cpu {res.get('cpu')}: max {B['max_cpu']}")
    except ValueError:
        errors.append(f"runtime.resources.cpu {res.get('cpu')}: not a number")
    mem = _mem_gi(res.get("memory"))
    if mem is None or mem > B["max_memory_gi"]:
        errors.append(f"runtime.resources.memory {res.get('memory')}: max {B['max_memory_gi']}Gi")

    # model
    allow = s["model"]["allow"]
    for m in allow:
        if m not in B["models"]:
            errors.append(f"model.allow {m}: not an org-approved model")
    for k in ("default", "small"):
        if k in s["model"] and s["model"][k] not in allow:
            errors.append(f"model.{k} {s['model'][k]}: not in model.allow")
    if int(s["model"]["maxTokens"]) > B["max_tokens"]:
        errors.append(f"model.maxTokens {s['model']['maxTokens']}: max {B['max_tokens']}")

    # egress: exact hostnames from the approved catalogue only
    for h in s["egress"]["allow"]:
        if any(c in h for c in "*?[]") or "/" in h:
            errors.append(f"egress.allow {h}: wildcards and URLs are not allowed; use exact hostnames")
            continue
        try:
            ipaddress.ip_address(h)
            errors.append(f"egress.allow {h}: IP literals are not allowed")
            continue
        except ValueError:
            pass
        if h not in B["approved_destinations"]:
            errors.append(f"egress.allow {h}: not in the approved destination catalogue")

    # secrets and repo
    for g in s["secrets"]:
        if g.get("ref") not in B["secret_catalogue"]:
            errors.append(f"secrets {g.get('ref')}: unknown credential (not in credproxy catalogue)")
    if s["repo"]["access"] not in B["repo_access"]:
        errors.append(f"repo.access {s['repo']['access']}: sandboxes get read-only copies; writes are the control plane's")
    for p in s["repo"]["allow"]:
        if p.strip() in ("*", "*/*", "**"):
            errors.append(f"repo.allow {p}: too broad; name an org/prefix")

    # tools: broad shell needs an explicit, attributable risk acceptance
    tools = s.get("agentTools", {}).get("allow", [])
    if any(t in B["broad_tools"] for t in tools):
        if not ann.get("riskAcceptance"):
            errors.append("agentTools: unrestricted Bash requires metadata.annotations.riskAcceptance")
        else:
            warnings.append(f"agentTools: unrestricted Bash accepted ({ann['riskAcceptance']})")

    # parameters: bounded strings only, never policy keys
    for name, schema in s["parameters"].items():
        if name in B["policy_keys"]:
            errors.append(f"parameters.{name}: policy keys cannot be run-time parameters")
        if schema.get("type") != "string" or not ("pattern" in schema or "maxLength" in schema or "enum" in schema):
            errors.append(f"parameters.{name}: must be a string bounded by pattern, maxLength or enum")

    lo, hi = B["deny_burst_count"]
    burst = s.get("detection", {}).get("denyBurst", {}).get("count", 5)
    if not lo <= int(burst) <= hi:
        errors.append(f"detection.denyBurst.count {burst}: must be within {lo}..{hi}")

    if previous:
        errors += _versioning(spec, previous)
        widened = widening(previous, spec)
        if widened and not ann.get("securityApproval"):
            errors.append("widens access (" + "; ".join(widened) + "): requires metadata.annotations.securityApproval")
        elif widened:
            warnings.append(f"widens access, approved: {ann['securityApproval']}")
    return errors, warnings


def _versioning(spec: dict, previous: dict) -> list[str]:
    v, pv = spec["metadata"]["version"], previous["metadata"]["version"]
    if v <= pv:
        return [f"metadata.version {v}: must be greater than the registered version {pv} (specs are immutable)"]
    return []


def widening(old: dict, new: dict) -> list[str]:
    """What the new version can do that the old one could not."""
    o, n, out = old["spec"], new["spec"], []
    added = set(n["egress"]["allow"]) - set(o["egress"]["allow"])
    if added:
        out.append(f"new egress {sorted(added)}")
    added = {g["ref"] for g in n["secrets"]} - {g["ref"] for g in o["secrets"]}
    if added:
        out.append(f"new secrets {sorted(added)}")
    added = set(n.get("agentTools", {}).get("allow", [])) - set(o.get("agentTools", {}).get("allow", []))
    if added:
        out.append(f"new tools {sorted(added)}")
    added = set(n["model"]["allow"]) - set(o["model"]["allow"])
    if added:
        out.append(f"new models {sorted(added)}")
    if not all(any(fnmatch.fnmatchcase(p, q) for q in o["repo"]["allow"]) for p in n["repo"]["allow"]):
        out.append("broader repo.allow")
    if (_ttl_s(n["runtime"]["ttl"]) or 0) > (_ttl_s(o["runtime"]["ttl"]) or 0):
        out.append(f"longer ttl {n['runtime']['ttl']}")
    return out
