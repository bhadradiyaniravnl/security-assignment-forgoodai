"""Agent specs: loading, parameter validation and compilation into a per-session policy.

M3 keeps this minimal (load, digest, owner check, parameter schema, compile). The org
baseline checks at registration time arrive in M6.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re

import jsonschema
import yaml

SPECS_DIR = os.environ.get("SPECS_DIR", "/app/specs")
NAME_RE = re.compile(r"^[a-z0-9-]{1,63}$")


class SpecError(ValueError):
    pass


def load(name: str) -> tuple[dict, str]:
    """Returns (spec, digest). The digest binds every session to the exact spec bytes."""
    if not NAME_RE.match(name):
        raise SpecError("invalid spec name")
    path = os.path.join(SPECS_DIR, f"{name}.yaml")
    if not os.path.exists(path):
        raise SpecError(f"unknown spec {name}")
    raw = open(path, "rb").read()
    return yaml.safe_load(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


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
        "deny_burst": {"count": int(burst["count"]), "window_s": _seconds(burst["window"])},
        "runtime": {
            "image": s["runtime"]["image"],
            "runtime_class": s["runtime"]["runtimeClass"],
            "cpu": str(s["runtime"]["resources"]["cpu"]),
            "memory": str(s["runtime"]["resources"]["memory"]),
            "ttl_s": _seconds(s["runtime"]["ttl"]),
        },
    }
