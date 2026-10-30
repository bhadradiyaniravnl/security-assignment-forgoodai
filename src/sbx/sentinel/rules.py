"""Sentinel detection rules (pure functions + small state; I/O lives in main.py).

Severity, response, thresholds and allowlists come from the detection policy (policy.py); the values
below are the built-in defaults. Rules emit alerts with a `stage`; the policy decides what happens.

Sources: platform evidence shipped to the sentinel (claims, chain-verified on arrival) and Hubble
flows (L3/L4, produced by Cilium's eBPF datapath, independent of every platform pod).

  D1  canary (any supported encoding) in an outbound egress request        high    contain
  D2  spec denial (gateway) or dropped flow (Hubble) from a session         medium  first per session
      ... reaching the spec's denyBurst threshold within its window         high    contain
  D3  model tool_use referencing the canary, or an acting tool referencing .env / a non-allowed host
  EV  shipped evidence chain broken or a sequence gap                       high    alert only
  S1  datapath saw materially more requests than the gateway logged         high    contain   (main.py)
  S2  platform pod: policy-dropped connection, or world egress by anything other than credproxy, or
      credproxy reaching a name outside its allowlist                       high    alert (isolation needs approval)
  S6  traffic forwarded from a session after its quarantine took effect     high    re-quarantine
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from datetime import datetime

from sbx.sentinel.policy import Policy, default_policy


def _id(*parts) -> str:
    return "al_" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def alert(rule, severity, sid, summary, action, evidence, key="", stage=None) -> dict:
    """severity is the rule's built-in default; the active policy may override it in main.respond()."""
    return {"alert_id": _id(rule, sid, key or summary), "rule": rule, "severity": severity, "session_id": sid,
            "summary": summary, "observed": action, "evidence": evidence, "stage": stage}


class Engine:
    def __init__(self):
        self.pol: Policy = default_policy()                      # swapped by main on a policy load
        self.denials: dict[str, deque] = defaultdict(deque)      # sid -> timestamps
        self.first_denial: set[str] = set()
        self.burst_fired: set[str] = set()
        self.recent_drops: dict[tuple, float] = {}                # dedupe TCP retransmits
        self.drops_by_session: dict[str, list] = defaultdict(list)

    # ---- gateway evidence -------------------------------------------------------------
    def on_gateway(self, e: dict, policy: dict | None) -> list[dict]:
        sid, act, out = e.get("session_id"), e.get("action"), []
        ref = [{"source": "gateway", "seq": e.get("seq"), "hash": e.get("hash")}]
        action = {k: e.get(k) for k in ("action", "method", "dest_host", "dest_port", "path", "decision", "reason",
                                         "bytes_out", "model", "tool") if e.get(k) is not None}
        if not sid:
            return out
        if act in ("egress_http", "egress_deny") and e.get("canary_match"):
            m = e["canary_match"]
            out.append(alert("D1", "high", sid,
                             f"canary {m['id']} ({m['encoding']}) sent in {e.get('method')} to {e.get('dest_host')} "
                             f"[{e.get('decision')}]", action, ref, key=e.get("seq")))
        if e.get("decision") == "deny" and e.get("reason") in set(self.pol.param("D2", "deny_reasons") or []):
            out += self._denial(sid, e.get("ts"), f"gateway denied {act} to {e.get('dest_host') or e.get('model')} "
                                                  f"({e.get('reason')})", action, ref, policy)
        # Host/.env references only count for tools that can act on them; an Edit that quotes the
        # injected comment (e.g. to delete it) is not an attempt. A canary in ANY tool input counts:
        # writing the secret into code or a message is itself a leak.
        tool = e.get("tool") or ""
        acting = tool in set(self.pol.param("D3", "acting_tools") or []) or \
            any(tool.startswith(p) for p in self.pol.param("D3", "acting_tool_prefixes") or [])
        if act == "ai_tool_use" and (e.get("canary_match") or
                                     (acting and (e.get("refs_env_file") or e.get("refs_disallowed_hosts")))):
            why = [w for w, hit in (("canary", e.get("canary_match")), (".env", e.get("refs_env_file")),
                                    (f"hosts {e.get('refs_disallowed_hosts')}", e.get("refs_disallowed_hosts"))) if hit]
            out.append(alert("D3", "medium", sid, f"model requested {e.get('tool')} referencing {', '.join(why)}",
                             {**action, "input": (e.get("input") or "")[:300]}, ref, key=e.get("seq")))
        return out

    # ---- Hubble flows -----------------------------------------------------------------
    def on_flow(self, f: dict, policy_for) -> list[dict]:
        if f.get("verdict") != "DROPPED":
            return []
        src = f.get("source", {})
        if src.get("namespace") != "sbx-sessions":
            return []
        sid = next((l.split("=", 1)[1] for l in src.get("labels", []) if l.startswith("k8s:sbx/session=")), None)
        if not sid:
            return []
        dst, l4 = f.get("destination", {}), f.get("l4", {})
        proto = next(iter(l4), "?")
        port = (l4.get(proto) or {}).get("destination_port")
        ip = f.get("IP", {}).get("destination")
        ts = _ts(f.get("time"))
        self.drops_by_session[sid].append({"time": ts, "dst": ip, "port": port, "proto": proto})
        key = (sid, ip, port, proto)
        if ts - self.recent_drops.get(key, 0) < 5:                 # one attempt, many retransmits
            return []
        self.recent_drops[key] = ts
        target = f"{dst.get('namespace', '')}/{dst.get('pod_name', '')}".strip("/") or ip
        action = {"action": "flow_dropped", "proto": proto, "dest": target, "dest_ip": ip, "dest_port": port,
                  "drop_reason": f.get("drop_reason_desc")}
        ref = [{"source": "hubble", "time": f.get("time"), "node": f.get("node_name")}]
        return self._denial(sid, ts, f"dropped {proto} to {target}:{port} ({f.get('drop_reason_desc')})",
                            action, ref, policy_for(sid))

    # ---- D2 ---------------------------------------------------------------------------
    def _denial(self, sid, ts, summary, action, ref, policy) -> list[dict]:
        out = []
        if policy is None or policy.get("state") != "running":
            return out
        burst = policy["policy"].get("deny_burst") or self.pol.param("D2", "default_burst")   # agent spec wins
        if sid not in self.first_denial:
            self.first_denial.add(sid)
            out.append(alert("D2", "medium", sid, f"first denial: {summary}", action, ref, key="first", stage="first"))
        q = self.denials[sid]
        q.append(ts)
        while q and ts - q[0] > burst["window_s"]:
            q.popleft()
        if len(q) >= burst["count"] and sid not in self.burst_fired:
            self.burst_fired.add(sid)
            out.append(alert("D2", "high", sid, f"{len(q)} denials within {burst['window_s']}s (latest: {summary})",
                             action, ref, key="burst"))
        return out


def _ts(value) -> float:
    if not value:
        return 0.0
    v = re.sub(r"(\.\d{6})\d+", r"\1", str(value)).replace("Z", "+00:00")   # Hubble uses nanoseconds
    return datetime.fromisoformat(v).timestamp()


# ---------------------------------------------------------------------------------------------- S2
def platform_flow_alert(f: dict, world_allowlist: dict) -> dict | None:
    """S2: platform pods run trusted code, so a policy drop or unexpected world egress from one is a
    strong compromise (or misconfiguration) signal. The platform can't hide it: Hubble is the kernel."""
    src = f.get("source", {})
    if src.get("namespace") != "sbx-system":
        return None
    app = next((l.split("=", 1)[1] for l in src.get("labels", []) if l.startswith("k8s:app=")), "?")
    dst = f.get("destination", {})
    l4 = f.get("l4", {})
    proto = next(iter(l4), "?")
    port = (l4.get(proto) or {}).get("destination_port")
    names = f.get("destination_names") or []
    world = "reserved:world" in dst.get("labels", [])
    bucket = int(_ts(f.get("time"))) // 600     # re-alert every 10 min: alert ids are deduped across restarts
    observed = {"action": "platform_flow", "app": app, "pod": src.get("pod_name"), "dest_ip": f.get("IP", {}).get("destination"),
                "dest_port": port, "dest_names": names, "verdict": f.get("verdict"), "drop_reason": f.get("drop_reason_desc")}
    if f.get("verdict") == "DROPPED" and f.get("drop_reason_desc") == "POLICY_DENIED" and f.get("traffic_direction") == "EGRESS":
        return alert("S2", "high", None, f"platform pod {app} attempted a policy-denied connection to "
                     f"{names[0] if names else observed['dest_ip']}:{port}", observed,
                     [{"source": "hubble", "time": f.get("time")}], key=f"{app}|{observed['dest_ip']}|{port}|{bucket}")
    if f.get("verdict") == "FORWARDED" and world and f.get("traffic_direction") == "EGRESS":
        allowed = set(world_allowlist[app]) if app in world_allowlist else None
        if allowed is None or (names and not set(names) & allowed):
            return alert("S2", "high", None, f"platform pod {app} reached the outside world "
                         f"({', '.join(names) or observed['dest_ip']}:{port})", observed,
                         [{"source": "hubble", "time": f.get("time")}], key=f"{app}|{observed['dest_ip']}|{port}|{bucket}")
    return None


# ---------------------------------------------------------------------------------------------- S6
def leak_after_containment(f: dict, contained_at: float, grace_s: float = 3.0) -> dict | None:
    """S6: a contained session must be silent. Anything Cilium still forwards from its pod after the
    grace period means the quarantine didn't take (or was removed)."""
    if f.get("verdict") != "FORWARDED" or f.get("traffic_direction") != "EGRESS":
        return None
    sid = next((l.split("=", 1)[1] for l in f.get("source", {}).get("labels", []) if l.startswith("k8s:sbx/session=")), None)
    ts = _ts(f.get("time"))
    if not sid or ts < contained_at + grace_s:
        return None
    dst = f.get("destination", {})
    return alert("S6", "high", sid, f"traffic forwarded after containment to "
                 f"{dst.get('namespace', '')}/{dst.get('pod_name', '') or f.get('IP', {}).get('destination')}",
                 {"action": "flow_forwarded_after_containment", "dest_ip": f.get("IP", {}).get("destination")},
                 [{"source": "hubble", "time": f.get("time")}], key=f"{int(ts) // 30}")
