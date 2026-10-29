"""Detection rules over two independent telemetry sources.

  gateway evidence (L7, written by the gateway, never by the sandbox)
  Hubble flows     (L3/L4, produced by Cilium's eBPF datapath on the node)

  D1  canary (any supported encoding) in an outbound egress request    high    contain
  D2  spec denial (gateway) or dropped flow (Hubble) from a session     medium  first per session
      ... reaching the spec's denyBurst threshold within its window     high    contain
  D3  model tool_use referencing the canary, .env, or a non-allowed host medium  alert only
  EV  gateway evidence hash chain broken                                high    alert only
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from datetime import datetime

DENY_REASONS = {"default_deny", "model_not_allowed", "budget", "credproxy_refused"}


def _id(*parts) -> str:
    return "al_" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def alert(rule, severity, sid, summary, action, evidence, contain=False, key="") -> dict:
    return {"alert_id": _id(rule, sid, key or summary), "rule": rule, "severity": severity, "session_id": sid,
            "summary": summary, "observed": action, "evidence": evidence, "contain": contain}


class Engine:
    def __init__(self):
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
                             f"[{e.get('decision')}]", action, ref, contain=True, key=e.get("seq")))
        if e.get("decision") == "deny" and e.get("reason") in DENY_REASONS:
            out += self._denial(sid, e.get("ts"), f"gateway denied {act} to {e.get('dest_host') or e.get('model')} "
                                                  f"({e.get('reason')})", action, ref, policy)
        if act == "ai_tool_use" and (e.get("canary_match") or e.get("refs_env_file") or e.get("refs_disallowed_hosts")):
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
        burst = policy["policy"].get("deny_burst", {"count": 5, "window_s": 60})
        if sid not in self.first_denial:
            self.first_denial.add(sid)
            out.append(alert("D2", "medium", sid, f"first denial: {summary}", action, ref, key="first"))
        q = self.denials[sid]
        q.append(ts)
        while q and ts - q[0] > burst["window_s"]:
            q.popleft()
        if len(q) >= burst["count"] and sid not in self.burst_fired:
            self.burst_fired.add(sid)
            out.append(alert("D2", "high", sid, f"{len(q)} denials within {burst['window_s']}s (latest: {summary})",
                             action, ref, contain=True, key="burst"))
        return out


def _ts(value) -> float:
    if not value:
        return 0.0
    v = re.sub(r"(\.\d{6})\d+", r"\1", str(value)).replace("Z", "+00:00")   # Hubble uses nanoseconds
    return datetime.fromisoformat(v).timestamp()
