"""Sentinel built-in detection rules (pure functions + small per-session state; all I/O lives in main.py).

Input: one shipped gateway evidence record or one Hubble flow (JSON dict) at a time.
Output: alert dicts (see `alert()`); the rule ID, alert_id and `observed`/`evidence` fields are the
record format of the sentinel's log and the control plane's alerts, so keep them stable.

Severity, response, thresholds and allowlists come from the detection policy (detection_policy.py);
the severities below are the built-in defaults. Rules emit alerts with a `stage`; the policy decides
what happens.

What each source is trusted for: shipped platform evidence is a claim (chain-verified on arrival by
main.py); Hubble flows (L3/L4/L7, produced by Cilium's eBPF datapath) are independent of every
platform pod.

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

from sbx.sentinel.detection_policy import Policy


def _alert_id(*parts) -> str:
    """Deterministic alert id, so the same finding is raised once even across sentinel restarts."""
    return "al_" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def alert(rule, sid, summary, observed, evidence, key="", stage=None) -> dict:
    """Build an alert record. Severity and response are not decided here: main.respond() takes them
    from the detection policy (per rule, and per `stage` for multi-stage rules such as D2's first
    denial). `observed` is what was seen, `evidence` points at the source records, and `key`
    (default: the summary) distinguishes separate findings of one rule in one session."""
    return {"alert_id": _alert_id(rule, sid, key or summary), "rule": rule, "session_id": sid,
            "summary": summary, "observed": observed, "evidence": evidence, "stage": stage}


class Engine:
    """Stateful part of D1-D3: per-session denial windows and drop history. One instance, owned by main."""

    def __init__(self):
        self.pol: Policy | None = None                           # set by main before any event is processed
        self.denials: dict[str, deque] = defaultdict(deque)      # sid -> timestamps
        self.first_denial: set[str] = set()
        self.burst_fired: set[str] = set()
        self.recent_drops: dict[tuple, float] = {}                # dedupe TCP retransmits
        self.drops_by_session: dict[str, list] = defaultdict(list)

    # ---- gateway evidence -------------------------------------------------------------
    def on_gateway(self, e: dict, policy: dict | None) -> list[dict]:
        """D1, D2 (gateway denials) and D3 for one shipped gateway record `e`; `policy` is the session's."""
        sid, event_action, found = e.get("session_id"), e.get("action"), []
        evidence = [{"source": "gateway", "seq": e.get("seq"), "hash": e.get("hash")}]
        observed = {k: e.get(k) for k in ("action", "method", "dest_host", "dest_port", "path", "decision", "reason",
                                         "bytes_out", "model", "tool") if e.get(k) is not None}
        if not sid:
            return found
        if event_action in ("egress_http", "egress_deny") and e.get("canary_match"):
            m = e["canary_match"]
            found.append(alert("D1", sid,
                               f"canary {m['id']} ({m['encoding']}) sent in {e.get('method')} to {e.get('dest_host')} "
                               f"[{e.get('decision')}]", observed, evidence, key=e.get("seq")))
        if e.get("decision") == "deny" and e.get("reason") in set(self.pol.param("D2", "deny_reasons") or []):
            found += self._denial(sid, e.get("ts"), f"gateway denied {event_action} to "
                                                    f"{e.get('dest_host') or e.get('model')} ({e.get('reason')})",
                                  observed, evidence, policy)
        # Host/.env references only count for tools that can act on them; an Edit that quotes the
        # injected comment (e.g. to delete it) is not an attempt. A canary in ANY tool input counts:
        # writing the secret into code or a message is itself a leak.
        tool = e.get("tool") or ""
        acting = tool in set(self.pol.param("D3", "acting_tools") or []) or \
            any(tool.startswith(p) for p in self.pol.param("D3", "acting_tool_prefixes") or [])
        if event_action == "ai_tool_use" and (e.get("canary_match") or
                                     (acting and (e.get("refs_env_file") or e.get("refs_disallowed_hosts")))):
            why = [w for w, hit in (("canary", e.get("canary_match")), (".env", e.get("refs_env_file")),
                                    (f"hosts {e.get('refs_disallowed_hosts')}", e.get("refs_disallowed_hosts"))) if hit]
            found.append(alert("D3", sid, f"model requested {e.get('tool')} referencing {', '.join(why)}",
                               {**observed, "input": (e.get("input") or "")[:300]}, evidence, key=e.get("seq")))
        return found

    # ---- Hubble flows -----------------------------------------------------------------
    def on_flow(self, f: dict, policy_for) -> list[dict]:
        """D2 for one Hubble flow: a DROPPED flow from a session pod counts as a denial.
        `policy_for(sid)` returns that session's policy."""
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
        ts = parse_time(f.get("time"))
        self.drops_by_session[sid].append({"time": ts, "dst": ip, "port": port, "proto": proto})
        key = (sid, ip, port, proto)
        if ts - self.recent_drops.get(key, 0) < 5:                 # one attempt, many retransmits
            return []
        self.recent_drops[key] = ts
        target = f"{dst.get('namespace', '')}/{dst.get('pod_name', '')}".strip("/") or ip
        observed = {"action": "flow_dropped", "proto": proto, "dest": target, "dest_ip": ip, "dest_port": port,
                    "drop_reason": f.get("drop_reason_desc")}
        evidence = [{"source": "hubble", "time": f.get("time"), "node": f.get("node_name")}]
        return self._denial(sid, ts, f"dropped {proto} to {target}:{port} ({f.get('drop_reason_desc')})",
                            observed, evidence, policy_for(sid))

    # ---- D2 ---------------------------------------------------------------------------
    def _denial(self, sid, ts, summary, observed, evidence, policy) -> list[dict]:
        """Record one denial: alert on the session's first (stage "first"), and once more when the
        denials within the burst window reach the burst count (the agent spec's, else the policy's)."""
        found = []
        if policy is None or policy.get("state") != "running":
            return found
        burst = policy["policy"].get("deny_burst") or self.pol.param("D2", "default_burst")   # agent spec wins
        if sid not in self.first_denial:
            self.first_denial.add(sid)
            found.append(alert("D2", sid, f"first denial: {summary}", observed, evidence, key="first",
                               stage="first"))
        q = self.denials[sid]
        q.append(ts)
        while q and ts - q[0] > burst["window_s"]:
            q.popleft()
        if len(q) >= burst["count"] and sid not in self.burst_fired:
            self.burst_fired.add(sid)
            found.append(alert("D2", sid, f"{len(q)} denials within {burst['window_s']}s (latest: {summary})",
                               observed, evidence, key="burst"))
        return found


def parse_time(value) -> float:
    """Hubble's RFC 3339 timestamp (nanosecond precision) -> epoch seconds; 0.0 if missing."""
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
    bucket = int(parse_time(f.get("time"))) // 600     # re-alert every 10 min: alert ids are deduped across restarts
    observed = {"action": "platform_flow", "app": app, "pod": src.get("pod_name"), "dest_ip": f.get("IP", {}).get("destination"),
                "dest_port": port, "dest_names": names, "verdict": f.get("verdict"), "drop_reason": f.get("drop_reason_desc")}
    if f.get("verdict") == "DROPPED" and f.get("drop_reason_desc") == "POLICY_DENIED" and f.get("traffic_direction") == "EGRESS":
        return alert("S2", None, f"platform pod {app} attempted a policy-denied connection to "
                     f"{names[0] if names else observed['dest_ip']}:{port}", observed,
                     [{"source": "hubble", "time": f.get("time")}], key=f"{app}|{observed['dest_ip']}|{port}|{bucket}")
    if f.get("verdict") == "FORWARDED" and world and f.get("traffic_direction") == "EGRESS":
        allowed = set(world_allowlist[app]) if app in world_allowlist else None
        if allowed is None or (names and not set(names) & allowed):
            return alert("S2", None, f"platform pod {app} reached the outside world "
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
    ts = parse_time(f.get("time"))
    if not sid or ts < contained_at + grace_s:
        return None
    dst = f.get("destination", {})
    return alert("S6", sid, f"traffic forwarded after containment to "
                 f"{dst.get('namespace', '')}/{dst.get('pod_name', '') or f.get('IP', {}).get('destination')}",
                 {"action": "flow_forwarded_after_containment", "dest_ip": f.get("IP", {}).get("destination")},
                 [{"source": "hubble", "time": f.get("time")}], key=f"{int(ts) // 30}")
