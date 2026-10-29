"""sbxctl: CLI for the sandboxed agent platform (stdlib only, runs on the host).

  sbxctl run bugfix-agent -p repo=demo/app -p task="Make the tests pass" [-f]
  sbxctl ls | status SID | logs SID [-f] [--raw] | stop SID | diff SID | destroy SID
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("SBX_API", "http://127.0.0.1:8443")
USER = os.environ.get("SBX_USER", getpass.getuser())


def call(method: str, path: str, body: dict | None = None, stream: bool = False):
    req = urllib.request.Request(API + path, method=method, headers={"X-User": USER, "Content-Type": "application/json"},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        resp = urllib.request.urlopen(req, timeout=None if stream else 300)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            detail = json.loads(detail).get("detail", detail)
        except ValueError:
            pass
        sys.exit(f"error {e.code}: {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"control plane unreachable at {API}: {e.reason}")
    if stream:
        return resp
    data = resp.read().decode()
    ctype = resp.headers.get("content-type", "")
    return json.loads(data) if "json" in ctype else data


def pretty(line: str) -> str | None:
    """Condenses Claude Code stream-json into readable progress lines."""
    try:
        ev = json.loads(line)
    except ValueError:
        return line.rstrip() or None
    if "sbx" in ev:
        return f"[sbx] {ev['sbx']}" + (f" code={ev['code']}" if "code" in ev else "")
    t = ev.get("type")
    if t == "system" and ev.get("subtype") == "init":
        return f"[init] model={ev.get('model')} tools={len(ev.get('tools', []))}"
    if t == "assistant":
        out = []
        for b in ev.get("message", {}).get("content", []):
            if b.get("type") == "text" and b["text"].strip():
                out.append("[assistant] " + b["text"].strip().replace("\n", "\n            "))
            elif b.get("type") == "tool_use":
                out.append(f"[tool] {b['name']} {json.dumps(b.get('input', {}))[:200]}")
        return "\n".join(out) or None
    if t == "user":
        for b in ev.get("message", {}).get("content", []):
            if isinstance(b, dict) and b.get("type") == "tool_result":
                c = b.get("content")
                text = c if isinstance(c, str) else json.dumps(c)
                return f"[result{' ERROR' if b.get('is_error') else ''}] {text[:200]}"
    if t == "result":
        return f"[done] {ev.get('subtype')} turns={ev.get('num_turns')} cost=${ev.get('total_cost_usd', 0):.4f}"
    return None


def follow_logs(sid: str, follow: bool, raw: bool) -> None:
    resp = call("GET", f"/sessions/{sid}/logs?follow={'true' if follow else 'false'}", stream=True)
    for line in resp:
        text = line.decode(errors="replace")
        out = text.rstrip() if raw else pretty(text)
        if out:
            print(out, flush=True)
        if not raw and '"sbx": "agent_exit"' in text.replace('"sbx":"', '"sbx": "'):
            break


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="sbxctl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="start a session from an agent spec")
    r.add_argument("spec")
    r.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE")
    r.add_argument("-f", "--follow", action="store_true", help="stream progress until the agent exits")
    sub.add_parser("ls", help="list your sessions")
    for name in ("status", "stop", "diff", "destroy"):
        sub.add_parser(name).add_argument("sid")
    lg = sub.add_parser("logs", help="agent progress (from pod stdout; not security evidence)")
    lg.add_argument("sid")
    lg.add_argument("-f", "--follow", action="store_true")
    lg.add_argument("--raw", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "run":
        params = dict(p.split("=", 1) for p in a.param)
        s = call("POST", "/runs", {"spec": a.spec, "params": params})
        print(f"session {s['session_id']} started  spec={s['spec']}  digest={s['spec_digest'][:19]}…")
        if a.follow:
            follow_logs(s["session_id"], True, False)
    elif a.cmd == "ls":
        for s in call("GET", "/sessions"):
            print(f"{s['session_id']:<11} {s['state']:<10} {s['spec_name']:<18} {s['params'].get('repo', ''):<12} "
                  f"{s.get('detail') or ''}")
    elif a.cmd == "status":
        print(json.dumps(call("GET", f"/sessions/{a.sid}"), indent=2))
    elif a.cmd == "logs":
        follow_logs(a.sid, a.follow, a.raw)
    elif a.cmd == "stop":
        print(json.dumps(call("POST", f"/sessions/{a.sid}/stop")))
    elif a.cmd == "diff":
        print(call("GET", f"/sessions/{a.sid}/diff"), end="")
    elif a.cmd == "destroy":
        print(json.dumps(call("DELETE", f"/sessions/{a.sid}")))


if __name__ == "__main__":
    main()
