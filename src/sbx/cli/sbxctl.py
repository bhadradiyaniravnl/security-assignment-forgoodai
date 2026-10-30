"""sbxctl: CLI for the sandboxed agent platform (stdlib only, runs on the host).

  sbxctl run bugfix-agent -p repo=demo/app -p task="Make the tests pass" [-f]
  sbxctl ls | status SID | logs SID [-f] [--raw] | stop SID | diff SID | destroy SID
  sbxctl send SID "follow-up instruction" [-f] | attach SID
  sbxctl contain SID | alerts | freeze "reason" | unfreeze   (freeze/unfreeze: security admins)
  sbxctl spec approve FILE (security approver) | spec register FILE | spec ls
"""
from __future__ import annotations

# The docstring above doubles as `--help` text. Not in it: the CLI trusts the control plane, sends
# the user as X-User (prototype identity), and treats every agent-derived string (logs, diffs,
# status, alert summaries) as hostile terminal input to be passed through safe().

import argparse
import getpass
import threading
import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("SBX_API", "http://127.0.0.1:8443")
USER = os.environ.get("SBX_USER", getpass.getuser())
# Agent output and diffs are attacker-controlled: never let them reach the terminal as control
# sequences (OSC 52 clipboard writes, cursor moves that hide lines, title changes, ...).
_CONTROL_CHAR_ESCAPES = {c: f"\\x{c:02x}" for c in list(range(0x00, 0x20)) + list(range(0x7f, 0xa0))
                         if c not in (0x0a, 0x09)}


def safe(text: str) -> str:
    """Renders C0/C1 control characters (except newline and tab) as visible \\xNN escapes."""
    return text.translate(_CONTROL_CHAR_ESCAPES)


def call(method: str, path: str, body: dict | bytes | None = None, stream: bool = False):
    """One control-plane request as USER. bytes bodies are sent as YAML (specs), dicts as JSON.
    Exits with the server's error detail on failure; returns the open response when `stream`."""
    raw = isinstance(body, bytes)
    req = urllib.request.Request(API + path, method=method,
                                 headers={"X-User": USER, "Content-Type": "application/yaml" if raw else "application/json"},
                                 data=body if raw else (json.dumps(body).encode() if body is not None else None))
    try:
        resp = urllib.request.urlopen(req, timeout=None if stream else 300)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            detail = json.loads(detail).get("detail", detail)
        except ValueError:
            pass
        if isinstance(detail, dict) and detail.get("reasons"):
            detail = detail["error"] + "".join(f"\n  - {r}" for r in detail["reasons"])
        sys.exit(f"error {e.code}: {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"control plane unreachable at {API}: {e.reason}")
    if stream:
        return resp
    data = resp.read().decode()
    ctype = resp.headers.get("content-type", "")
    return json.loads(data) if "json" in ctype else data


def pretty(line: str) -> str | None:
    """Condenses Claude Code stream-json into readable progress lines (None: nothing to show).
    `{"sbx": ...}` lines are the sandbox entrypoint's own status events."""
    try:
        ev = json.loads(line)
    except ValueError:
        return line.rstrip() or None
    if "sbx" in ev:
        return (f"[sbx] {ev['sbx']}" + (f" turn={ev['turn']}" if "turn" in ev else "")
                + (f" code={ev['code']}" if "code" in ev else ""))
    kind = ev.get("type")
    if kind == "system" and ev.get("subtype") == "init":
        return f"[init] model={ev.get('model')} tools={len(ev.get('tools', []))}"
    if kind == "assistant":
        out = []
        for block in ev.get("message", {}).get("content", []):
            if block.get("type") == "text" and block["text"].strip():
                out.append("[assistant] " + block["text"].strip().replace("\n", "\n            "))
            elif block.get("type") == "tool_use":
                out.append(f"[tool] {block['name']} {json.dumps(block.get('input', {}))[:200]}")
        return "\n".join(out) or None
    if kind == "user":
        for block in ev.get("message", {}).get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_result":
                content = block.get("content")
                text = content if isinstance(content, str) else json.dumps(content)
                return f"[result{' ERROR' if block.get('is_error') else ''}] {text[:200]}"
    if kind == "result":
        return f"[done] {ev.get('subtype')} turns={ev.get('num_turns')} cost=${ev.get('total_cost_usd', 0):.4f}"
    return None


def is_exit(text: str) -> bool:
    """True for the entrypoint's agent_exit event, which ends a followed stream."""
    return '"sbx":"agent_exit"' in text.replace(" ", "")


def open_logs(sid: str, follow: bool, tail: int | None = None):
    """Opens the session's log stream (pod stdout: untrusted)."""
    q = f"follow={'true' if follow else 'false'}" + (f"&tail={tail}" if tail is not None else "")
    return call("GET", f"/sessions/{sid}/logs?{q}", stream=True)


def print_logs(resp, raw: bool, stop_at_exit: bool) -> None:
    """Prints a log stream, condensed unless `raw`, always through safe()."""
    for line in resp:
        text = line.decode(errors="replace")
        out = text.rstrip() if raw else pretty(text)
        if out:
            print(safe(out), flush=True)
        if stop_at_exit and is_exit(text):
            break


def follow_logs(sid: str, follow: bool, raw: bool) -> None:
    """`logs` / `run -f`: a condensed followed stream stops at agent exit; a raw one does not."""
    print_logs(open_logs(sid, follow), raw, stop_at_exit=not raw)


def send(sid: str, text: str, follow: bool) -> None:
    """Opens the live stream first (tail=0: only new output), then posts, so nothing is missed."""
    stream = open_logs(sid, True, tail=0) if follow else None
    r = call("POST", f"/sessions/{sid}/messages", {"text": text})
    print(f"sent turn {r['turn']} to {sid}", flush=True)
    if stream:
        print_logs(stream, False, stop_at_exit=True)


def attach(sid: str) -> None:
    """Replays recent history, then streams live while each line you type becomes a follow-up.
    Ctrl-D detaches; the session keeps running (stop/destroy it explicitly)."""
    s = call("GET", f"/sessions/{sid}")
    print(f"attached to {sid} ({s['spec_name']}, {s['state']}, turns={s.get('turns') or 0}). "
          "Type a follow-up and press Enter; Ctrl-D to detach.", flush=True)
    print_logs(open_logs(sid, False, tail=40), False, stop_at_exit=False)
    live = open_logs(sid, True, tail=0)
    threading.Thread(target=print_logs, args=(live, False, False), daemon=True).start()
    try:
        while True:
            line = input()
            if line.strip():
                r = call("POST", f"/sessions/{sid}/messages", {"text": line})
                print(f"[you] turn {r['turn']}: {line}", flush=True)
    except (EOFError, KeyboardInterrupt):
        print(f"\ndetached; {sid} is still running (sbxctl stop {sid} when done)")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="sbxctl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    run_cmd = sub.add_parser("run", help="start a session from an agent spec")
    run_cmd.add_argument("spec")
    run_cmd.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE")
    run_cmd.add_argument("-f", "--follow", action="store_true", help="stream progress until the agent exits")
    sub.add_parser("ls", help="list your sessions")
    sub.add_parser("alerts", help="detections and containment verifications for your sessions")
    fz = sub.add_parser("freeze", help="fleet kill switch: contain every live session, block new runs")
    fz.add_argument("reason", nargs="?", default="manual")
    sub.add_parser("unfreeze", help="lift the fleet freeze (frozen sessions stay contained)")
    sd = sub.add_parser("send", help="send a follow-up; the agent resumes the same conversation")
    sd.add_argument("sid")
    sd.add_argument("text")
    sd.add_argument("-f", "--follow", action="store_true", help="stream that turn until the agent finishes it")
    sub.add_parser("attach", help="stream live and type follow-ups interactively").add_argument("sid")
    sp = sub.add_parser("spec", help="register or list agent specs")
    sp.add_argument("action", choices=["register", "approve", "ls"])
    sp.add_argument("file", nargs="?")
    for name in ("status", "stop", "diff", "destroy", "contain"):
        sub.add_parser(name).add_argument("sid")
    lg = sub.add_parser("logs", help="agent progress (from pod stdout; not security evidence)")
    lg.add_argument("sid")
    lg.add_argument("-f", "--follow", action="store_true")
    lg.add_argument("--raw", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "run":
        params = dict(p.split("=", 1) for p in args.param)
        s = call("POST", "/runs", {"spec": args.spec, "params": params})
        print(f"session {s['session_id']} started  spec={s['spec']}  digest={s['spec_digest'][:19]}…")
        if args.follow:
            follow_logs(s["session_id"], True, False)
    elif args.cmd == "ls":
        for s in call("GET", "/sessions"):
            print(f"{s['session_id']:<11} {s['state']:<10} {s['spec_name']:<18} {s['params'].get('repo', ''):<12} "
                  f"{s.get('detail') or ''}")
    elif args.cmd == "status":
        print(safe(json.dumps(call("GET", f"/sessions/{args.sid}"), indent=2)))
    elif args.cmd == "logs":
        follow_logs(args.sid, args.follow, args.raw)
    elif args.cmd == "stop":
        print(json.dumps(call("POST", f"/sessions/{args.sid}/stop")))
    elif args.cmd == "diff":
        print(safe(call("GET", f"/sessions/{args.sid}/diff")), end="")
    elif args.cmd == "send":
        send(args.sid, args.text, args.follow)
    elif args.cmd == "attach":
        attach(args.sid)
    elif args.cmd == "freeze":
        print(json.dumps(call("POST", "/admin/freeze", {"reason": args.reason}), indent=2))
    elif args.cmd == "unfreeze":
        print(json.dumps(call("POST", "/admin/unfreeze", {})))
    elif args.cmd == "contain":
        r = call("POST", f"/sessions/{args.sid}/contain")
        print(json.dumps({k: r.get(k) for k in ("session_id", "state", "probe", "probe_blocked", "elapsed_s", "snapshot")},
                         indent=2))
    elif args.cmd == "alerts":
        for alert in call("GET", "/alerts"):
            containment = alert.get("containment") or {}
            print(safe(f"{alert['seq']:>4} {alert['rule']:<3} {alert['severity']:<6} {alert.get('session_id') or '-':<10} "
                       f"user={alert.get('user')} spec={alert.get('spec')}") + f"\n     {safe(alert['summary'])}"
                  + (f"\n     contained in {containment.get('elapsed_s')}s probe_blocked={containment.get('probe_blocked')}"
                     if containment.get('quarantined_at') else ""))
    elif args.cmd == "spec" and args.action == "register":
        if not args.file:
            sys.exit("spec register needs a FILE")
        r = call("POST", "/specs", open(args.file, "rb").read())
        print(f"registered {r['name']} v{r['version']} {r['digest'][:19]}…" + (" (unchanged)" if r.get("unchanged") else ""))
        for w in r.get("warnings", []):
            print(f"  warning: {w}")
    elif args.cmd == "spec" and args.action == "approve":
        if not args.file:
            sys.exit("spec approve needs a FILE")
        r = call("POST", "/specs/approvals", open(args.file, "rb").read())
        print(f"approved {r['name']} v{r['version']} {r['digest'][:19]}… by {r['approved_by']}")
    elif args.cmd == "spec":
        for r in call("GET", "/specs"):
            print(f"{r['name']:<20} v{r['version']:<3} {r['digest'][:19]}…  by {r['registered_by']:<17} "
                  f"warnings={len(json.loads(r['warnings']))}")
    elif args.cmd == "destroy":
        print(json.dumps(call("DELETE", f"/sessions/{args.sid}")))


if __name__ == "__main__":
    main()
