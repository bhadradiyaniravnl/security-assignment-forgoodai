"""Security-team CLI inside the sentinel pod (reach it with `kubectl exec`, i.e. cluster access to the
sbx-security namespace is the authorisation). Talks to the sentinel's localhost-only admin API.

  python -m sbx.sentinel.ctl status | alerts [N] | freeze REASON | unfreeze | release SID
                             policy | reload | validate FILE|-   (validate prints the diff vs the active policy)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request


def call(cmd: str, body: dict) -> object:
    req = urllib.request.Request(f"http://127.0.0.1:9101/admin/{cmd}", method="POST",
                                 data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit(__doc__)
    actor = os.environ.get("SENTINEL_ACTOR") or f"uid:{os.getuid()}"   # kubectl exec identity is in the audit log
    cmd, rest = argv[0], argv[1:]
    if cmd == "alerts":
        for e in call("alerts", {"n": int(rest[0]) if rest else 30}):
            what = e.get("summary") or e.get("action")
            print(f"{e['seq']:>5} {e.get('rule', ''):<3} {e.get('severity', ''):<6} {e.get('session_id') or '-':<10} "
                  f"{what}" + (f"  verified={e['verified']}" if "verified" in e else "")
                  + (f"  [monitor: would {'+'.join(e.get('would_run') or [])}]" if e.get("mode") == "monitor" else ""))
    elif cmd == "freeze":
        print(json.dumps(call("freeze", {"actor": actor, "reason": " ".join(rest) or "manual"})))
    elif cmd == "validate":
        import difflib

        from sbx.sentinel import policy as detpol
        text = sys.stdin.read() if not rest or rest[0] == "-" else open(rest[0]).read()
        try:
            new = detpol.load(text, source="candidate")
        except detpol.PolicyError as e:
            print("INVALID")
            for err in e.errors:
                print(f"  - {err}")
            sys.exit(1)
        active = call("policy", {"actor": actor})
        print(f"valid  {new.digest}  (active {active['digest']})")
        if new.digest == active["digest"]:
            print("no change")
        diff = list(difflib.unified_diff(active["text"].splitlines(), text.splitlines(),
                                         "active", "candidate", lineterm="", n=1))
        print("\n".join(diff[2:]) if diff else "")
        s, a = new.summary(), active
        for kind in ("rules", "custom"):
            for rid in sorted(set(s[kind]) | set(a[kind])):
                if s[kind].get(rid) != a[kind].get(rid):
                    print(f"  {rid}: {a[kind].get(rid)} -> {s[kind].get(rid)}")
    elif cmd == "release":
        print(json.dumps(call("release", {"actor": actor, "session_id": rest[0]})))
    else:
        print(json.dumps(call(cmd, {"actor": actor}), indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
