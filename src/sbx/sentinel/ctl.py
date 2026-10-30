"""Security-team CLI inside the sentinel pod (reach it with `kubectl exec`, i.e. cluster access to the
sbx-security namespace is the authorisation). Talks to the sentinel's localhost-only admin API.

  python -m sbx.sentinel.ctl status | alerts [N] | freeze REASON | unfreeze | release SID
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
                  f"{what}" + (f"  verified={e['verified']}" if "verified" in e else ""))
    elif cmd == "freeze":
        print(json.dumps(call("freeze", {"actor": actor, "reason": " ".join(rest) or "manual"})))
    elif cmd == "release":
        print(json.dumps(call("release", {"actor": actor, "session_id": rest[0]})))
    else:
        print(json.dumps(call(cmd, {"actor": actor}), indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
