"""Evidence shipper (sidecar in the gateway pod): tails the platform's hash-chained evidence files
and pushes every record to the sentinel, which keeps its own verified copy outside the platform's
trust zone. Resumes from the sentinel's acknowledged position, so nothing is lost across restarts."""
from __future__ import annotations

import json
import os
import time
import urllib.request

FILES = ("gateway.jsonl", "control-plane.jsonl")
DIR = os.environ.get("EVIDENCE_DIR", "/evidence")
URL = os.environ.get("SENTINEL_URL", "http://sentinel.sbx-security.svc:9100")
KEY = os.environ.get("SENTINEL_INGEST_KEY", "")
BATCH = 200


def post(path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(URL + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Sbx-Ingest": KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def main() -> None:
    offsets: dict[str, int] = {}      # byte offset just past the last record the sentinel acknowledged
    prev_ack: dict[str, int] = {}
    while True:
        try:
            acked = post("/ingest/position")                    # last seq the sentinel holds, per file
            for name in FILES:
                path = os.path.join(DIR, name)
                if not os.path.exists(path):
                    continue
                last = acked.get(name, 0)
                if last < prev_ack.get(name, 0):                # sentinel lost state: resend everything
                    offsets[name] = 0
                prev_ack[name] = last
                batch = []
                with open(path) as f:
                    f.seek(offsets.get(name, 0))
                    while len(batch) < BATCH:
                        line = f.readline()
                        if not line.endswith("\n"):
                            break
                        e = json.loads(line)
                        if e["seq"] <= last:
                            offsets[name] = f.tell()
                            continue
                        batch.append(e)
                if batch:
                    post("/ingest", {"file": name, "events": batch})
        except Exception as e:  # noqa: BLE001 - keep shipping; the sentinel flags gaps itself
            print(json.dumps({"shipper_error": str(e)[:200]}), flush=True)
            time.sleep(3)
        time.sleep(1)


if __name__ == "__main__":
    main()
