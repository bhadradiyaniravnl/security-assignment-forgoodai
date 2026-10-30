"""Lab destination ("attacker-sink" / "paste-mock"), outside the platform in its own namespace.

Accepts any method and path on :8080 (HTTP) and :8443 (TLS, lab certificate) and records every
request it receives, headers and full body, as one JSON line on stdout and in RECEIPTS_FILE.
These receipts are the ground truth for whether a canary left the platform: the security tests
check them independently of the gateway's own evidence. Not an enforcement point; it trusts
nothing and decides nothing.
"""
import asyncio
import base64
import json
import os
import ssl
import time

from aiohttp import web

NAME = os.environ.get("SINK_NAME", "sink")
RECEIPTS_FILE = os.environ.get("RECEIPTS_FILE", "/data/receipts.jsonl")
TLS_CERT = os.environ.get("TLS_CERT", "/etc/lab-tls/tls.crt")
TLS_KEY = os.environ.get("TLS_KEY", "/etc/lab-tls/tls.key")


async def record(request: web.Request) -> web.Response:
    """Append a receipt for the request and answer 200."""
    body = await request.read()
    receipt = {
        "ts": time.time(),
        "sink": NAME,
        "scheme": request.scheme,
        "peer": request.remote,
        "method": request.method,
        "path": request.path_qs,
        "headers": dict(request.headers),
        "body_b64": base64.b64encode(body).decode(),
        "body_len": len(body),
    }
    line = json.dumps(receipt)
    print(line, flush=True)
    with open(RECEIPTS_FILE, "a") as f:
        f.write(line + "\n")
    return web.json_response({"ok": True, "sink": NAME})


async def main() -> None:
    os.makedirs(os.path.dirname(RECEIPTS_FILE), exist_ok=True)
    app = web.Application(client_max_size=10 * 1024 * 1024)
    app.router.add_route("*", "/{tail:.*}", record)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 8080).start()
    tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    tls.load_cert_chain(TLS_CERT, TLS_KEY)
    await web.TCPSite(runner, "0.0.0.0", 8443, ssl_context=tls).start()
    print(json.dumps({"sink": NAME, "msg": "listening", "ports": [8080, 8443]}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
