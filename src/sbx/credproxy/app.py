"""Credentials proxy: the only holder of real secrets and the only path out of the cluster.

  :9000  HTTP  /anthropic/<path>  -> api.anthropic.com, real x-api-key injected
               /egress            -> plain-HTTP target from X-Sbx-Target (allowlist re-checked)
  :9001  TCP   tunnel for CONNECT (one JSON line handshake, then raw bytes)

Callers are authenticated (shared internal key) and must name a session; every grant is
re-checked against that session's compiled policy, so a confused or compromised gateway
cannot obtain a credential the spec never granted. Secrets are never returned to callers.
"""
from __future__ import annotations

import asyncio
import json
import os
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

from sbx.common import internal
from sbx.common.policy import ControlPlane, host_allowed

ANTHROPIC_URL = os.environ.get("ANTHROPIC_UPSTREAM", "https://api.anthropic.com")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_WORKSPACE = os.environ.get("ANTHROPIC_WORKSPACE_ID", "")   # only for keys not scoped to a workspace
GRANT_ANTHROPIC = "anthropic/default"

HOP = {"connection", "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer",
       "transfer-encoding", "upgrade", "host", "content-length"}
STRIP = HOP | {"authorization", "x-api-key"}

cp = ControlPlane()


async def session_policy(request: web.Request) -> dict:
    if not internal.check(request.headers.get(internal.HEADER)):
        raise web.HTTPUnauthorized(text="internal auth required")
    sid = request.headers.get("X-Sbx-Session", "")
    status, body = await cp.policy(sid)
    if status != 200 or body.get("state") != "running":
        raise web.HTTPForbidden(text=f"session not running: {sid}")
    return body


def clean_headers(headers) -> dict:
    out = {k: v for k, v in headers.items()
           if k.lower() not in STRIP | {"accept-encoding"} and not k.lower().startswith("x-sbx-")}
    out["Accept-Encoding"] = "identity"   # the gateway inspects response bodies; keep them uncompressed
    return out


async def relay(request: web.Request, upstream: aiohttp.ClientResponse) -> web.StreamResponse:
    resp = web.StreamResponse(status=upstream.status,
                              headers={k: v for k, v in upstream.headers.items() if k.lower() not in HOP})
    await resp.prepare(request)
    async for chunk in upstream.content.iter_any():
        await resp.write(chunk)
    await resp.write_eof()
    return resp


async def anthropic(request: web.Request) -> web.StreamResponse:
    ctx = await session_policy(request)
    if GRANT_ANTHROPIC not in ctx["policy"].get("grants", []):
        raise web.HTTPForbidden(text="credential not granted by spec")
    headers = clean_headers(request.headers)
    headers["x-api-key"] = ANTHROPIC_KEY
    headers.pop("anthropic-workspace-id", None)
    if ANTHROPIC_WORKSPACE:
        headers["anthropic-workspace-id"] = ANTHROPIC_WORKSPACE
    url = f"{ANTHROPIC_URL}/{request.match_info['tail']}"
    async with request.app["http"].request(request.method, url, params=request.query, headers=headers,
                                           data=await request.read()) as up:
        return await relay(request, up)


async def egress(request: web.Request) -> web.StreamResponse:
    ctx = await session_policy(request)
    target = request.headers.get("X-Sbx-Target", "")
    parts = urlsplit(target)
    if parts.scheme != "http" or not parts.hostname or not host_allowed(parts.hostname, ctx["policy"].get("egress_allow", [])):
        raise web.HTTPForbidden(text="destination not allowed by spec")
    async with request.app["http"].request(request.method, target, headers=clean_headers(request.headers),
                                           data=await request.read(), allow_redirects=False) as up:
        return await relay(request, up)


async def tunnel(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
        if not internal.check(hello.get("key")):
            raise PermissionError("internal auth")
        status, ctx = await cp.policy(hello.get("session_id", ""))
        if status != 200 or ctx.get("state") != "running":
            raise PermissionError("session not running")
        host, port = hello["host"], int(hello["port"])
        if not host_allowed(host, ctx["policy"].get("egress_allow", [])):
            raise PermissionError("destination not allowed by spec")
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
    except Exception as e:  # noqa: BLE001 - any failure closes the tunnel
        writer.write(f"ERR {type(e).__name__}: {e}\n".encode())
        await writer.drain()
        writer.close()
        return
    writer.write(b"OK\n")
    await writer.drain()
    await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while data := await src.read(65536):
            dst.write(data)
            await dst.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        dst.close()


async def main() -> None:
    if not ANTHROPIC_KEY:
        raise SystemExit("ANTHROPIC_API_KEY not set")
    app = web.Application(client_max_size=32 * 1024 * 1024)
    app["http"] = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600), auto_decompress=False)
    app.router.add_route("*", "/anthropic/{tail:.*}", anthropic)
    app.router.add_route("*", "/egress", egress)
    app.router.add_get("/healthz", lambda r: web.json_response({"ok": True}))
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 9000).start()
    await asyncio.start_server(tunnel, "0.0.0.0", 9001)
    print(json.dumps({"credproxy": "listening", "ports": [9000, 9001]}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
