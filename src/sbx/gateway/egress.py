"""Egress gateway (:3128): authenticated forward proxy enforcing the spec's egress allowlist.

Plain HTTP: the full request is visible, so URL, headers and body are scanned for canaries
before forwarding (via credproxy /egress). CONNECT: only host:port is visible; allowed hosts
are tunnelled through credproxy, and the payload is opaque (documented blind spot).
"""
from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import urlsplit

import aiohttp

from sbx.common import internal
from sbx.common.canary import scan
from sbx.common.policy import host_allowed, normalize_host
from sbx.gateway.common import cp, evidence, session_fields, sha256

MAX_HEADER = 64 * 1024
MAX_BODY = 16 * 1024 * 1024
DROP = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "host", "content-length",
        "transfer-encoding"}


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, http: aiohttp.ClientSession) -> None:
    peer = (writer.get_extra_info("peername") or ("", 0))[0]
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        writer.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, _ = lines[0].split(" ", 2)
    except ValueError:
        return await reply(writer, 400, "bad request")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if method == "CONNECT":
        host, _, port = target.rpartition(":")
        port = int(port or 443)
        path = None
    else:
        u = urlsplit(target)
        if u.scheme != "http" or not u.hostname:
            return await reply(writer, 400, "absolute http:// URL required (use CONNECT for https)")
        host, port, path = u.hostname, u.port or 80, (u.path or "/") + (f"?{u.query}" if u.query else "")
    base = dict(pod_ip=peer, method=method, dest_host=normalize_host(host), dest_port=port, path=path)

    sid, token = _proxy_auth(headers.get("proxy-authorization", ""))
    status, ctx = await cp.validate(token, peer)
    if status != 200:
        reason = "revoked" if "session" in str(ctx.get("detail", "")) else "invalid_token"
        await evidence.write("egress_deny", **base, claimed_session=sid, decision="deny", reason=reason)
        return await reply(writer, 407, "proxy authentication required", {"Proxy-Authenticate": 'Basic realm="sbx"'})
    _, pol = await cp.policy(ctx["session_id"])
    policy, canaries = pol["policy"], pol.get("canaries", [])
    base.update(session_fields(ctx))
    allowed = host_allowed(host, policy.get("egress_allow", []))

    if method == "CONNECT":
        if not allowed:
            await evidence.write("egress_deny", **base, decision="deny", reason="default_deny")
            return await reply(writer, 403, "destination not allowed by spec")
        return await tunnel(reader, writer, base, ctx["session_id"], host, port)

    body = await _read_body(reader, headers)
    if body is None:
        return await reply(writer, 413, "body too large or malformed")
    visible = target.encode() + b"\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()
                                                  if k != "proxy-authorization").encode() + b"\n" + body
    match = scan(visible, canaries)
    base.update(bytes_out=len(body), body_sha256=sha256(body), canary_match=match)
    if not allowed:
        await evidence.write("egress_deny", **base, decision="deny", reason="default_deny")
        return await reply(writer, 403, "destination not allowed by spec")

    fwd = {k: v for k, v in headers.items() if k not in DROP}
    fwd.update(internal.headers())
    fwd.update({"X-Sbx-Session": ctx["session_id"], "X-Sbx-Target": target})
    try:
        async with http.request(method, f"{internal.CREDPROXY_URL}/egress", headers=fwd, data=body) as up:
            data = await up.read()
            await evidence.write("egress_http", **base, decision="allow", reason="spec_allowlist",
                                 status=up.status, bytes_in=len(data))
            ctype = up.headers.get("content-type", "application/octet-stream")
            await reply(writer, up.status, None, {"Content-Type": ctype}, data)
    except aiohttp.ClientError as e:
        await evidence.write("egress_http", **base, decision="allow", reason="spec_allowlist", error=str(e))
        await reply(writer, 502, "upstream error")


async def tunnel(reader, writer, base: dict, sid: str, host: str, port: int) -> None:
    try:
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(*internal.CREDPROXY_TUNNEL), 5)
        up_w.write(json.dumps({"key": internal.key(), "session_id": sid, "host": host, "port": port}).encode() + b"\n")
        await up_w.drain()
        ack = await asyncio.wait_for(up_r.readline(), 10)
    except (OSError, asyncio.TimeoutError) as e:
        await evidence.write("egress_connect", **base, decision="allow", reason="spec_allowlist", error=str(e))
        return await reply(writer, 502, "tunnel failed")
    if not ack.startswith(b"OK"):
        await evidence.write("egress_connect", **base, decision="deny", reason="credproxy_refused",
                             detail=ack.decode(errors="replace").strip())
        return await reply(writer, 403, "destination refused")
    await evidence.write("egress_connect", **base, decision="allow", reason="spec_allowlist")
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    counts = await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))
    await evidence.write("egress_connect_close", **base, bytes_out=counts[0], bytes_in=counts[1])


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> int:
    n = 0
    try:
        while data := await src.read(65536):
            n += len(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        dst.close()
    return n


def _proxy_auth(value: str) -> tuple[str, str]:
    if not value.lower().startswith("basic "):
        return "", ""
    try:
        user, _, pw = base64.b64decode(value[6:]).decode().partition(":")
        return user, pw
    except (ValueError, UnicodeDecodeError):
        return "", ""


async def _read_body(reader: asyncio.StreamReader, headers: dict) -> bytes | None:
    if headers.get("transfer-encoding", "").lower() == "chunked":
        out = b""
        while True:
            size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await reader.readline()
                return out
            out += await reader.readexactly(size)
            await reader.readline()
            if len(out) > MAX_BODY:
                return None
    n = int(headers.get("content-length", "0") or 0)
    if n > MAX_BODY:
        return None
    return await reader.readexactly(n) if n else b""


async def reply(writer, status: int, text: str | None, headers: dict | None = None, body: bytes | None = None) -> None:
    if body is None:
        body = (text or "").encode() + b"\n"
    hdrs = {"Content-Length": str(len(body)), "Connection": "close", **(headers or {})}
    writer.write(f"HTTP/1.1 {status} sbx\r\n".encode() + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()).encode()
                 + b"\r\n" + body)
    try:
        await writer.drain()
    finally:
        writer.close()
