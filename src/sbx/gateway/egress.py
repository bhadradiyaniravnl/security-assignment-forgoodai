"""Egress gateway (:3128): authenticated forward proxy enforcing the spec's egress allowlist.

The sandbox's only route to anything outside the cluster (its network policy admits only this
port and the AI gateway). Trusts nothing from the sandbox: the session is authenticated from
Proxy-Authorization (Basic, password = session token, bound to the pod IP), and every request is
checked against the session's compiled policy:
- egress_allow: destinations the session may read from (GET/HEAD);
- egress_write: the subset it may send data to (any other method, and every CONNECT).
Every request, allowed or denied, is recorded (evidence actions egress_deny, egress_http,
egress_connect, egress_connect_close). Allowed traffic goes out through credproxy, which
re-checks the policy.

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
from sbx.common.session_policy import host_allowed, normalize_host
from sbx.gateway.shared import cp, evidence, session_fields, sha256

MAX_HEADER = 64 * 1024
MAX_BODY = 16 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
BODY_TIMEOUT_S = 30
READ_METHODS = {"GET", "HEAD"}
MAX_CONN_PER_IP = 16          # one sandbox must not be able to exhaust the shared gateway
_active_conns: dict[str, int] = {}   # pod IP -> open connections
# Never forwarded: hop-by-hop headers and the sandbox's proxy credential.
DROP_HEADERS = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "host", "content-length",
        "transfer-encoding"}


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, http: aiohttp.ClientSession) -> None:
    """Connection entry point: enforce the per-IP connection cap, then serve one proxy request."""
    peer = (writer.get_extra_info("peername") or ("", 0))[0]
    if _active_conns.get(peer, 0) >= MAX_CONN_PER_IP:
        await evidence.write("egress_deny", pod_ip=peer, decision="deny", reason="connection_limit")
        return await reply(writer, 429, "too many concurrent connections")
    _active_conns[peer] = _active_conns.get(peer, 0) + 1
    try:
        await _serve_request(reader, writer, http, peer)
    finally:
        _active_conns[peer] -= 1


async def _serve_request(reader, writer, http: aiohttp.ClientSession, peer: str) -> None:
    """Parse one request (CONNECT or absolute-URL HTTP), authenticate, apply policy, forward or deny."""
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
        url = urlsplit(target)
        if url.scheme != "http" or not url.hostname:
            return await reply(writer, 400, "absolute http:// URL required (use CONNECT for https)")
        host, port, path = url.hostname, url.port or 80, (url.path or "/") + (f"?{url.query}" if url.query else "")
    event_fields = dict(pod_ip=peer, method=method, dest_host=normalize_host(host), dest_port=port, path=path)

    # The Basic username is only the session id the sandbox claims (recorded on failure); the token decides.
    sid, token = _parse_proxy_auth(headers.get("proxy-authorization", ""))
    status, ctx = await cp.validate(token, peer)
    if status != 200:
        reason = "revoked" if "session" in str(ctx.get("detail", "")) else "invalid_token"
        await evidence.write("egress_deny", **event_fields, claimed_session=sid, decision="deny", reason=reason)
        return await reply(writer, 407, "proxy authentication required", {"Proxy-Authenticate": 'Basic realm="sbx"'})
    _, lookup = await cp.policy(ctx["session_id"])
    policy, canaries = lookup["policy"], lookup.get("canaries", [])
    event_fields.update(session_fields(ctx))
    allowed = host_allowed(host, policy.get("egress_allow", []))
    writable = host_allowed(host, policy.get("egress_write", []))

    if method == "CONNECT":
        if not allowed:
            await evidence.write("egress_deny", **event_fields, decision="deny", reason="default_deny")
            return await reply(writer, 403, "destination not allowed by spec")
        if not writable:    # a TLS tunnel's payload is opaque, so it counts as a write
            await evidence.write("egress_deny", **event_fields, decision="deny", reason="write_not_allowed")
            return await reply(writer, 403, "destination is read-only for this spec (no CONNECT)")
        return await tunnel(reader, writer, event_fields, ctx["session_id"], host, port)

    try:
        body = await asyncio.wait_for(_read_body(reader, headers), BODY_TIMEOUT_S)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError):
        body = None
    if body is None:
        return await reply(writer, 413, "body too large or malformed")
    # Everything the destination would see, minus the sandbox's own proxy credential.
    visible = target.encode() + b"\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()
                                                  if k != "proxy-authorization").encode() + b"\n" + body
    match = scan(visible, canaries)
    event_fields.update(bytes_out=len(body), body_sha256=sha256(body), canary_match=match)
    if not allowed:
        await evidence.write("egress_deny", **event_fields, decision="deny", reason="default_deny")
        return await reply(writer, 403, "destination not allowed by spec")
    if method not in READ_METHODS and not writable:
        await evidence.write("egress_deny", **event_fields, decision="deny", reason="write_not_allowed")
        return await reply(writer, 403, "destination is read-only for this spec")

    fwd_headers = {k: v for k, v in headers.items() if k not in DROP_HEADERS}
    fwd_headers.update(internal.headers())
    fwd_headers.update({"X-Sbx-Session": ctx["session_id"], "X-Sbx-Target": target})
    try:
        async with http.request(method, f"{internal.CREDPROXY_URL}/egress", headers=fwd_headers, data=body) as upstream:
            data = await upstream.content.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                await evidence.write("egress_http", **event_fields, decision="deny", reason="response_too_large")
                return await reply(writer, 502, "upstream response too large")
            await evidence.write("egress_http", **event_fields, decision="allow", reason="spec_allowlist",
                                 status=upstream.status, bytes_in=len(data))
            ctype = upstream.headers.get("content-type", "application/octet-stream")
            await reply(writer, upstream.status, None, {"Content-Type": ctype}, data)
    except aiohttp.ClientError as e:
        await evidence.write("egress_http", **event_fields, decision="allow", reason="spec_allowlist", error=str(e))
        await reply(writer, 502, "upstream error")


async def tunnel(reader, writer, event_fields: dict, sid: str, host: str, port: int) -> None:
    """Open a CONNECT tunnel via credproxy's :9001 (JSON handshake, credproxy re-checks egress_write)
    and pipe bytes both ways; only the byte counts are recorded, the payload is opaque."""
    try:
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(*internal.CREDPROXY_TUNNEL), 5)
        up_w.write(json.dumps({"key": internal.key(), "session_id": sid, "host": host, "port": port}).encode() + b"\n")
        await up_w.drain()
        ack = await asyncio.wait_for(up_r.readline(), 10)
    except (OSError, asyncio.TimeoutError) as e:
        await evidence.write("egress_connect", **event_fields, decision="allow", reason="spec_allowlist", error=str(e))
        return await reply(writer, 502, "tunnel failed")
    if not ack.startswith(b"OK"):
        await evidence.write("egress_connect", **event_fields, decision="deny", reason="credproxy_refused",
                             detail=ack.decode(errors="replace").strip())
        return await reply(writer, 403, "destination refused")
    await evidence.write("egress_connect", **event_fields, decision="allow", reason="spec_allowlist")
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    bytes_out, bytes_in = await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))
    await evidence.write("egress_connect_close", **event_fields, bytes_out=bytes_out, bytes_in=bytes_in)


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> int:
    """Copy src to dst until EOF, then close dst. Returns the number of bytes copied."""
    total = 0
    try:
        while data := await src.read(65536):
            total += len(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        dst.close()
    return total


def _parse_proxy_auth(value: str) -> tuple[str, str]:
    """Proxy-Authorization: Basic -> (username, password); ("", "") if absent or malformed."""
    if not value.lower().startswith("basic "):
        return "", ""
    try:
        user, _, pw = base64.b64decode(value[6:]).decode().partition(":")
        return user, pw
    except (ValueError, UnicodeDecodeError):
        return "", ""


async def _read_body(reader: asyncio.StreamReader, headers: dict) -> bytes | None:
    """Read a chunked or Content-Length body, capped at MAX_BODY (None if over the cap)."""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        out = b""
        while True:
            size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await reader.readline()
                return out
            if size < 0 or len(out) + size > MAX_BODY:     # check BEFORE buffering the chunk
                return None
            out += await reader.readexactly(size)
            await reader.readline()
    n = int(headers.get("content-length", "0") or 0)
    if n > MAX_BODY:
        return None
    return await reader.readexactly(n) if n else b""


async def reply(writer, status: int, text: str | None, headers: dict | None = None, body: bytes | None = None) -> None:
    """Write a complete HTTP/1.1 response and close the connection (one request per connection)."""
    if body is None:
        body = (text or "").encode() + b"\n"
    hdrs = {"Content-Length": str(len(body)), "Connection": "close", **(headers or {})}
    writer.write(f"HTTP/1.1 {status} sbx\r\n".encode() + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()).encode()
                 + b"\r\n" + body)
    try:
        await writer.drain()
    finally:
        writer.close()
