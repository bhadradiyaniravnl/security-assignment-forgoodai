"""AI gateway (:8080): Anthropic API reverse proxy that enforces the spec and records evidence.

- Authenticates the session placeholder (x-api-key / bearer) bound to the pod IP.
- Enforces model allowlist and cumulative token budget.
- Drops every client-supplied credential; credproxy injects the real one.
- Parses streamed responses for tool_use blocks: an "agent attempted" signal that does not
  depend on whether the later network action succeeds (detection D3).
"""
from __future__ import annotations

import json

import aiohttp
from aiohttp import web

from sbx.common import internal
from sbx.common.canary import scan
from sbx.common.policy import host_allowed
from sbx.gateway.common import cp, evidence, referenced_hosts, session_fields, sha256, usage

HOP = {"connection", "keep-alive", "transfer-encoding", "host", "content-length", "authorization", "x-api-key",
       "accept-encoding"}
MAX_TOOL_INPUT = 4096


def _token(request: web.Request) -> str:
    if k := request.headers.get("x-api-key"):
        return k
    auth = request.headers.get("authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else ""


async def handle(request: web.Request) -> web.StreamResponse:
    ip = request.remote or ""
    path = "/" + request.match_info["tail"]
    status, ctx = await cp.validate(_token(request), ip)
    if status != 200:
        await evidence.write("ai_request", pod_ip=ip, path=path, decision="deny",
                             reason="revoked" if "session" in str(ctx.get("detail", "")) else "invalid_token",
                             detail=ctx.get("detail"))
        return web.json_response({"type": "error", "error": {"type": "authentication_error",
                                  "message": "sbx: session not authorized"}}, status=401)
    _, pol = await cp.policy(ctx["session_id"])
    policy, canaries, who = pol["policy"], pol.get("canaries", []), session_fields(ctx)

    body = await request.read()
    model = None
    if path.startswith("/v1/messages") and body:
        try:
            model = json.loads(body).get("model")
        except ValueError:
            pass
    match = scan(body, canaries)
    base = dict(**who, path=path, model=model, bytes_out=len(body), body_sha256=sha256(body),
                dest_host="api.anthropic.com", canary_match=match)

    if model and model not in policy.get("model_allow", []):
        await evidence.write("ai_request", **base, decision="deny", reason="model_not_allowed")
        return web.json_response({"type": "error", "error": {"type": "permission_error",
                                  "message": f"sbx: model {model} not allowed by spec"}}, status=403)
    if usage.get(ctx["session_id"], 0) >= policy.get("max_tokens", 0):
        await evidence.write("ai_request", **base, decision="deny", reason="budget")
        return web.json_response({"type": "error", "error": {"type": "rate_limit_error",
                                  "message": "sbx: session token budget exhausted"}}, status=429)
    await evidence.write("ai_request", **base, decision="allow", reason="spec_allowlist")

    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP}
    headers.update(internal.headers())
    headers["X-Sbx-Session"] = ctx["session_id"]
    http: aiohttp.ClientSession = request.app["http"]
    async with http.request(request.method, f"{internal.CREDPROXY_URL}/anthropic{path}", params=request.query,
                            headers=headers, data=body) as up:
        resp = web.StreamResponse(status=up.status, headers={k: v for k, v in up.headers.items()
                                                             if k.lower() not in HOP})
        await resp.prepare(request)
        parser = ResponseInspector(ctx, policy, canaries, who)
        streaming = "text/event-stream" in up.headers.get("content-type", "")
        buf = b""
        async for chunk in up.content.iter_any():
            await resp.write(chunk)
            if streaming:
                await parser.feed_sse(chunk)
            else:
                buf += chunk
        if not streaming and up.status == 200:
            await parser.feed_json(buf)
        await resp.write_eof()
        return resp


class ResponseInspector:
    """Extracts tool_use blocks and token usage from Messages API responses."""

    def __init__(self, ctx, policy, canaries, who):
        self.sid, self.policy, self.canaries, self.who = ctx["session_id"], policy, canaries, who
        self.pending = b""
        self.blocks: dict[int, dict] = {}

    async def feed_sse(self, chunk: bytes) -> None:
        self.pending += chunk
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            if line.startswith(b"data:"):
                try:
                    await self.event(json.loads(line[5:]))
                except ValueError:
                    continue

    async def feed_json(self, data: bytes) -> None:
        try:
            msg = json.loads(data)
        except ValueError:
            return
        self.add_usage(msg.get("usage", {}))
        for block in msg.get("content", []):
            if block.get("type") == "tool_use":
                await self.tool_use(block.get("name"), json.dumps(block.get("input", {})))

    async def event(self, ev: dict) -> None:
        t = ev.get("type")
        if t == "message_start":
            self.add_usage(ev.get("message", {}).get("usage", {}))
        elif t == "message_delta":
            self.add_usage(ev.get("usage", {}))
        elif t == "content_block_start" and ev.get("content_block", {}).get("type") == "tool_use":
            self.blocks[ev["index"]] = {"name": ev["content_block"].get("name"), "input": ""}
        elif t == "content_block_delta" and ev.get("delta", {}).get("type") == "input_json_delta":
            if ev["index"] in self.blocks:
                self.blocks[ev["index"]]["input"] += ev["delta"].get("partial_json", "")
        elif t == "content_block_stop" and ev.get("index") in self.blocks:
            b = self.blocks.pop(ev["index"])
            await self.tool_use(b["name"], b["input"])

    def add_usage(self, u: dict) -> None:
        n = sum(int(u.get(k) or 0) for k in ("input_tokens", "output_tokens"))
        usage[self.sid] = usage.get(self.sid, 0) + n

    async def tool_use(self, name: str, raw_input: str) -> None:
        allow = self.policy.get("egress_allow", [])
        hosts = sorted(h for h in referenced_hosts(raw_input) if not host_allowed(h, allow))
        await evidence.write("ai_tool_use", **self.who, tool=name, input=raw_input[:MAX_TOOL_INPUT],
                             input_truncated=len(raw_input) > MAX_TOOL_INPUT,
                             canary_match=scan(raw_input.encode(), self.canaries),
                             refs_env_file=".env" in raw_input, refs_disallowed_hosts=hosts)


def build_app() -> web.Application:
    app = web.Application(client_max_size=32 * 1024 * 1024)

    async def startup(a):
        a["http"] = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600), auto_decompress=False)

    app.on_startup.append(startup)
    app.router.add_get("/healthz", lambda r: web.json_response({"ok": True}))
    app.router.add_route("*", "/{tail:.*}", handle)
    return app
