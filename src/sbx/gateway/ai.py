"""AI gateway (:8080): Anthropic API reverse proxy that enforces the spec and records evidence.

Trusts nothing from the sandbox: every request is authenticated, shape-checked against the
session's compiled policy (from the control plane) and recorded before it is forwarded to
credproxy, which adds the real API key. Enforces:
- Authenticates the session placeholder token (x-api-key / bearer), bound to the pod IP.
- Allows only POST /v1/messages and /v1/messages/count_tokens, with a top-level model from the spec.
- Rejects provider-side capabilities that would move data out through Anthropic's infrastructure,
  outside our egress controls: server tools (web_fetch, web_search, code execution, ...), MCP
  connectors (mcp_servers), containers, and URL- or file-sourced content the provider would fetch.
- Enforces the cumulative token budget.
- Drops every client-supplied credential; credproxy injects the real one.
- Caps concurrent requests per pod IP.

Records (evidence actions): ai_request for every answered request, allowed or denied, with a
canary scan of the body; ai_tool_use for every tool_use block in the response, an "agent
attempted" signal that does not depend on whether the later network action succeeds (sentinel
rule D3). Full request/response bodies go to BODY_DIR, canaries redacted, for investigators.
"""
from __future__ import annotations

import gzip
import json
import os

import aiohttp
from aiohttp import web

from sbx.common import internal
from sbx.common.canary import scan
from sbx.common.session_policy import host_allowed
from sbx.gateway.shared import cp, evidence, referenced_hosts, session_fields, sha256, usage

ALLOWED_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
ALLOWED_SOURCE_TYPES = {"base64", "text", "content"}
FORBIDDEN_FIELDS = {"mcp_servers", "container"}

# Never forwarded in either direction: hop-by-hop headers plus any client-supplied credential.
DROP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "host", "content-length", "authorization",
                "x-api-key", "accept-encoding"}
MAX_TOOL_INPUT = 4096


def request_policy(method: str, path: str, body: bytes, model_allow: list[str]) -> tuple[str | None, str | None]:
    """Returns (model, deny_reason). Pure function: the whole request-shape policy lives here."""
    if method != "POST" or path not in ALLOWED_PATHS:
        return None, "path_not_allowed"
    try:
        req = json.loads(body)
    except ValueError:
        return None, "malformed_request"
    if not isinstance(req, dict):
        return None, "malformed_request"
    model = req.get("model")
    if not isinstance(model, str) or model not in model_allow:
        return model if isinstance(model, str) else None, "model_not_allowed"
    if FORBIDDEN_FIELDS & set(req):
        return model, "provider_side_capability"
    for tool in req.get("tools") or []:
        if not isinstance(tool, dict) or tool.get("type", "custom") != "custom":
            return model, "provider_side_tool"
    if _has_remote_source(req.get("messages")) or _has_remote_source(req.get("system")):
        return model, "remote_content_source"
    return model, None


def _has_remote_source(node) -> bool:
    """True if any content block asks the provider to fetch something (URL) or read stored files."""
    if isinstance(node, dict):
        src = node.get("source")
        if isinstance(src, dict) and src.get("type") not in ALLOWED_SOURCE_TYPES:
            return True
        return any(_has_remote_source(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_remote_source(v) for v in node)
    return False


def _presented_token(request: web.Request) -> str:
    """The session token, from x-api-key or an Authorization: Bearer header."""
    if k := request.headers.get("x-api-key"):
        return k
    auth = request.headers.get("authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else ""


async def handle(request: web.Request) -> web.StreamResponse:
    """Authenticate, apply request_policy and the token budget, record, then stream via credproxy."""
    ip = request.remote or ""
    path = "/" + request.match_info["tail"]
    status, ctx = await cp.validate(_presented_token(request), ip)
    if status != 200:
        await evidence.write("ai_request", pod_ip=ip, path=path, decision="deny",
                             reason="revoked" if "session" in str(ctx.get("detail", "")) else "invalid_token",
                             detail=ctx.get("detail"))
        return web.json_response({"type": "error", "error": {"type": "authentication_error",
                                  "message": "sbx: session not authorized"}}, status=401)
    _, lookup = await cp.policy(ctx["session_id"])
    policy, canaries, who = lookup["policy"], lookup.get("canaries", []), session_fields(ctx)

    body = await request.read()
    model, deny = request_policy(request.method, path, body, policy.get("model_allow", []))
    match = scan(body, canaries)
    event_fields = dict(**who, path=path, method=request.method, model=model, bytes_out=len(body),
                        body_sha256=sha256(body), dest_host="api.anthropic.com", canary_match=match)

    if deny:
        await evidence.write("ai_request", **event_fields, decision="deny", reason=deny)
        return web.json_response({"type": "error", "error": {"type": "permission_error",
                                  "message": f"sbx: request denied by spec ({deny})"}}, status=403)
    if usage.get(ctx["session_id"], 0) >= policy.get("max_tokens", 0):
        await evidence.write("ai_request", **event_fields, decision="deny", reason="budget")
        return web.json_response({"type": "error", "error": {"type": "rate_limit_error",
                                  "message": "sbx: session token budget exhausted"}}, status=429)
    # Recorded before forwarding, so the event exists even if the upstream call fails.
    req_event = await evidence.write("ai_request", **event_fields, decision="allow", reason="spec_policy")

    headers = {k: v for k, v in request.headers.items() if k.lower() not in DROP_HEADERS}
    headers.update(internal.headers())
    headers["X-Sbx-Session"] = ctx["session_id"]
    http: aiohttp.ClientSession = request.app["http"]
    async with http.request(request.method, f"{internal.CREDPROXY_URL}/anthropic{path}", params=request.query,
                            headers=headers, data=body) as upstream:
        resp = web.StreamResponse(status=upstream.status, headers={k: v for k, v in upstream.headers.items()
                                                                   if k.lower() not in DROP_HEADERS})
        await resp.prepare(request)
        inspector = ResponseInspector(ctx, policy, canaries, who)
        streaming = "text/event-stream" in upstream.headers.get("content-type", "")
        json_body = b""
        kept_response = bytearray()     # capped copy for store_bodies
        async for chunk in upstream.content.iter_any():
            await resp.write(chunk)
            if len(kept_response) < MAX_BODY_KEEP:
                kept_response += chunk[:MAX_BODY_KEEP - len(kept_response)]
            if streaming:
                await inspector.feed_sse(chunk)
            else:
                json_body += chunk
        if not streaming and upstream.status == 200:
            await inspector.feed_json(json_body)
        await resp.write_eof()
        if req_event.get("seq", -1) > 0:     # seq -1: the event was dropped (fault injection), so nothing to link to
            store_bodies(ctx["session_id"], req_event["seq"], body, bytes(kept_response), canaries, upstream.status)
        return resp


MAX_BODY_KEEP = 4 * 1024 * 1024
BODY_DIR = os.path.join(os.environ.get("EVIDENCE_DIR", "/evidence"), "bodies")


def store_bodies(sid: str, seq: int, request_body: bytes, response_body: bytes, canaries: list, status: int) -> None:
    """Full prompt and response per model call, so investigators can audit the reasoning chain.
    Canary values are redacted at rest; the evidence event already records that one was present.
    Linked to the hash-chained `ai_request` event by seq and body_sha256."""
    def redact(data: bytes) -> bytes:
        for canary in canaries:
            data = data.replace(canary["value"].encode(), f"[CANARY:{canary['id']}]".encode())
        return data
    session_dir = os.path.join(BODY_DIR, sid)
    os.makedirs(session_dir, exist_ok=True)
    with gzip.open(os.path.join(session_dir, f"{seq:08d}.json.gz"), "wt") as f:
        json.dump({"seq": seq, "status": status, "request": redact(request_body).decode(errors="replace"),
                   "response": redact(response_body).decode(errors="replace"),
                   "response_truncated": len(response_body) >= MAX_BODY_KEEP}, f)


class ResponseInspector:
    """Extracts tool_use blocks and token usage from Messages API responses.

    Token usage feeds the session budget; each tool_use is recorded as an ai_tool_use event, with
    a canary scan and the hosts it mentions that are outside the spec's egress allowlist."""

    def __init__(self, ctx, policy, canaries, who):
        self.sid, self.policy, self.canaries, self.who = ctx["session_id"], policy, canaries, who
        self.pending = b""                    # partial SSE line carried over between chunks
        self.blocks: dict[int, dict] = {}     # content-block index -> tool_use being streamed

    async def feed_sse(self, chunk: bytes) -> None:
        """Consume a chunk of a text/event-stream response."""
        self.pending += chunk
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            if line.startswith(b"data:"):
                try:
                    await self.on_event(json.loads(line[5:]))
                except ValueError:
                    continue

    async def feed_json(self, data: bytes) -> None:
        """Consume a complete non-streaming response body."""
        try:
            msg = json.loads(data)
        except ValueError:
            return
        self.add_usage(msg.get("usage", {}))
        for block in msg.get("content", []):
            if block.get("type") == "tool_use":
                await self.tool_use(block.get("name"), json.dumps(block.get("input", {})))

    async def on_event(self, ev: dict) -> None:
        """Handle one SSE event: usage from message_start/delta, tool_use input assembled from deltas."""
        kind = ev.get("type")
        if kind == "message_start":
            self.add_usage(ev.get("message", {}).get("usage", {}))
        elif kind == "message_delta":
            self.add_usage(ev.get("usage", {}))
        elif kind == "content_block_start" and ev.get("content_block", {}).get("type") == "tool_use":
            self.blocks[ev["index"]] = {"name": ev["content_block"].get("name"), "input": ""}
        elif kind == "content_block_delta" and ev.get("delta", {}).get("type") == "input_json_delta":
            if ev["index"] in self.blocks:
                self.blocks[ev["index"]]["input"] += ev["delta"].get("partial_json", "")
        elif kind == "content_block_stop" and ev.get("index") in self.blocks:
            block = self.blocks.pop(ev["index"])
            await self.tool_use(block["name"], block["input"])

    def add_usage(self, counts: dict) -> None:
        """Add a response's input and output tokens to the session's running total."""
        tokens = sum(int(counts.get(k) or 0) for k in ("input_tokens", "output_tokens"))
        usage[self.sid] = usage.get(self.sid, 0) + tokens

    async def tool_use(self, name: str, raw_input: str) -> None:
        """Record one tool call the model asked for (an attempt, whether or not it later succeeds)."""
        allow = self.policy.get("egress_allow", [])
        hosts = sorted(h for h in referenced_hosts(raw_input) if not host_allowed(h, allow))
        await evidence.write("ai_tool_use", **self.who, tool=name, input=raw_input[:MAX_TOOL_INPUT],
                             input_truncated=len(raw_input) > MAX_TOOL_INPUT,
                             canary_match=scan(raw_input.encode(), self.canaries),
                             refs_env_file=".env" in raw_input, refs_disallowed_hosts=hosts)


MAX_INFLIGHT_PER_IP = 8
_inflight: dict[str, int] = {}


@web.middleware
async def per_ip_limit(request: web.Request, handler):
    """At most MAX_INFLIGHT_PER_IP concurrent requests per pod, so one sandbox cannot starve the rest."""
    ip = request.remote or ""
    if _inflight.get(ip, 0) >= MAX_INFLIGHT_PER_IP:
        if request.path != "/healthz":    # every answered request is in evidence (the sentinel's S1 completeness rule counts them)
            await evidence.write("ai_request", pod_ip=ip, path=request.path, decision="deny", reason="inflight_limit")
        return web.json_response({"type": "error", "error": {"type": "rate_limit_error",
                                  "message": "sbx: too many concurrent requests"}}, status=429)
    _inflight[ip] = _inflight.get(ip, 0) + 1
    try:
        return await handler(request)
    finally:
        _inflight[ip] -= 1


def build_app() -> web.Application:
    """The :8080 aiohttp app: /healthz plus a catch-all routed to handle()."""
    app = web.Application(client_max_size=32 * 1024 * 1024, middlewares=[per_ip_limit])

    async def startup(a):
        a["http"] = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600), auto_decompress=False)

    app.on_startup.append(startup)
    app.router.add_get("/healthz", lambda r: web.json_response({"ok": True}))
    app.router.add_route("*", "/{tail:.*}", handle)
    return app
