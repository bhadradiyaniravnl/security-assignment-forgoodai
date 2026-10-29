"""Gateway process: AI gateway on :8080, egress gateway on :3128."""
from __future__ import annotations

import asyncio
import json

import aiohttp
from aiohttp import web

from sbx.gateway import ai, egress


async def main() -> None:
    runner = web.AppRunner(ai.build_app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 8080).start()
    http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120), auto_decompress=False)
    await asyncio.start_server(lambda r, w: egress.handle(r, w, http), "0.0.0.0", 3128, limit=egress.MAX_HEADER)
    print(json.dumps({"gateway": "listening", "ports": [8080, 3128]}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
