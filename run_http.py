# -*- coding: utf-8 -*-
"""HTTP launcher: run web-api-extractor MCP server on 127.0.0.1:8422/mcp.

Stdio transport requires a persistent client session; this launcher exposes
the same tools over streamable HTTP so any local process can drive them.

**重要**：请用 `start_server.py` 启动本服务，不要直接在宿主 shell 的后台任务里跑。
直接后台运行会让进程留在宿主 shell 的 job object 内，宿主回收 shell 时
服务连同它拉起的 Chromium 会被一起杀掉（表现为浏览器「打开后立刻消失」）。
"""
import argparse
import sys
from pathlib import Path

from fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).resolve().parent))

from webapi_extractor.server import mcp  # noqa: E402

DEFAULT_PORT = 8422

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="启动 web-api-extractor 的 HTTP MCP 服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--path", default="/mcp")
    args = ap.parse_args()

    mcp.run(transport="http", host=args.host, port=args.port, path=args.path)
