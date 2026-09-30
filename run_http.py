# -*- coding: utf-8 -*-
"""HTTP launcher: run scry-mcp-gen MCP server on 127.0.0.1:8422/mcp.

Stdio transport requires a persistent client session; this launcher exposes
the same tools over streamable HTTP so any local process can drive them.

**重要**：请用 `start_server.py` 启动本服务，不要直接在宿主 shell 的后台任务里跑。
直接后台运行会让进程留在宿主 shell 的 job object 内，宿主回收 shell 时
服务连同它拉起的 Chromium 会被一起杀掉（表现为浏览器「打开后立刻消失」）。
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ⚠️ 必须在导入 fastmcp **之前**清洗 NO_PROXY。FastMCP 的启动横幅会调
# check_for_newer_version()，用 trust_env=True 的 httpx 客户端去打 PyPI；而宿主
# 注入的 NO_PROXY 里带方括号 IPv6（`[::1]`）会让 httpx 在**构造 URLPattern 时**
# 就抛 InvalidURL。后果：服务在 mcp.run() 内部崩溃、端口从未监听，调用方只看到
# httpx.ConnectError（目标计算机积极拒绝）—— 报错方向完全指向「服务/网络没起来」，
# 只有 server.log 末尾那行 InvalidURL 才指得出真因。
# scry_mcp_gen/proxy_env.py 早已实现并写清了这件事，mcp_call.py 也用
# trust_env=False 规避过 —— 唯独服务端启动路径漏调，属于「修了一半」。
# 这段顺序由 tests/test_proxy_env.py 的守卫看着，别再被重新生成冲掉。
from scry_mcp_gen.proxy_env import sanitize_no_proxy  # noqa: E402

sanitize_no_proxy()

from fastmcp import FastMCP  # noqa: E402

from scry_mcp_gen.server import mcp  # noqa: E402

DEFAULT_PORT = 8422

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="启动 scry-mcp-gen 的 HTTP MCP 服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--path", default="/mcp")
    args = ap.parse_args()

    mcp.run(transport="http", host=args.host, port=args.port, path=args.path)
