# -*- coding: utf-8 -*-
"""HTTP launcher: run web-api-extractor MCP server on 127.0.0.1:8422/mcp.

Stdio transport requires a persistent client session; this launcher exposes
the same tools over streamable HTTP so any local process can drive them.
"""
import sys
from pathlib import Path

from fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).resolve().parent))

from webapi_extractor.server import mcp  # noqa: E402

if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8422, path="/mcp")
