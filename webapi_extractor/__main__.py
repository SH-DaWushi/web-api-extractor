"""CLI entry for ``python -m webapi_extractor``.

Subcommands:
    (default)   start the MCP server over stdio
    doctor      run the environment self-check
    serve-http  start the MCP server over streamable HTTP on 127.0.0.1:8422/mcp
"""
from __future__ import annotations

import sys


def main() -> None:
    argv = sys.argv[1:]
    command = argv[0] if argv else ""

    if command == "doctor":
        from .doctor import main as doctor_main

        raise SystemExit(doctor_main(argv[1:]))

    if command == "serve-http":
        # Same launcher as run_http.py, exposed as a subcommand for convenience.
        from fastmcp import FastMCP  # noqa: F401  (ensure dependency present early)
        from .server import mcp

        mcp.run(transport="http", host="127.0.0.1", port=8422, path="/mcp")
        return

    # Default: stdio MCP server. Imported lazily so `doctor` works even if a
    # heavy dependency (fastmcp) is missing.
    from .server import main as server_main

    server_main()


if __name__ == "__main__":
    main()
