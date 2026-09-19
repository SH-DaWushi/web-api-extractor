# -*- coding: utf-8 -*-
"""Minimal streamable-HTTP MCP client driver for web-api-extractor.

Usage:
    python mcp_call.py <tool_name> [json_arguments]
    python mcp_call.py <tool_name> @args.json     # read arguments from a JSON file
    python mcp_call.py <tool_name> -              # read arguments from stdin

The @file / stdin forms avoid Windows shell quoting issues entirely and are the
recommended way to pass arguments containing Windows paths.

Prints the tool result as JSON. Reuses a session id cached in .mcp_session.
"""
import json
import sys
import pathlib

import httpx

BASE = "http://127.0.0.1:8422/mcp"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
CACHE = pathlib.Path(__file__).resolve().parent / ".mcp_session"


def load_args(raw: str) -> dict:
    """Parse tool arguments from a literal JSON string, '@file' or '-' (stdin)."""
    raw = raw.strip()
    if raw == "-":
        raw = sys.stdin.read()
    elif raw.startswith("@"):
        raw = pathlib.Path(raw[1:]).read_text(encoding="utf-8")
    return json.loads(raw) if raw else {}


def post(client: httpx.Client, payload: dict, sid: str | None):
    h = dict(HEADERS)
    if sid:
        h["Mcp-Session-Id"] = sid
    r = client.post(BASE, headers=h, json=payload)
    r.raise_for_status()
    new_sid = r.headers.get("mcp-session-id")
    out = r.text
    # parse SSE or JSON
    if out.startswith("event:") or "\ndata: " in out:
        for line in out.splitlines():
            if line.startswith("data:"):
                out = line[5:].strip()
                break
    if not out:
        return None, new_sid
    return json.loads(out), new_sid


def main():
    tool = sys.argv[1]
    args = load_args(sys.argv[2]) if len(sys.argv) > 2 else {}
    sid = CACHE.read_text().strip() if CACHE.exists() else None

    def initialize(client):
        resp, new_sid = post(client, {
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "driver", "version": "0"}},
        }, None)
        if not new_sid:
            raise SystemExit("no session id returned:\n" + json.dumps(resp))
        CACHE.write_text(new_sid)
        post(client, {"jsonrpc": "2.0", "method": "notifications/initialized"}, new_sid)
        return new_sid

    with httpx.Client(timeout=300) as client:
        if not sid:
            sid = initialize(client)
        resp, _ = post(client, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }, sid)
        # E-2: cached session id goes stale after a server restart; the server
        # then answers 404. Detect, re-initialize once, retry automatically.
        if _is_stale_session(resp):
            sys.stderr.write("缓存的 MCP 会话已失效（服务可能重启过），重新初始化并重试...\n")
            try:
                CACHE.unlink()
            except OSError:
                pass
            sid = initialize(client)
            resp, _ = post(client, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            }, sid)
        print(json.dumps(resp, ensure_ascii=False, indent=2))


def _is_stale_session(resp) -> bool:
    """Heuristic: stale-session failures surface as protocol errors or 404 text."""
    if not isinstance(resp, dict):
        return False
    err = resp.get("error")
    if isinstance(err, dict) and (err.get("code") == -32001 or "404" in str(err.get("message", ""))):
        return True
    return "result" not in resp and "404" in str(resp)


if __name__ == "__main__":
    main()
