# -*- coding: utf-8 -*-
"""Minimal streamable-HTTP MCP client driver for web-api-extractor.

Usage: python mcp_call.py <tool_name> [json_arguments]
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
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    sid = CACHE.read_text().strip() if CACHE.exists() else None
    with httpx.Client(timeout=300) as client:
        if not sid:
            resp, sid = post(client, {
                "jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "driver", "version": "0"}},
            }, None)
            if not sid:
                raise SystemExit("no session id returned:\n" + json.dumps(resp))
            CACHE.write_text(sid)
            post(client, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
        resp, _ = post(client, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }, sid)
        print(json.dumps(resp, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
