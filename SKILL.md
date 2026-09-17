---
name: web-api-extractor
description: Extract web API traffic through browser authentication and CDP capture, analyze endpoints, and generate a Python FastMCP server.
---

# Web API Extractor Workflow

1. Call `probe_login` and use interactive login when confidence is below `0.8`.
2. Call `http_login` for a known simple form or JSON login; follow `fallback=interactive` when returned.
3. Call `open_browser_login`, poll `get_login_status`, and continue only after `completed`.
4. Call `start_capture`, let the user operate the site, then call `get_capture_status` and `stop_capture`.
5. Call `analyze_traffic`, show the endpoint list, and use `update_endpoint` for user-provided descriptions.
6. When `crypto_findings.found` is true, call `extract_crypto_logic` and disclose the selected strategy.
7. Call `generate_mcp_server` with the confirmed `endpoint_ids`; generated mutating tools are marked `[MUTATING]`.

The data root defaults to `~/.webapiextractor` and can be overridden with
`WEB_API_EXTRACTOR_DATA`. Capture response truncation defaults to 256 KiB and
idle pause defaults to five minutes; both are configurable through environment
variables.