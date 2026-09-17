"""Generate a small editable Python/FastMCP client from analysis.json."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _name(endpoint: dict[str, Any], used: set[str]) -> str:
    parts = [part for part in endpoint.get("path", "").split("/") if part and not part.startswith("{")]
    resource = "_".join(re.sub(r"[^a-zA-Z0-9]+", "_", part).strip("_") for part in parts) or "endpoint"
    verb = {"GET": "get", "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}.get(endpoint.get("method", "GET"), "call")
    name = f"{verb}_{resource}"
    if "{" in endpoint.get("path", ""):
        name += "_by_id"
    candidate = name
    index = 2
    while candidate in used:
        candidate = f"{name}_{index}"
        index += 1
    used.add(candidate)
    return candidate


def generate(session_dir: Path, output_dir: Path, endpoint_ids: list[str] | None = None) -> dict[str, Any]:
    analysis = json.loads((session_dir / "analysis.json").read_text(encoding="utf-8"))
    selected = [endpoint for endpoint in analysis.get("endpoints", []) if endpoint_ids is None or endpoint.get("endpoint_id") in endpoint_ids]
    if endpoint_ids is not None and len(selected) != len(endpoint_ids):
        known = {endpoint.get("endpoint_id") for endpoint in analysis.get("endpoints", [])}
        missing = sorted(set(endpoint_ids) - known)
        raise ValueError(f"Unknown endpoint_ids: {', '.join(missing)}")
    output_dir.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    functions: list[str] = []
    for endpoint in selected:
        function_name = _name(endpoint, used)
        mutating = endpoint.get("method") not in {"GET", "HEAD"}
        marker = "[MUTATING] " if mutating else ""
        functions.append(f'''@mcp.tool()\nasync def {function_name}(payload: dict | None = None) -> dict:\n    """{marker}{endpoint.get("description") or endpoint.get("method") + " " + endpoint.get("path", "")}."""\n    return await client.request({endpoint.get("method")!r}, {endpoint.get("path")!r}, payload or {{}})\n''')
    server = '''from __future__ import annotations\n\nimport os\nimport httpx\nfrom fastmcp import FastMCP\n\n\nclass APIClient:\n    def __init__(self):\n        self.base_url = os.environ["API_BASE_URL"].rstrip("/")\n        self.token = os.environ.get("API_TOKEN")\n\n    async def request(self, method: str, path: str, payload: dict) -> dict:\n        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}\n        async with httpx.AsyncClient(base_url=self.base_url, timeout=30) as session:\n            response = await session.request(method, path, json=payload, headers=headers)\n            if response.status_code == 401:\n                raise RuntimeError("ReAuthRequiredError: API token rejected")\n            response.raise_for_status()\n            if not response.content:\n                return {"status": response.status_code}\n            return response.json()\n\n\nmcp = FastMCP("Generated Web API")\nclient = APIClient()\n\n''' + "\n".join(functions) + '''\n\nif __name__ == "__main__":\n    mcp.run()\n'''
    (output_dir / "server.py").write_text(server, encoding="utf-8")
    (output_dir / "requirements.txt").write_text("fastmcp>=2.0\nhttpx>=0.27\n", encoding="utf-8")
    (output_dir / ".env.example").write_text("API_BASE_URL=https://example.com\nAPI_TOKEN=replace-me\n", encoding="utf-8")
    (output_dir / ".gitignore").write_text(".env\nauth_state*\n__pycache__/\n", encoding="utf-8")
    readme = f"# Generated Web API\n\nGenerated {len(selected)} endpoint tool(s). Set `API_BASE_URL` and `API_TOKEN` from `.env`.\n"
    if any(endpoint.get("method") not in {"GET", "HEAD"} for endpoint in selected):
        readme += "\nMutating tools are marked `[MUTATING]`; invocation causes real business side effects.\n"
    (output_dir / "README.md").write_text(readme, encoding="utf-8")
    get_endpoints = [endpoint for endpoint in selected if endpoint.get("method") == "GET"]
    smoke = """import asyncio\nimport os\nimport httpx\n\nasync def main():\n    endpoint = os.environ.get("SMOKE_ENDPOINT")\n    if not endpoint:\n        endpoint = %r\n    if not endpoint:\n        raise SystemExit("No GET endpoint available; use SMOKE_ENDPOINT explicitly for a selected endpoint")\n    async with httpx.AsyncClient() as client:\n        response = await client.get(os.environ["API_BASE_URL"].rstrip("/") + endpoint, headers={"Authorization": "Bearer " + os.environ.get("API_TOKEN", "")})\n        response.raise_for_status()\n        print(response.status_code)\n\nasyncio.run(main())\n""" % (get_endpoints[0].get("path") if get_endpoints else "")
    (output_dir / "smoke_test.py").write_text(smoke, encoding="utf-8")
    return {"output_dir": str(output_dir), "files": [path.name for path in output_dir.iterdir()], "endpoint_count": len(selected), "requires_auth_setup": any(endpoint.get("auth_required") for endpoint in selected)}