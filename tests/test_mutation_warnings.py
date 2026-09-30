# -*- coding: utf-8 -*-
"""S33：写操作的**实质警示**与 README 写操作清单。

``confirm`` 拦的是一次误触（不传 ``confirm=true`` 时请求根本不发，见本文件最后一条），
但它**拦不住调用方自己重试** —— 它不是向人取得同意的门槛。所以必须把「这会真的改数据、
可能撤不回来」写在调用方真正会读的两处：

* 写操作工具的 docstring（LLM 只读这里）；
* 生成物 README 的写操作清单（用户不点进表格也能一眼看到哪些工具会改数据）。

措辞面向完全不懂 HTTP / 不懂编程的用户：不出现 status code、endpoint、scheme 这类词。
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

from scry_mcp_gen.generator import render_server

HOST = "portal.example.com"


def _registry(method: str = "POST", tool_name: str = "del_order",
              path: str = "/api/orders/9", auth_login: dict | None = None) -> dict:
    return {
        "site_name": "portal", "registry_version": 1,
        "hosts": {HOST: {"scheme": "Bearer", "cookie_names": []}},
        "endpoints": [{
            "tool_name": tool_name, "method": method, "host": HOST, "path": path,
            "path_params": [], "query_params": {}, "sample_count": 3,
            "auth_required": True, "status": "active", "description": "删除订单",
        }],
        "auth_login": auth_login,
    }


def _tool_source(registry: dict, tool_name: str) -> str:
    source = render_server(registry)["server.py"]
    start = source.index(f"async def {tool_name}(")
    end = source.index("\n@mcp.tool()", start) if "\n@mcp.tool()" in source[start:] \
        else len(source)
    return source[start:end]


WARNING_MARKERS = ("会真的修改服务器上的数据", "可能无法撤销", "confirm=true", "audit.log")


class TestMutatingDocstringCarriesRealConsequences:
    def test_warning_present_for_every_write_method(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            block = _tool_source(_registry(method=method), "del_order")
            for marker in WARNING_MARKERS:
                assert marker in block, f"{method} 工具的描述里缺少「{marker}」"

    def test_read_only_tool_has_no_mutating_warning(self):
        """只读工具不该被写上一句「会改数据」—— 那会让警示失去意义。"""
        registry = _registry(method="GET")
        registry["endpoints"][0]["tool_name"] = "get_orders"
        block = _tool_source(registry, "get_orders")

        for marker in WARNING_MARKERS:
            assert marker not in block

    def test_warning_is_inside_the_docstring_not_the_body(self):
        """必须写在调用方读得到的 docstring 里，不能只是代码里的注释。"""
        block = _tool_source(_registry(), "del_order")
        doc = block[block.index('"""') + 3:block.index('"""', block.index('"""') + 3)]

        assert "会真的修改服务器上的数据" in doc


class TestGeneratedReadmeListsMutatingTools:
    def _readme(self) -> str:
        registry = _registry()
        registry["endpoints"].append({
            "tool_name": "get_orders", "method": "GET", "host": HOST, "path": "/api/orders",
            "path_params": [], "query_params": {}, "sample_count": 3,
            "auth_required": True, "status": "active", "description": "订单列表",
        })
        return render_server(registry)["README.md"]

    def test_has_a_dedicated_section(self):
        readme = self._readme()
        assert "会修改服务器数据的工具" in readme
        assert "可能撤不回来" in readme

    def test_names_the_mutating_tool(self):
        readme = self._readme()
        section = readme[readme.index("会修改服务器数据的工具"):]

        assert "- `del_order`" in section

    def test_read_only_tools_are_not_in_the_list(self):
        readme = self._readme()
        section = readme[readme.index("会修改服务器数据的工具"):]
        # 清单到「其余工具都只读」这句为止；只读 GET 工具不能出现在里面。
        listing = section[:section.index("其余工具都只读")]
        assert "get_orders" not in listing
        assert "其余工具都只读" in section

    def test_no_such_section_when_nothing_mutates(self):
        registry = _registry(method="GET", tool_name="get_orders")
        readme = render_server(registry)["README.md"]

        assert "会修改服务器数据的工具" not in readme


class TestConfirmGateStillStopsTheRequest:
    """警示是**附加**的，不能削弱原有的 confirm 门槛：不传就一个请求都不发。"""

    def _load(self, tmp_path: Path, monkeypatch) -> tuple[object, list]:
        calls: list = []

        class _Resp:
            status_code = 200
            content = b"{}"
            text = "{}"

            def json(self):
                return {}

            def raise_for_status(self):
                return None

        class FakeAsyncClient:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def request(self, method, path, **kwargs):
                calls.append({"method": method, "path": path})
                return _Resp()

        fake_httpx = types.ModuleType("httpx")
        fake_httpx.AsyncClient = FakeAsyncClient
        fake_httpx.HTTPError = type("HTTPError", (Exception,), {})
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

        class FakeFastMCP:
            def __init__(self, name):
                pass

            def tool(self, *args, **kwargs):
                return lambda fn: fn

            def run(self):
                pass

        fake_fastmcp = types.ModuleType("fastmcp")
        fake_fastmcp.FastMCP = FakeFastMCP
        monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)

        target = tmp_path / "server.py"
        target.write_text(render_server(_registry())["server.py"], encoding="utf-8")
        spec = importlib.util.spec_from_file_location("gen_s33_server", target)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, calls

    def test_without_confirm_nothing_is_sent(self, tmp_path, monkeypatch):
        module, calls = self._load(tmp_path, monkeypatch)

        result = asyncio.run(module.del_order())

        assert result["need_confirm"] is True
        assert calls == []          # 请求根本没发出去

    def test_with_confirm_the_call_goes_out_and_is_audited(self, tmp_path, monkeypatch):
        module, calls = self._load(tmp_path, monkeypatch)
        monkeypatch.setattr(module, "AUDIT_PATH", tmp_path / "audit.log")

        asyncio.run(module.del_order(confirm=True))

        assert [(c["method"], c["path"]) for c in calls] == [("POST", "/api/orders/9")]
        assert "del_order" in (tmp_path / "audit.log").read_text(encoding="utf-8")
