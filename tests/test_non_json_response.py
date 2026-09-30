# -*- coding: utf-8 -*-
"""Issue #16：非 JSON 响应端点（页面/控件端点）的判定与生成过滤。

页面/控件端点（.axd/.aspx/.asmx/.svc 等）响应 text/html 或 302，不是 JSON
数据接口。修复前它们被生成为「调用并解析 JSON」的工具，实际调用直接
JSONDecodeError。判定按响应 Content-Type（+ 3xx 重定向），仅标记不删除。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from webapi_extractor.analyzer import (
    _is_json_content_type,
    _non_json_response,
    analyze_capture,
    is_attachment_disposition,
    is_business_file_download,
)
from webapi_extractor.generator import render_server
from webapi_extractor.project import generation_skip_reasons, session_to_registry_entries


class TestIsJsonContentType:
    @pytest.mark.parametrize("content_type,expected", [
        # JSON 变体
        ("application/json", True),
        ("application/json; charset=utf-8", True),
        ("application/odata+json", True),
        ("application/problem+json", True),
        ("text/json", True),
        ("application/hal+json; charset=utf-8", True),
        # 页面/控件端点
        ("text/html", False),
        ("text/html; charset=utf-8", False),
        ("text/plain", False),
        ("application/javascript", False),
        ("application/octet-stream", False),
        # 无 Content-Type（204/无体）
        ("", False),
        (None, False),
    ])
    def test_classification(self, content_type, expected):
        assert _is_json_content_type(content_type) is expected


def _resp(headers: dict | None = None, status: int | None = None) -> dict:
    return {"headers": headers or {}, "status": status}


class TestNonJsonResponse:
    def test_html_response_is_non_json(self):
        assert _non_json_response([_resp({"Content-Type": "text/html"}, 200)]) is True

    def test_json_response_is_not_non_json(self):
        assert _non_json_response([_resp({"Content-Type": "application/json"}, 200)]) is False

    def test_odata_json_is_not_non_json(self):
        assert _non_json_response([_resp({"Content-Type": "application/odata+json"}, 200)]) is False

    def test_redirect_without_content_type_is_non_json(self):
        # 302 跳转（即使没带 Content-Type）也是页面端点
        assert _non_json_response([_resp({}, 302)]) is True

    def test_mixed_json_and_html_is_kept(self):
        """只要有任一 JSON 响应，就视为数据接口、不误标（保守）。"""
        responses = [
            _resp({"Content-Type": "application/json"}, 200),
            _resp({"Content-Type": "text/html"}, 500),
        ]
        assert _non_json_response(responses) is False

    def test_no_response_info_is_not_non_json(self):
        # 无响应头、无状态码（如 $batch 子请求）——无证据，不标记
        assert _non_json_response([{"headers": {}, "status": None}]) is False

    def test_empty_list_is_not_non_json(self):
        assert _non_json_response([]) is False


class TestRegistryFilter:
    def _analysis(self, endpoints):
        return {"endpoints": endpoints, "auth_metadata": {"auth_schemes": {}}}

    def _ep(self, name, **extra):
        ep = {
            "method": "GET",
            "host": "example.com",
            "path": f"/{name}",
            "query_params": {},
            "sample_count": 2,
            "request_schema": None,
            "response_schema": None,
            "auth_required": False,
            "description": None,
            "notes": None,
            "url": f"https://example.com/{name}",
        }
        ep.update(extra)
        return ep

    def test_non_json_endpoint_skipped_by_default(self):
        eps = [
            self._ep("data", non_json_response=False),
            self._ep("dashboard", non_json_response=True),
        ]
        entries, _ = session_to_registry_entries(self._analysis(eps), "s1")
        assert [e["tool_name"] for e in entries] == ["get_data"]

    def test_non_json_endpoint_kept_with_include_noise(self):
        eps = [
            self._ep("data", non_json_response=False),
            self._ep("dashboard", non_json_response=True),
        ]
        entries, _ = session_to_registry_entries(self._analysis(eps), "s1", include_noise=True)
        names = {e["tool_name"] for e in entries}
        assert names == {"get_data", "get_dashboard"}
        # 保留标记，供人工复核
        report = next(e for e in entries if e["tool_name"] == "get_dashboard")
        assert report["non_json_response"] is True


class TestRedirectHopsSurvive:
    """C-3 #2：重定向链不得塌成最后一跳，且 3xx 不能把最终端点误标成非 JSON。

    CDP 对重定向会用**同一个 requestId 重新发出** ``requestWillBeSent``
    （capture.py 里也有这条注释）。此前按 requestId 建 dict，整条链只剩最后一跳：
    ``POST /form/x → 302 → GET /result`` 里真正干活的 POST 消失，生成出的是一个
    没人要的 GET 工具。修复后每一跳都保留，交给既有的端点身份/合并逻辑收敛。

    同时要保证 3xx 那一跳**不会**顺着 ``_non_json_response`` 把最终端点误标成
    「非 JSON」——最终端点的响应就是这条 requestId 的末条响应（200 JSON）。
    """

    POST_URL = "https://oa.example.com/form/x"
    GET_URL = "https://oa.example.com/result"

    def _capture(self, tmp_path: Path) -> Path:
        session = tmp_path / "cap"
        session.mkdir()
        events = [
            # 跳 1：真正干活的 POST（表单提交）
            {"type": "request", "requestId": "r1", "url": self.POST_URL, "method": "POST",
             "resourceType": "Document", "postData": "user=alice",
             "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
            # 3xx 那一跳：按 CDP 时序先落盘
            {"type": "response", "requestId": "r1", "status": 302, "headers": {}},
            # 跳 2：重定向后的落地页（同一个 requestId）
            {"type": "request", "requestId": "r1", "url": self.GET_URL, "method": "GET",
             "resourceType": "Document", "headers": {"Accept": "application/json"}},
            {"type": "response", "requestId": "r1", "status": 200,
             "headers": {"Content-Type": "application/json"}},
            {"type": "response_body", "requestId": "r1", "body": '{"ok":true}', "size": 11},
        ]
        (session / "capture.jsonl").write_text(
            "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        return session

    def test_every_hop_is_kept(self, tmp_path):
        analysis = analyze_capture(self._capture(tmp_path))

        assert [(e["method"], e["path"]) for e in analysis["endpoints"]] == [
            ("POST", "/form/x"), ("GET", "/result")]
        # 仍是「不同 requestId 的个数」，重定向重复事件不算新请求
        assert analysis["stats"]["total"] == 1

    def test_the_redirect_does_not_mark_the_final_endpoint_non_json(self, tmp_path):
        analysis = analyze_capture(self._capture(tmp_path))

        assert all(e["non_json_response"] is False for e in analysis["endpoints"]), \
            [e["non_json_response"] for e in analysis["endpoints"]]

    def test_the_post_hop_is_still_generated(self, tmp_path):
        """修复前这里只剩 GET /result —— 调用方要的那个 POST 永远不会出现。"""
        entries, _ = session_to_registry_entries(analyze_capture(self._capture(tmp_path)), "s1")

        assert sorted(e["path"] for e in entries) == ["/form/x", "/result"]
        assert [e["method"] for e in entries if e["path"] == "/form/x"] == ["POST"]


# --------------------------------------------------------------------------- #
# Fix 1：业务文件下载端点（报表/导出）不得被「非 JSON」这条规则吞掉
#
# 实测（audit/csv_probe）：`GET /api/report.csv` 的响应是 `Content-Type: text/csv`
# → `_non_json_response=True` → `session_to_registry_entries` 丢弃 → **0 个端点**
# 进 registry，一个工具都不生成。下载报表正是这类系统的用途，是能力缺口。
# 但也不能「非 JSON 一律放行」：HTML 页面 / 追踪像素被当成数据工具更糟。
# --------------------------------------------------------------------------- #
def _resp_of(headers: dict | None = None, status: int = 200) -> dict:
    return {"headers": headers or {}, "status": status}


class TestBusinessFileDownloadPredicate:
    """三条证据（Content-Disposition: attachment / 文档类 Content-Type / 路径扩展名+GET）。"""

    @pytest.mark.parametrize("value,expected", [
        ("attachment; filename=\"report.csv\"", True),
        ("ATTACHMENT", True),
        (" attachment ; filename=x", True),
        # inline 是浏览器内联展示（页面/图片），不是下载
        ("inline; filename=\"report.csv\"", False),
        ("inline", False),
        ("", False),
        (None, False),
    ])
    def test_attachment_disposition(self, value, expected):
        assert is_attachment_disposition(value) is expected

    @pytest.mark.parametrize("method,path,headers,expected", [
        # 证据 2：文档/表格/压缩包类 Content-Type
        ("GET", "/api/report.csv", {"Content-Type": "text/csv"}, True),
        ("GET", "/download", {"Content-Type": "application/pdf"}, True),
        ("GET", "/api/export/book", {"Content-Type": "application/vnd.ms-excel"}, True),
        ("GET", "/api/export/sheet", {
            "Content-Type": "application/vnd.openxmlformats-officedocument."
                             "spreadsheetml.sheet"}, True),
        ("GET", "/api/export/archive", {"Content-Type": "application/zip"}, True),
        # 证据 1：Content-Disposition: attachment（即使类型是泛二进制）
        ("GET", "/download", {"Content-Type": "application/octet-stream",
                              "Content-Disposition": "attachment; filename=\"r.pdf\""}, True),
        # 证据 3：路径扩展名 + GET
        ("GET", "/api/export/archive.zip", {}, True),
        ("GET", "/api/report.csv", {}, True),
        # 证据 3 要求 GET：POST 导出（无其它证据时）不认
        ("POST", "/api/export/archive.zip", {}, False),
        # 负例：普通 HTML 页面
        ("GET", "/dashboard", {"Content-Type": "text/html"}, False),
        ("GET", "/api/page.aspx", {"Content-Type": "text/html; charset=utf-8"}, False),
        ("GET", "/dashboard", {"Content-Type": "text/html",
                               "Content-Disposition": "inline"}, False),
        # 负例：追踪像素（image/* 永不认）
        ("GET", "/px", {"Content-Type": "image/gif"}, False),
        ("GET", "/beacon/collect", {"Content-Type": "image/png"}, False),
        # 负例：泛二进制且无任何文件名 / 路径线索
        ("GET", "/api/blob", {"Content-Type": "application/octet-stream"}, False),
        # octet-stream **有**文件名线索时才认（题目要求的组合条件）
        ("GET", "/api/blob", {"Content-Type": "application/octet-stream",
                              "Content-Disposition": "inline; filename=\"x.pdf\""}, True),
        ("GET", "/api/files/x.pdf", {"Content-Type": "application/octet-stream"}, True),
        # text/plain 不在白名单：它太宽，页面与接口都可能是它
        ("GET", "/api/notes", {"Content-Type": "text/plain"}, False),
        ("GET", "/api/users", {"Content-Type": "application/json"}, False),
        # 无响应信息（如 $batch 子请求）时，路径扩展名 + GET 仍算证据
        ("GET", "/api/export/report.xlsx", {}, True),
        ("POST", "/api/export/report.xlsx", {}, False),
    ])
    def test_predicate(self, method, path, headers, expected):
        assert is_business_file_download(method, path, [_resp_of(headers)]) is expected

    def test_no_responses_is_not_a_file_download(self):
        assert is_business_file_download("GET", "/api/orders", []) is False


class TestFileEndpointSurvivesGeneration:
    """文件端点必须活到 registry（此前这条路是 0 个端点进 registry）。"""

    def _analysis(self, endpoints):
        return {"endpoints": endpoints, "auth_metadata": {"auth_schemes": {}}}

    def _ep(self, name, **extra):
        ep = {"method": "GET", "host": "oa.example.com", "path": f"/{name}",
              "query_params": {}, "sample_count": 1, "request_schema": None,
              "response_schema": None, "auth_required": False, "description": None,
              "notes": None, "url": f"https://oa.example.com/{name}"}
        ep.update(extra)
        return ep

    def test_file_response_exempts_one_skip_reason_only(self):
        """只豁免 `non_json_response`：噪音 / 不可独立调用仍是硬跳过理由。"""
        assert generation_skip_reasons(
            self._ep("api/report.csv", non_json_response=True, file_response=True)) == []
        assert generation_skip_reasons(
            self._ep("api/report.csv", non_json_response=True)) == ["non_json_response"]
        assert generation_skip_reasons(
            self._ep("collect/v1", noise=True, file_response=True)) == ["noise"]
        assert generation_skip_reasons(
            self._ep("api/export/x.xlsx", not_independently_callable=True,
                     file_response=True)) == ["not_independently_callable"]

    def test_csv_endpoint_reaches_the_registry(self):
        entries, _ = session_to_registry_entries(self._analysis([
            self._ep("api/orders", non_json_response=False, file_response=False),
            self._ep("api/report.csv", non_json_response=True, file_response=True),
        ]), "s1")

        assert sorted(e["tool_name"] for e in entries) == ["get_api_orders", "get_api_report_csv"]
        report = next(e for e in entries if e["tool_name"] == "get_api_report_csv")
        assert report["file_response"] is True
        # 原始观测仍然保留（它确实不是 JSON），只是不再据此丢弃
        assert report["non_json_response"] is True

    def test_forced_include_defaults_to_false(self):
        entries, _ = session_to_registry_entries(self._analysis([self._ep("api/orders")]), "s1")
        assert entries[0]["forced_include"] is False


def test_content_disposition_survives_redaction():
    """判定依赖**响应头**，故落盘前不能把它抹掉。

    `capture.on_response` 的响应头会先过 `redact_headers`（Authorization / Cookie /
    token 类整段遮蔽）。`Content-Disposition` 是**证据**不是凭据，必须原样留下，
    否则 attachment 这条判据永远读不到。
    """
    from webapi_extractor.redaction import redact_headers

    redacted = redact_headers({"Content-Disposition": 'attachment; filename="q3.csv"',
                              "Content-Type": "text/csv"})

    assert redacted == {"Content-Disposition": 'attachment; filename="q3.csv"',
                        "Content-Type": "text/csv"}


class TestFileEndpointEndToEnd:
    """一次真实抓包 → analysis → registry：文件端点活着，页面与像素仍然被丢。"""

    CASES = [
        ("https://oa.example.com/api/report.csv", "GET",
         {"Content-Type": "text/csv"}, "id,name\n1,bob", True),
        # 无扩展名，靠 attachment + octet-stream 认定
        ("https://oa.example.com/export/download", "GET",
         {"Content-Type": "application/octet-stream",
          "Content-Disposition": "attachment; filename=\"q3.xlsx\""}, "\x00\x01", True),
        ("https://oa.example.com/dashboard", "GET", {"Content-Type": "text/html"},
         "<html>ok</html>", False),
        ("https://oa.example.com/api/page.aspx", "GET", {"Content-Type": "text/html"},
         "<html>ok</html>", False),
        # 追踪像素：路径不带静态扩展名，故确实会进分析（不会先被静态规则滤掉）
        ("https://oa.example.com/px", "GET", {"Content-Type": "image/gif"}, "GIF89a", False),
        ("https://oa.example.com/api/blob", "GET",
         {"Content-Type": "application/octet-stream"}, "\x00\x01", False),
    ]

    def _capture(self, tmp_path: Path) -> Path:
        session = tmp_path / "cap"
        session.mkdir()
        lines = []
        for index, (url, method, headers, body, _) in enumerate(self.CASES):
            request_id = f"r{index}"
            lines += [
                {"type": "request", "requestId": request_id, "url": url, "method": method,
                 "headers": {}, "resourceType": "XHR"},
                {"type": "response", "requestId": request_id, "status": 200, "headers": headers},
                {"type": "response_body", "requestId": request_id, "body": body,
                 "size": len(body)},
            ]
        (session / "capture.jsonl").write_text(
            "\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
        return session

    def test_analysis_marks_only_real_downloads(self, tmp_path):
        analysis = analyze_capture(self._capture(tmp_path))
        by_path = {e["path"]: e for e in analysis["endpoints"]}

        assert {path: e["file_response"] for path, e in by_path.items()} == {
            "/api/report.csv": True,
            "/export/download": True,
            "/dashboard": False,
            "/api/page.aspx": False,
            "/px": False,
            "/api/blob": False,
        }
        # 页面/像素的「非 JSON」判定不受影响
        assert by_path["/dashboard"]["non_json_response"] is True
        assert by_path["/px"]["non_json_response"] is True
        assert analysis["stats"]["file_response"] == 2

    def test_registry_keeps_files_and_drops_pages(self, tmp_path):
        analysis = analyze_capture(self._capture(tmp_path))
        entries, _ = session_to_registry_entries(analysis, "s1")

        assert sorted(e["path"] for e in entries) == ["/api/report.csv", "/export/download"]

    def _rendered(self, tmp_path):
        analysis = analyze_capture(self._capture(tmp_path))
        entries, hosts = session_to_registry_entries(analysis, "s1")
        registry = {"site_name": "portal", "registry_version": 1, "hosts": hosts,
                    "endpoints": entries, "auth_login": None}
        return render_server(registry)

    def test_the_generated_tool_returns_the_body_verbatim(self, tmp_path):
        """生成的工具必须如实返回文件原文，而不是假装有 JSON schema。"""
        files = self._rendered(tmp_path)
        server = files["server.py"]

        compile(server, "server.py", "exec")          # 生成物必须能编译
        # raw 通道只在真有文件端点时才发射
        assert "raw: bool = False" in server
        assert "_raw_payload" in server
        assert "raw=True" in server
        # docstring 必须说清「这是文件/流、要自己落盘」
        assert "[FILE]" in server
        assert "落盘" in server
        # README 也要能一眼看出哪些工具返回文件
        assert "[FILE]" in files["README.md"]
        assert "文件 / 流式响应工具" in files["README.md"]

    def test_pure_json_registry_gets_no_raw_machinery(self):
        """良性（纯 JSON）产物不得被这条新链路扰动 —— 冻结输出守卫的前提。"""
        files = render_server({"site_name": "portal", "registry_version": 1,
                               "hosts": {}, "endpoints": [], "auth_login": None})
        assert "_raw_payload" not in files["server.py"]
        assert "raw: bool = False" not in files["server.py"]
        assert "文件 / 流式响应工具" not in files["README.md"]


class TestEmittedRawPayload:
    """直接执行**发射出来的** `_raw_payload`：文本原样、二进制给 base64。"""

    def _helpers(self) -> dict:
        import ast
        import base64 as b64

        files = render_server({
            "site_name": "portal", "registry_version": 1, "hosts": {}, "auth_login": None,
            "endpoints": [{"tool_name": "get_report", "method": "GET", "host": "h",
                           "path": "/api/report.csv", "path_params": [], "query_params": {},
                           "sample_count": 1, "status": "active", "file_response": True}]})
        tree = ast.parse(files["server.py"])
        wanted = {"_TEXT_CONTENT_TYPES", "_TEXT_CONTENT_SUFFIXES", "_TEXT_CONTENT_EXACT",
                  "_is_text_content_type", "_raw_payload"}
        picked = [node for node in tree.body
                  if (isinstance(node, ast.FunctionDef) and node.name in wanted)
                  or (isinstance(node, ast.Assign)
                      and getattr(node.targets[0], "id", "") in wanted)]
        assert "def _raw_payload" in files["server.py"], "测试自身失效：没发射出 _raw_payload"
        namespace = {"base64": b64}
        exec(compile(ast.Module(body=picked, type_ignores=[]), "<emitted>", "exec"), namespace)
        return namespace

    class _Resp:
        def __init__(self, content: bytes, content_type: str, status: int = 200,
                     disposition: str = "") -> None:
            self.content = content
            self.text = content.decode("utf-8", "replace")
            self.status_code = status
            self.headers = {"content-type": content_type, "content-disposition": disposition}

    def test_text_content_is_returned_verbatim(self):
        payload = self._helpers()["_raw_payload"](
            self._Resp(b"id,name\n1,bob", "text/csv",
                       disposition='attachment; filename="report.csv"'))

        assert payload["text"] == "id,name\n1,bob"
        assert "base64" not in payload
        assert payload["content_type"] == "text/csv"
        assert payload["status"] == 200
        assert payload["size"] == len(b"id,name\n1,bob")
        assert payload["content_disposition"] == 'attachment; filename="report.csv"'

    def test_binary_content_is_returned_as_base64(self):
        import base64 as b64

        raw = b"%PDF-1.7\x00\xff"
        payload = self._helpers()["_raw_payload"](self._Resp(raw, "application/pdf"))

        assert payload["base64"] == b64.b64encode(raw).decode("ascii")
        assert "text" not in payload

    def test_octet_stream_is_treated_as_binary(self):
        payload = self._helpers()["_raw_payload"](
            self._Resp(b"\x00\x01", "application/octet-stream"))

        assert payload["base64"] == "AAE="


class TestGeneratedFileToolRuns:
    """真跑一遍生成物：文件工具必须返回响应体原文（raw 分支真的走到了）。

    只断言「源码里有 raw=True」是不够的——注入错位置一样能编译通过。这里把生成的
    server.py 作为模块加载，用假的 httpx/fastmcp 顶替依赖，直接调用工具函数。
    """

    HOST = "oa.example.com"

    class _Resp:
        def __init__(self, content: bytes, content_type: str):
            self.status_code = 200
            self.content = content
            self.text = content.decode("utf-8", "replace")
            self.headers = {"content-type": content_type,
                            "content-disposition": 'attachment; filename="report.csv"'}

        def raise_for_status(self):
            return None

    def _load(self, tmp_path: Path, monkeypatch, endpoint: dict, response):
        import importlib.util
        import sys
        import types

        calls: list = []

        class FakeAsyncClient:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def request(self, method, path, **kwargs):
                calls.append((method, path, kwargs.get("params")))
                return response

        fake_httpx = types.ModuleType("httpx")
        fake_httpx.AsyncClient = FakeAsyncClient
        fake_httpx.HTTPError = type("HTTPError", (Exception,), {})

        class FakeFastMCP:
            def __init__(self, name):
                self.name = name

            def tool(self, *args, **kwargs):
                return lambda fn: fn

            def run(self):
                pass

        fake_fastmcp = types.ModuleType("fastmcp")
        fake_fastmcp.FastMCP = FakeFastMCP
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
        monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)

        registry = {"site_name": "portal", "registry_version": 1,
                    "hosts": {self.HOST: {"scheme": None, "cookie_names": []}},
                    "auth_login": None, "endpoints": [endpoint]}
        target = tmp_path / "server.py"
        target.write_text(render_server(registry)["server.py"], encoding="utf-8")
        spec = importlib.util.spec_from_file_location("generated_probe_server", target)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, calls

    def _endpoint(self, path="/api/report.csv", tool_name="get_api_report_csv"):
        return {"tool_name": tool_name, "method": "GET", "host": self.HOST, "path": path,
                "path_params": [], "query_params": {"page": ["1"]}, "sample_count": 1,
                "status": "active", "file_response": True, "auth_required": False,
                "description": "导出报表"}

    def test_text_file_is_returned_verbatim(self, tmp_path, monkeypatch):
        import asyncio

        response = self._Resp(b"id,name\n1,bob", "text/csv; charset=utf-8")
        module, calls = self._load(tmp_path, monkeypatch, self._endpoint(), response)

        result = asyncio.run(module.get_api_report_csv(page=1))

        assert calls == [("GET", "/api/report.csv", {"page": 1})]
        assert result["text"] == "id,name\n1,bob"
        assert "base64" not in result
        assert result["content_type"].startswith("text/csv")
        assert result["status"] == 200
        assert result["content_disposition"] == 'attachment; filename="report.csv"'
        assert (module.get_api_report_csv.__doc__.startswith("[FILE]")
                and "落盘" in module.get_api_report_csv.__doc__)

    def test_binary_file_is_returned_as_base64(self, tmp_path, monkeypatch):
        import asyncio
        import base64 as b64

        raw = b"%PDF-1.7\x00\xff"
        module, calls = self._load(tmp_path, monkeypatch,
                                   self._endpoint("/api/export/blob",
                                                  "get_api_export_blob"),
                                   self._Resp(raw, "application/pdf"))

        # 该端点的 query 里有 `page`：名字像「取值会切换响应形态」的一类。它**没有实测
        # 证据**，故按分级是**可选、无默认值**（见 test_generator_robustness 的
        # TestSwitchParamsAreNeverBaked）—— 调用方不传时，请求里**不能**出现这个键
        # （`_clean` 丢掉 `None`），服务端才会用它自己的默认值。
        result = asyncio.run(module.get_api_export_blob())

        assert "page" not in (calls[0][2] or {}), calls        # 不传就不发
        assert result["base64"] == b64.b64encode(raw).decode("ascii")
        assert "text" not in result
