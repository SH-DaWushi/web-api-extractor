# -*- coding: utf-8 -*-
"""Issue #23：表单编码的 POST 请求体必须变成工具参数。

传统服务端渲染系统普遍靠表单编码体传参：

    POST /api/portal/dashboard/data
    section=4&companyId=2&menuIds=0%2C4

修复前 analyzer 只对能 json.loads 的请求体产出 request_schema，表单体全丢，
生成的工具签名只剩 confirm —— 能连通、能鉴权，但缺参数必然业务报错。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from webapi_extractor.analyzer import analyze_capture
from webapi_extractor.bodies import body_fields, parse_form_urlencoded
from webapi_extractor.generator import _param_decl, _render_tool, render_server
from webapi_extractor.project import session_to_registry_entries

URL = "https://portal.example.com/api/portal/dashboard/data"
FORM_BODY = "section=4&companyId=2&menuIds=0%2C4&includeHidden=false"


def _session(tmp_path: Path, samples: int = 2) -> Path:
    lines = []
    for i in range(samples):
        rid = f"r{i}"
        lines += [
            {"type": "request", "requestId": rid, "url": URL, "method": "POST",
             "postData": FORM_BODY, "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
            {"type": "response", "requestId": rid, "status": 200,
             "headers": {"Content-Type": "text/plain; charset=utf-8"}},
            {"type": "response_body", "requestId": rid, "body": '{"data": []}', "size": 12},
        ]
    (tmp_path / "capture.jsonl").write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in lines), encoding="utf-8")
    return tmp_path


class TestSharedParser:
    """解析逻辑已收敛到 bodies.py 单一实现（脱敏/密文判定/取参共用）。"""

    def test_parse_pairs(self):
        assert parse_form_urlencoded(FORM_BODY)[:2] == [("section", "4"), ("companyId", "2")]

    def test_decodes_values(self):
        assert body_fields("menuIds=0%2C4")["menuIds"] == "0,4"

    def test_json_body_not_treated_as_form(self):
        assert parse_form_urlencoded('{"a": 1}') is None

    def test_html_not_treated_as_form(self):
        assert parse_form_urlencoded("<html>a=b</html>") is None

    def test_valueless_segment_is_tolerated(self):
        """D1：真实登录表单带无值控制项（``&submit``），不能因此判「非表单编码」。

        修复前这个 None 直接导致脱敏层原样放行整个请求体（明文密码落盘）。
        """
        assert parse_form_urlencoded("password=Secret1&submit") == \
               [("password", "Secret1"), ("submit", "")]

    def test_pure_text_without_equals_still_not_form(self):
        """容忍无值段 ≠ 把纯文本当表单：完全不含 ``=`` 仍返回 None。"""
        assert parse_form_urlencoded("just some text") is None
        assert parse_form_urlencoded("") is None


class TestRedactionPreservesStructure:
    """脱敏必须只遮值、不破坏键名——analyzer 的参数推断依赖同一份请求体。"""

    def test_key_names_identical_after_redaction(self):
        from webapi_extractor.redaction import redact_payload

        body = "section=4&companyId=2&menuIds=0%2C4&password=Secret1&submit"
        red, _, _ = redact_payload(body)
        assert "Secret1" not in red
        assert "section=4" in red          # 非敏感值原样保留
        assert "companyId=2" in red
        # 键名与顺序完全一致 → 生成的工具参数不会因脱敏而变。
        assert [k for k, _ in parse_form_urlencoded(red)] == \
               [k for k, _ in parse_form_urlencoded(body)]

    def test_redacted_body_keeps_field_names(self):
        """脱敏后的体仍能解析出全套字段名（analyzer 走的就是这条路径）。"""
        from webapi_extractor.redaction import redact_payload

        red, _, _ = redact_payload("section=4&companyId=2&password=Secret1&submit")
        assert parse_form_urlencoded(red) is not None
        fields = body_fields(red)
        assert set(fields) == {"section", "companyId", "password", "submit"}
        assert fields["section"] == "4"
        assert fields["password"] == "***"


class TestAnalyzerExtracts:
    def test_form_fields_collected(self, tmp_path):
        analysis = analyze_capture(_session(tmp_path))
        ep = analysis["endpoints"][0]
        params = ep.get("request_body_params") or {}
        assert "section" in params
        assert params["section"] == ["4"]
        assert params["companyId"] == ["2"]
        assert params["menuIds"] == ["0,4"]     # URL 解码后的值

    def test_valueless_control_does_not_drop_other_fields(self, tmp_path):
        """D1 的取参侧：带 ``&submit`` 的表单体不能因为容忍解析而丢字段。"""
        lines = []
        body = "section=4&companyId=2&submit"
        for i in range(2):
            rid = f"r{i}"
            lines += [
                {"type": "request", "requestId": rid, "url": URL, "method": "POST",
                 "postData": body, "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
                {"type": "response", "requestId": rid, "status": 200,
                 "headers": {"Content-Type": "text/plain; charset=utf-8"}},
                {"type": "response_body", "requestId": rid, "body": '{"data": []}', "size": 12},
            ]
        (tmp_path / "capture.jsonl").write_text(
            "\n".join(json.dumps(x, ensure_ascii=False) for x in lines), encoding="utf-8")
        params = analyze_capture(tmp_path)["endpoints"][0]["request_body_params"]
        assert params["section"] == ["4"]
        assert params["companyId"] == ["2"]

    def test_json_body_still_uses_request_schema(self, tmp_path):
        """原有 JSON 路径不受影响。"""
        lines = [
            {"type": "request", "requestId": "r1", "url": "https://x.example.com/api/a",
             "method": "POST", "postData": '{"name": "bob"}', "headers": {}},
            {"type": "response", "requestId": "r1", "status": 200,
             "headers": {"Content-Type": "application/json"}},
            {"type": "response_body", "requestId": "r1", "body": "{}", "size": 2},
        ]
        (tmp_path / "capture.jsonl").write_text(
            "\n".join(json.dumps(x) for x in lines), encoding="utf-8")
        ep = analyze_capture(tmp_path)["endpoints"][0]
        assert ep.get("request_schema")
        assert ep.get("request_body_params") in ({}, None)


class TestRegistryPassthrough:
    def test_entries_carry_body_params(self, tmp_path):
        analysis = analyze_capture(_session(tmp_path))
        entries, _ = session_to_registry_entries(analysis, "s1")
        assert entries[0]["request_body_params"]["section"] == ["4"]


class TestRenderedTool:
    def _entry(self, **extra):
        base = {
            "tool_name": "dashboard", "method": "POST", "host": "portal.example.com",
            "path": "/api/portal/dashboard/data", "path_params": [],
            "query_params": {}, "sample_count": 3,
        }
        base.update(extra)
        return base

    def test_signature_exposes_body_fields(self):
        src = _render_tool(self._entry(request_body_params={"section": ["4"], "companyId": ["2"]}), "PORTAL")
        assert "section" in src and "companyId" in src
        assert "confirm: bool = False" in src

    def test_call_uses_form_body(self):
        src = _render_tool(self._entry(request_body_params={"section": ["4"]}), "PORTAL")
        assert "form_body={" in src
        assert "json_body=" not in src

    def test_no_body_kwarg_without_params(self):
        src = _render_tool(self._entry(), "PORTAL")
        assert "form_body=" not in src

    def test_default_gate_blocks_volatile_values(self):
        """含逗号的值不给默认（避免把抓包当时的真实数据烘进分发包）。"""
        src = _render_tool(self._entry(request_body_params={"menuIds": ["0,4"]}), "PORTAL")
        assert "menuIds: str | None = None" in src

    def test_identity_like_name_gets_no_default(self):
        src = _render_tool(self._entry(request_body_params={"userId": ["1001"]}), "PORTAL")
        assert "userId: int | None = None" in src


class TestParamDeclGate:
    # 门禁有两条路：证据说 `fixed`，或「无证据 + 观测取值唯一」；两条都还要过名字/取值闸门。
    # 故这里给关键用例显式配一份 fixed 证据，专门考名字/取值那道闸门；`None` 代表没有证据。
    _FIXED = {"class": "fixed", "values": ["4"], "present_in": 2, "requests": 2,
              "switch_risk": False, "behaviour_switch": None, "verified": True}

    @pytest.mark.parametrize("ident,values,evidence,expected", [
        ("section", ["4"], _FIXED, "'4'"),     # 固定 + 稳定短值 → 给默认
        ("menuIds", ["0,4"], _FIXED, None),    # 含逗号 → 不给
        ("section", ["4"], None, "'4'"),       # 无证据但取值唯一 → 给默认（良性就保留）
        ("section", ["4", "5"], None, None),   # 无证据 + 多取值 → 不给（确切可变）
        ("password", ["***"], _FIXED, None),   # 脱敏哨兵 → 不给（见 Fix 2）
    ])
    def test_gate(self, ident, values, evidence, expected):
        decl = _param_decl(ident, "str", values, evidence)
        if expected is None:
            assert decl.endswith("| None = None"), decl
        else:
            assert expected in decl, decl

    def test_redaction_sentinel_never_becomes_a_default(self):
        """analyzer 读到的体**已脱敏**，敏感字段的取样值就是字面 `***`。

        `***` 又短又是 ASCII 又不含逗号，旧门槛全放行 → 生成物里出现
        `password: str = '***'`，调用方一调就把哨兵当密码发出去。
        """
        assert _param_decl("password", "str", ["***"], self._FIXED) \
            == "password: str | None = None"

    def test_different_length_mask_is_also_rejected(self):
        assert _param_decl("token", "str", ["*****"], self._FIXED) \
            == "token: str | None = None"

    def test_redacted_form_field_gets_no_default_end_to_end(self, tmp_path):
        """真路径：脱敏后的表单体 → analyzer → registry → 生成物。

        抓包落盘的 postData 已被脱敏（`password=***`），这条链路必须一路不烘默认值。
        """
        redacted = "section=4&password=***&submit"
        lines = []
        for i in range(2):
            rid = f"r{i}"
            lines += [
                {"type": "request", "requestId": rid, "url": URL, "method": "POST",
                 "postData": redacted,
                 "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
                {"type": "response", "requestId": rid, "status": 200,
                 "headers": {"Content-Type": "text/plain; charset=utf-8"}},
                {"type": "response_body", "requestId": rid, "body": '{"data": []}', "size": 12},
            ]
        (tmp_path / "capture.jsonl").write_text(
            "\n".join(json.dumps(x, ensure_ascii=False) for x in lines), encoding="utf-8")

        entry = session_to_registry_entries(analyze_capture(tmp_path), "s1")[0][0]
        src = _render_tool(entry, "PORTAL")

        assert "password: str | None = None" in src
        assert "'***'" not in src


class TestTemplateSupport:
    def test_template_has_form_channel(self):
        from webapi_extractor.generator import _SERVER_TEMPLATE
        assert "form_body" in _SERVER_TEMPLATE
        assert "application/x-www-form-urlencoded" in _SERVER_TEMPLATE


class TestRetryCarriesFormBody:
    """401 自动重登录后的重试必须**保持表单通道**。

    修复前重试只透传 `params` / `json_body`：表单端点被 401 后，重试的
    `body_kwargs` 退化成 `{"json": None}` 且不再带
    `application/x-www-form-urlencoded` —— 重登录明明成功，业务调用仍然失败
    （通常是 422 / 业务错误），读起来就像「重新登录没用」。

    只断言源码里有 `form_body=form_body` 不够：注入错位置一样能编译。这里把生成的
    server.py 当模块加载，用假的 httpx 顶替依赖，真跑一遍 401 → 重登录 → 重试。
    """

    HOST = "portal.example.com"
    PATH = "/api/portal/dashboard/data"
    FORM = {"section": "4", "menuIds": "0,4"}

    def _load(self, tmp_path: Path, monkeypatch, statuses: list):
        import importlib.util
        import sys
        import types

        calls: list = []

        class _Resp:
            def __init__(self, status: int):
                self.status_code = status
                self.content = b"{}"
                self.text = "{}"

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
                calls.append({"method": method, "path": path, **kwargs})
                return _Resp(statuses.pop(0))

        fake_httpx = types.ModuleType("httpx")
        fake_httpx.AsyncClient = FakeAsyncClient
        fake_httpx.HTTPError = type("HTTPError", (Exception,), {})
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

        class FakeFastMCP:
            def __init__(self, name):
                self.name = name

            def tool(self, *args, **kwargs):
                return lambda fn: fn

            def run(self):
                pass

        fake_fastmcp = types.ModuleType("fastmcp")
        fake_fastmcp.FastMCP = FakeFastMCP
        monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)

        # 有 auth_login 才会发射自动重登录分支（也是 form_body 透传的注入条件）。
        registry = {
            "site_name": "portal", "registry_version": 1,
            "hosts": {self.HOST: {"scheme": "Bearer", "cookie_names": []}},
            "endpoints": [{"tool_name": "dashboard", "method": "POST", "host": self.HOST,
                           "path": self.PATH, "auth_required": True, "status": "active",
                           "description": "仪表盘"}],
            "auth_login": {"method": "POST", "host": self.HOST, "path": "/api/login",
                           "account_field": "username", "password_field": "password",
                           "token_path": ["data", "token"], "query_params": {}},
        }
        target = tmp_path / "server.py"
        target.write_text(render_server(registry)["server.py"], encoding="utf-8")
        spec = importlib.util.spec_from_file_location("gen_retry_server", target)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # 重登录路径走桩件：不碰网络，也不碰 DPAPI 缓存。
        module._cached_credentials = lambda: ("bob", "secret")

        async def _fake_login(account, password):
            return {"success": True}

        module._do_login = _fake_login
        return module, calls

    def test_retry_keeps_form_encoding(self, tmp_path, monkeypatch):
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch, [401, 200])
        asyncio.run(module._request(self.HOST, "POST", self.PATH, form_body=dict(self.FORM)))

        assert len(calls) == 2, calls          # 401 原始请求 + 重登录后的重试
        retried = calls[1]
        assert retried["data"] == self.FORM    # 修复前：重试没有 data
        assert "json" not in retried           # 修复前：json=None
        assert retried["headers"]["Content-Type"].startswith(
            "application/x-www-form-urlencoded")

    def test_retry_keeps_json_channel_unchanged(self, tmp_path, monkeypatch):
        """JSON 路径不受影响：重试仍走 json，且不误加表单 Content-Type。"""
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch, [401, 200])
        asyncio.run(module._request(self.HOST, "POST", self.PATH, json_body={"section": "4"}))

        retried = calls[1]
        assert retried["json"] == {"section": "4"}
        assert "data" not in retried
        assert "application/x-www-form-urlencoded" not in retried["headers"].get("Content-Type", "")


class TestUnsetOptionalParamIsNotSent:
    """「不传就不发」—— 分级之后整条收口的地基。

    名字像开关的参数（`page` / `sort` …）在没有实测证据时是**可选、无默认值**。它要真的
    可选、且服务端能用自己的默认值，前提就是：调用方不传时，请求里**根本没有这个键**。
    发 `page=None` 或空串都不行 —— 前者是非法值、后者可能被服务端当成一个真筛选条件。

    生成器的工具签名与参数组装分处两地（`_param_decl` 给 `| None = None`，
    `_render_tool` 组 `params=` / `form_body=`），只断言源码形态证明不了线上行为。
    这里把生成的 server.py 当模块加载、用假的 httpx 顶替依赖，真跑一遍生成的工具，
    同时看 **query 与表单体**两条通道：不传 → 两个字典里都没有那两个键；传了 → 都有。
    """

    HOST = "portal.example.com"
    PATH = "/api/portal/dashboard/data"

    def _load(self, tmp_path: Path, monkeypatch):
        import importlib.util
        import sys
        import types

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
                calls.append({"method": method, "path": path, **kwargs})
                return _Resp()

        fake_httpx = types.ModuleType("httpx")
        fake_httpx.AsyncClient = FakeAsyncClient
        fake_httpx.HTTPError = type("HTTPError", (Exception,), {})
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

        class FakeFastMCP:
            def __init__(self, name):
                self.name = name

            def tool(self, *args, **kwargs):
                return lambda fn: fn

            def run(self):
                pass

        fake_fastmcp = types.ModuleType("fastmcp")
        fake_fastmcp.FastMCP = FakeFastMCP
        monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)

        registry = {
            "site_name": "portal", "registry_version": 1,
            "hosts": {self.HOST: {"scheme": None, "cookie_names": []}},
            "auth_login": None,
            "endpoints": [{
                "tool_name": "dashboard", "method": "POST", "host": self.HOST,
                "path": self.PATH, "path_params": [], "status": "active",
                "description": "仪表盘",
                # 两条通道各放一对：`page` / `sort` 名字像开关（无实测证据 → 可选无默认值），
                # `status` / `section` 是良性固定值（照烘成默认值）。
                "query_params": {"page": ["1"], "status": ["open"]},
                "request_body_params": {"sort": ["created"], "section": ["4"]},
            }],
        }
        target = tmp_path / "server.py"
        target.write_text(render_server(registry)["server.py"], encoding="utf-8")
        spec = importlib.util.spec_from_file_location("gen_unset_server", target)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, calls

    def test_unset_switch_params_are_absent_from_the_wire(self, tmp_path, monkeypatch):
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch)
        asyncio.run(module.dashboard(confirm=True))

        sent = calls[0]
        params = sent.get("params") or {}
        data = sent.get("data") or {}
        assert "page" not in params, sent          # 不传 → query 里没有这个键
        assert "sort" not in data, sent            # 不传 → 表单体里没有这个键
        # 烘了默认值的良性参数照旧发（「烘」与「必发」是两回事，这里只是确认不是全都不发）
        assert params.get("status") == "open"
        assert data.get("section") == 4
        assert sent["headers"]["Content-Type"].startswith(
            "application/x-www-form-urlencoded")

    def test_explicit_values_do_reach_the_wire(self, tmp_path, monkeypatch):
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch)
        asyncio.run(module.dashboard(page=9, sort="name", confirm=True))

        sent = calls[0]
        assert (sent.get("params") or {}).get("page") == 9
        assert (sent.get("data") or {}).get("sort") == "name"
