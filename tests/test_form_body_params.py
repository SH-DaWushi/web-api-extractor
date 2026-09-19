# -*- coding: utf-8 -*-
"""Issue #23：表单编码的 POST 请求体必须变成工具参数。

传统 OA 系统 等传统系统全靠表单编码体传参：

    POST /api/portal/dashboard/data
    section=4&companyId=2&menuIds=0%2C4

修复前 analyzer 只对能 json.loads 的请求体产出 request_schema，表单体全丢，
生成的工具签名只剩 confirm —— 能连通、能鉴权，但缺参数必然业务报错
（实测 "业务报错"）。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from webapi_extractor.analyzer import analyze_capture
from webapi_extractor.bodies import body_fields, parse_form_urlencoded
from webapi_extractor.generator import _param_decl, _render_tool
from webapi_extractor.project import session_to_registry_entries

URL = "https://oa.example.com/api/portal/dashboard/data"
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


class TestAnalyzerExtracts:
    def test_form_fields_collected(self, tmp_path):
        analysis = analyze_capture(_session(tmp_path))
        ep = analysis["endpoints"][0]
        params = ep.get("request_body_params") or {}
        assert "section" in params
        assert params["section"] == ["4"]
        assert params["companyId"] == ["2"]
        assert params["menuIds"] == ["0,4"]     # URL 解码后的值

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
            "tool_name": "dashboard", "method": "POST", "host": "oa.example.com",
            "path": "/api/portal/dashboard/data", "path_params": [],
            "query_params": {}, "sample_count": 3,
        }
        base.update(extra)
        return base

    def test_signature_exposes_body_fields(self):
        src = _render_tool(self._entry(request_body_params={"section": ["4"], "companyId": ["2"]}), "CMS")
        assert "section" in src and "companyId" in src
        assert "confirm: bool = False" in src

    def test_call_uses_form_body(self):
        src = _render_tool(self._entry(request_body_params={"section": ["4"]}), "CMS")
        assert "form_body={" in src
        assert "json_body=" not in src

    def test_no_body_kwarg_without_params(self):
        src = _render_tool(self._entry(), "CMS")
        assert "form_body=" not in src

    def test_default_gate_blocks_volatile_values(self):
        """含逗号的值不给默认（避免把抓包当时的真实数据烘进分发包）。"""
        src = _render_tool(self._entry(request_body_params={"menuIds": ["0,4"]}), "CMS")
        assert "menuIds: str | None = None" in src

    def test_identity_like_name_gets_no_default(self):
        src = _render_tool(self._entry(request_body_params={"userId": ["591"]}), "CMS")
        assert "userId: int | None = None" in src


class TestParamDeclGate:
    @pytest.mark.parametrize("ident,values,count", [
        ("section", ["4"], 3),          # 稳定短值 → 给默认
        ("menuIds", ["0,4"], 3),     # 含逗号 → 不给
        ("page", ["1"], 1),          # 单次采样 → 不给
    ])
    def test_gate(self, ident, values, count):
        decl = _param_decl(ident, "str", values, count)
        if ident == "section":
            assert "'4'" in decl
        else:
            assert decl.endswith("| None = None")


class TestTemplateSupport:
    def test_template_has_form_channel(self):
        from webapi_extractor.generator import _SERVER_TEMPLATE
        assert "form_body" in _SERVER_TEMPLATE
        assert "application/x-www-form-urlencoded" in _SERVER_TEMPLATE
