# -*- coding: utf-8 -*-
"""Issue #19：非 JSON 判定必须同时看响应体，而非只看 Content-Type。

大量 Java / 遗留系统用 `Content-Type: text/plain` 返回 **JSON 体**。
只看响应头会把这类站点的接口整体误杀。本问题是 #16 的修复引入的回归（粒度过粗）。
"""
from __future__ import annotations

import pytest

from webapi_extractor.analyzer import _looks_like_json_body, _non_json_response
from webapi_extractor.project import session_to_registry_entries


def _resp(content_type: str | None = None, status: int | None = 200) -> dict:
    return {"headers": {"Content-Type": content_type} if content_type else {}, "status": status}


JSON_BODY = '{"items":[{"type":"account","name":"username"}]}'


class TestLooksLikeJsonBody:
    @pytest.mark.parametrize("raw,expected", [
        (JSON_BODY, True),
        ("  [1,2,3]  ", True),
        ("<html>no</html>", False),
        ("webpackJsonpApp([16],{})", False),
        ('{"broken": ', False),          # 首字符像 JSON 但解析失败
        ("", False),
        (None, False),
    ])
    def test_detection(self, raw, expected):
        assert _looks_like_json_body(raw) is expected


class TestNonJsonResponse:
    def test_text_plain_with_json_body_is_data_endpoint(self):
        """核心场景：头说 text/plain，体是 JSON。"""
        assert _non_json_response([_resp("text/plain; charset=utf-8")], [JSON_BODY]) is False

    def test_text_plain_with_js_bundle_still_non_json(self):
        """头是 text/plain 且体是 JS 打包产物 —— 仍应判为非 JSON。"""
        assert _non_json_response([_resp("text/plain")], ["webpackJsonp([1],{})"]) is True

    def test_html_page_endpoint_is_non_json(self):
        """#16 的原始场景：.axd 返回 HTML —— 不能因本次修复而失效。"""
        assert _non_json_response([_resp("text/html")], ["<html><head><title>Object moved"]) is True

    def test_redirect_is_non_json(self):
        assert _non_json_response([_resp(None, 302)], [""]) is True

    def test_json_content_type_is_not_non_json(self):
        assert _non_json_response([_resp("application/json")], [JSON_BODY]) is False

    def test_no_evidence_is_not_non_json(self):
        assert _non_json_response([{"headers": {}, "status": None}], [None]) is False

    def test_json_body_without_content_type_is_data_endpoint(self):
        assert _non_json_response([{"headers": {}, "status": 200}], [JSON_BODY]) is False


class TestRegistryKeepsSuchEndpoints:
    def test_text_plain_json_endpoint_is_generated(self):
        analysis = {
            "endpoints": [{
                "method": "POST", "host": "portal.example.com",
                "path": "/api/portal/dashboard/data",
                "query_params": {}, "sample_count": 2,
                "url": "https://portal.example.com/api/portal/dashboard/data",
                "non_json_response": False,   # 修复后应为 False
            }],
            "auth_metadata": {"auth_schemes": {}},
        }
        entries, _ = session_to_registry_entries(analysis, "s1")
        assert len(entries) == 1
