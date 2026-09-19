# -*- coding: utf-8 -*-
"""Issue #16：非 JSON 响应端点（页面/控件端点）的判定与生成过滤。

页面/控件端点（.axd/.aspx/.asmx/.svc 等）响应 text/html 或 302，不是 JSON
数据接口。修复前它们被生成为「调用并解析 JSON」的工具，实际调用直接
JSONDecodeError。判定按响应 Content-Type（+ 3xx 重定向），仅标记不删除。
"""
from __future__ import annotations

import pytest

from webapi_extractor.analyzer import _is_json_content_type, _non_json_response
from webapi_extractor.project import session_to_registry_entries


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
