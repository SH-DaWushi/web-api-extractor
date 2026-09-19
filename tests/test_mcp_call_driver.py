# -*- coding: utf-8 -*-
"""Issue #17：mcp_call.py 的陈旧会话自动恢复必须真的能触发。

缺陷：post() 里 `r.raise_for_status()` 在解析响应体**之前**就把 HTTP 404
抛成异常，而 404 正是「陈旧会话」的信号——于是 `_is_stale_session` 永远拿不到
它，恢复分支成了死代码。后果是服务每次重启后所有调用都崩，必须手工
`rm .mcp_session`。

mcp_call.py 是仓库根目录的脚本（不在 webapi_extractor 包内），故按路径加载。
"""
from __future__ import annotations

import importlib.util
import pathlib

import httpx
import pytest


DRIVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "mcp_call.py"


@pytest.fixture(scope="module")
def driver():
    spec = importlib.util.spec_from_file_location("mcp_call_driver", DRIVER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        raise httpx.HTTPStatusError("should not be called", request=None, response=None)


class _FakeClient:
    def __init__(self, response: _FakeResponse):
        self.response = response

    def post(self, url, headers=None, json=None):
        return self.response


PAYLOAD = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "list_sessions", "arguments": {}}}


class TestPostDoesNotRaise:
    """核心回归：post() 不得对 HTTP 错误抛异常（否则恢复分支不可达）。"""

    def test_404_returns_status_instead_of_raising(self, driver):
        resp, _ = driver.post(_FakeClient(_FakeResponse(404, "Not Found")), PAYLOAD, "stale-sid")
        assert resp["http_status"] == 404

    def test_500_also_returns_status(self, driver):
        resp, _ = driver.post(_FakeClient(_FakeResponse(500, "boom")), PAYLOAD, "sid")
        assert resp["http_status"] == 500

    def test_fake_response_would_explode_if_raise_for_status_were_called(self, driver):
        """哨兵：_FakeResponse.raise_for_status 会抛——post() 调了就会被测出来。"""
        _FakeClient(_FakeResponse(404, "x"))
        with pytest.raises(httpx.HTTPStatusError):
            _FakeResponse(404, "x").raise_for_status()

    def test_success_still_parses_json(self, driver):
        body = '{"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}'
        resp, sid = driver.post(
            _FakeClient(_FakeResponse(200, body, {"mcp-session-id": "new-sid"})), PAYLOAD, None)
        assert resp["result"] == {"ok": True}
        assert sid == "new-sid"

    def test_sse_body_still_parsed(self, driver):
        body = 'event: message\ndata: {"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}\n\n'
        resp, _ = driver.post(_FakeClient(_FakeResponse(200, body)), PAYLOAD, "sid")
        assert resp["result"] == {"ok": True}


class TestStaleDetection:
    def test_404_is_stale(self, driver):
        assert driver._is_stale_session({"http_status": 404, "http_body": ""}) is True

    def test_500_is_not_stale(self, driver):
        assert driver._is_stale_session({"http_status": 500, "http_body": "boom"}) is False

    def test_500_whose_body_mentions_404_is_not_stale(self, driver):
        """状态码明确时不再靠字符串猜，否则会白重建一次会话。"""
        assert driver._is_stale_session(
            {"http_status": 500, "http_body": "upstream returned 404"}) is False

    def test_protocol_error_code_still_detected(self, driver):
        resp = {"jsonrpc": "2.0", "id": 1,
                "error": {"code": -32001, "message": "Session not found"}}
        assert driver._is_stale_session(resp) is True

    def test_normal_result_is_not_stale(self, driver):
        assert driver._is_stale_session({"result": {"ok": True}}) is False

    def test_non_dict_is_not_stale(self, driver):
        assert driver._is_stale_session(None) is False
