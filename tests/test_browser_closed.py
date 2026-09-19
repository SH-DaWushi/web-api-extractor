# -*- coding: utf-8 -*-
"""Issue #13：用户关闭浏览器后自动收尾。

修复前：会话卡在 capturing、元数据不落盘、list_sessions 看不到它，
用户以为整轮采集白干（实际 capture.jsonl 逐条落盘、数据完整）。

修复后：监听 browser "disconnected"，自动 stop 并写入可读提示。
"""
from __future__ import annotations

import asyncio
import json

import pytest

from webapi_extractor.capture import CaptureSession
from webapi_extractor.storage import SessionStore


def _session(tmp_path, sid="s1", **kw) -> CaptureSession:
    store = SessionStore(tmp_path)
    s = CaptureSession(sid, "https://example.com/", store,
                       response_limit=262144, idle_timeout=300, auth_state_path=None, **kw)
    return s


def _seed_capture(s: CaptureSession, payload: str = '{"type":"request"}\n') -> None:
    s.directory.mkdir(parents=True, exist_ok=True)
    s.capture_path.write_text(payload * 10, encoding="utf-8")


class TestOnBrowserClosed:
    def test_autostop_writes_metadata(self, tmp_path):
        """核心：关浏览器后元数据必须落盘，否则 list_sessions 看不到会话。"""
        async def run():
            s = _session(tmp_path)
            s.status = "capturing"
            _seed_capture(s)
            await s._on_browser_closed()
            return s

        s = asyncio.run(run())
        meta = s.store.read_metadata("s1")
        assert meta is not None, "元数据未落盘"
        assert meta["status"] == "stopped"
        assert meta["stop_reason"] == "browser_closed"

    def test_hint_mentions_data_and_analyze(self, tmp_path):
        """提示要能让用户知道「数据还在、可以继续分析」。"""
        async def run():
            s = _session(tmp_path)
            s.status = "capturing"
            _seed_capture(s)
            await s._on_browser_closed()
            return s.store.read_metadata("s1")

        meta = asyncio.run(run())
        assert meta["recovered"] is True
        assert meta["captured_bytes"] > 0
        assert "analyze_traffic" in meta["recovered_hint"]
        assert "浏览器" in meta["recovered_hint"]

    def test_idempotent_when_already_stopped(self, tmp_path):
        """Agent 之后又调 stop_capture 不应出错，也不应覆盖原因。"""
        async def run():
            s = _session(tmp_path)
            s.status = "capturing"
            _seed_capture(s)
            await s._on_browser_closed()
            first = s.store.read_metadata("s1")
            # 再触发一次
            await s._on_browser_closed()
            second = s.store.read_metadata("s1")
            return first, second

        first, second = asyncio.run(run())
        assert second["stop_reason"] == "browser_closed"
        # 不应重复追加历史
        assert len(second.get("status_history", [])) == len(first.get("status_history", []))

    def test_no_recovered_flag_without_data(self, tmp_path):
        """无数据的会话不标 recovered，避免误导。"""
        async def run():
            s = _session(tmp_path)
            s.status = "capturing"
            s.directory.mkdir(parents=True, exist_ok=True)
            await s._on_browser_closed()
            return s.store.read_metadata("s1")

        meta = asyncio.run(run())
        assert meta["status"] == "stopped"
        assert not meta.get("recovered")
        assert meta["captured_bytes"] == 0

    def test_records_status_history(self, tmp_path):
        async def run():
            s = _session(tmp_path)
            s.status = "capturing"
            _seed_capture(s)
            await s._on_browser_closed()
            return s.store.read_metadata("s1")

        meta = asyncio.run(run())
        last = meta["status_history"][-1]
        assert last["reason"] == "browser_closed"
        assert last["status"] == "stopped"

    def test_from_authenticating_state(self, tmp_path):
        """认证阶段就关浏览器也要能收尾。"""
        async def run():
            s = _session(tmp_path)
            s.status = "authenticating"
            _seed_capture(s)
            await s._on_browser_closed()
            return s.store.read_metadata("s1")

        meta = asyncio.run(run())
        assert meta["status"] == "stopped"
        assert meta["stop_reason"] == "browser_closed"
        assert "authenticating" in meta["recovered_hint"]


class TestControlBarRemoved:
    """Issue #14：页内控制条已移除。"""

    def test_no_control_binding(self, tmp_path):
        """不应再有 __mcp_control 绑定或 control() 方法。"""
        s = _session(tmp_path)
        assert not hasattr(s, "control"), "control() 应已移除"
        assert not hasattr(s, "_broadcast_state"), "_broadcast_state() 应已移除"

    def test_control_bar_module_gone(self):
        with pytest.raises(ImportError):
            import webapi_extractor.control_bar  # noqa: F401

    def test_pause_resume_still_work(self, tmp_path):
        """移除控制条不应影响 pause/resume（空闲超时仍在用）。"""
        async def run():
            s = _session(tmp_path)
            s.status = "capturing"
            await s.pause("idle_timeout")
            p = s.status
            await s.resume()
            return p, s.status

        paused, resumed = asyncio.run(run())
        assert paused == "paused"
        assert resumed == "capturing"
