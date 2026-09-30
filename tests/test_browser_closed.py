# -*- coding: utf-8 -*-
"""Issue #13：用户关闭浏览器后自动收尾。

修复前：会话卡在 capturing、元数据不落盘、list_sessions 看不到它，
用户以为整轮采集白干（实际 capture.jsonl 逐条落盘、数据完整）。

修复后：监听 browser "disconnected"，自动 stop 并写入可读提示。
"""
from __future__ import annotations

import asyncio
import json
import time

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


class _CapturingSession:
    """建一个已经在记录的会话：目录先建好（pause 要往上写元数据）。"""

    @staticmethod
    def build(tmp_path, sid: str = "s1") -> CaptureSession:
        session = _session(tmp_path, sid=sid)
        session.status = "capturing"
        session.directory.mkdir(parents=True, exist_ok=True)
        return session


def _events_on_disk(session: CaptureSession) -> list[dict]:
    if not session.capture_path.exists():
        return []
    return [json.loads(line) for line in
            session.capture_path.read_text(encoding="utf-8").splitlines() if line.strip()]


class TestIdleTimeoutKeepsCapturedData:
    """S22：空闲超时把会话置为 paused 时，**已经抓到**的数据不得静默丢失。

    修复前 ``pause()`` 只改内存里的 status / pause_reason：

    * 写盘队列里还没落盘的事件、writer 手里那批、以及只活在内存里的未配对
      ExtraInfo，都可能随暂停/停止无声消失；
    * 元数据**完全不落盘** —— ``list_sessions`` 读到的仍是 ``capturing``，Agent
      只有在同进程里恰好调 ``get_capture_status`` 才看得到，服务一重启连
      「为什么停的」都无从得知。

    超时时长与 pause→stop 的状态语义都不改：暂停后**新**到来的流量照样不记录。
    """

    def test_pause_flushes_already_queued_events(self, tmp_path):
        async def run():
            s = _CapturingSession.build(tmp_path)
            s.event_queue.put_nowait({"type": "request", "requestId": "r1"})
            await s.pause("idle_timeout")
            return s

        s = asyncio.run(run())
        assert [e["requestId"] for e in _events_on_disk(s)] == ["r1"]
        assert s.event_queue.empty(), "队列里的数据没有被落盘"

    def test_pause_flushes_the_batch_writer_holds(self, tmp_path):
        """writer 已经取出、还没落盘的那批（原先只活在局部变量里）。"""
        async def run():
            s = _CapturingSession.build(tmp_path)
            s._batch.append({"type": "response", "requestId": "r2"})
            await s.pause("idle_timeout")
            return s

        s = asyncio.run(run())
        assert [e["requestId"] for e in _events_on_disk(s)] == ["r2"]

    def test_pause_never_writes_the_stop_sentinel_as_data(self, tmp_path):
        """stop() 的收尾哨兵不是事件，绝不能变成 capture.jsonl 里的一行。"""
        async def run():
            s = _CapturingSession.build(tmp_path)
            s.event_queue.put_nowait({"type": "request", "requestId": "r1"})
            await s.stop("agent_requested")
            return s

        s = asyncio.run(run())
        events = _events_on_disk(s)
        assert [e["type"] for e in events] == ["request"]
        assert all(e is not None for e in events)

    def test_pause_is_visible_in_metadata_and_list_sessions(self, tmp_path):
        """转换必须可见：磁盘元数据 + status_history 的 reason + 摘要提示。"""
        async def run():
            s = _CapturingSession.build(tmp_path)
            s.event_queue.put_nowait({"type": "request", "requestId": "r1"})
            await s.pause("idle_timeout")
            return s

        s = asyncio.run(run())
        meta = s.store.read_metadata("s1")
        assert meta["status"] == "paused"
        assert meta["pause_reason"] == "idle_timeout"
        assert meta["paused_at"]
        assert meta["status_history"][-1]["status"] == "paused"
        assert meta["status_history"][-1]["reason"] == "idle_timeout"
        assert meta["captured_bytes"] > 0
        # list_sessions 读的是磁盘：修复前它仍然报 capturing
        assert [m["status"] for m in s.store.list_sessions()] == ["paused"]
        # get_capture_status 走的是 metadata()：原因与「数据还在」都要看得见
        summary = s.metadata()
        assert summary["pause_reason"] == "idle_timeout"
        assert summary["captured_bytes"] == meta["captured_bytes"]
        assert "analyze_traffic" in summary["pause_hint"]
        assert "没有丢失" in summary["pause_hint"]

    def test_metadata_of_a_pause_keeps_what_start_capture_wrote(self, tmp_path):
        """暂停写元数据必须是**合并**：start_capture 写的字段不能被抹掉。"""
        async def run():
            s = _CapturingSession.build(tmp_path)
            s.store.write_metadata("s1", {
                "session_id": "s1", "url": s.url, "status": "capturing",
                "created_at": "2026-01-01T00:00:00+00:00",
                "requested_session_id": "my session",
                "status_history": [{"status": "capturing",
                                    "ts": "2026-01-01T00:00:00+00:00",
                                    "reason": "started"}],
            })
            await s.pause("idle_timeout")
            return s.store.read_metadata("s1")

        meta = asyncio.run(run())
        assert meta["created_at"] == "2026-01-01T00:00:00+00:00"
        assert meta["requested_session_id"] == "my session"
        assert [h["reason"] for h in meta["status_history"]] == ["started", "idle_timeout"]

    def test_in_flight_response_body_survives_a_pause_mid_await(self, tmp_path):
        """handler 在暂停**之前**已进入、body 已经抓回来：不能因为暂停就丢。

        ``on_finished`` 在 ``Network.getResponseBody`` 上等待时超时触发；等它回来
        时状态已经是 paused。修复前 ``emit`` 按 status 直接丢弃这条 response_body，
        抓回来的响应体就这么无声消失。
        """
        async def run():
            s = _CapturingSession.build(tmp_path)

            class PausingCDP:
                async def send(self, method, params):
                    await s.pause("idle_timeout")      # 超时恰好在 await 期间触发
                    return {"body": '{"ok":true}', "base64Encoded": False}

            await s.on_finished({"requestId": "r7"}, PausingCDP())
            await s.stop("agent_requested")
            return s

        s = asyncio.run(run())
        bodies = [e for e in _events_on_disk(s) if e["type"] == "response_body"]
        assert [e["body"] for e in bodies] == ['{"ok":true}']

    def test_paused_session_still_ignores_new_traffic(self, tmp_path):
        """暂停语义不变：暂停之后**新**到来的事件仍然不记录。"""
        async def run():
            s = _CapturingSession.build(tmp_path)
            await s.pause("idle_timeout")
            await s.on_request({
                "requestId": "r9", "type": "XHR",
                "request": {"url": "https://example.com/api", "method": "GET", "headers": {}}},
                None)
            await s.on_response({"requestId": "r9", "response": {"status": 200}}, None)
            await s.on_finished({"requestId": "r9"}, None)
            await s.on_loading_failed({"requestId": "r9"})
            await s.on_websocket_created({"requestId": "r9"})
            return s

        s = asyncio.run(run())
        assert s.event_queue.empty()
        assert _events_on_disk(s) == []

    def test_idle_monitor_pauses_and_persists_the_data(self, tmp_path):
        """端到端：空闲超时触发 → 已抓到的数据落盘 + 原因写进元数据。"""
        async def run():
            s = _CapturingSession.build(tmp_path)
            s.idle_timeout = 1          # 只改本对象（全局超时时长由 Settings 决定）
            s.last_activity = time.monotonic() - 600
            s.event_queue.put_nowait({"type": "request", "requestId": "r1"})
            task = asyncio.create_task(s._idle_monitor())
            for _ in range(80):
                await asyncio.sleep(0.05)
                if s.status == "paused":
                    break
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return s

        s = asyncio.run(run())
        assert s.status == "paused"
        assert s.pause_reason == "idle_timeout"
        assert [e["requestId"] for e in _events_on_disk(s)] == ["r1"]
        meta = s.store.read_metadata("s1")
        assert meta["pause_reason"] == "idle_timeout"
        assert meta["status_history"][-1]["reason"] == "idle_timeout"
