# -*- coding: utf-8 -*-
"""Issue #1 回归测试：CDP requestWillBeSentExtraInfo 的合并与配对。

用模拟事件覆盖两种到达顺序（ExtraInfo 先到 / 后到），
断言合并后的 request 记录含 Cookie（且已脱敏为 ``name=***``）。
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webapi_extractor.capture import CaptureSession  # noqa: E402
from webapi_extractor.storage import SessionStore  # noqa: E402


class FakeCDP:
    async def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"body": '{"ok":true}', "base64Encoded": False}


def make_session(tmp_path: Path) -> CaptureSession:
    store = SessionStore(tmp_path)
    session = CaptureSession("s1", "https://example.com/", store, 256 * 1024, 300)
    session.status = "capturing"
    session.directory.mkdir(parents=True, exist_ok=True)
    return session


def drain(session: CaptureSession) -> list[dict[str, Any]]:
    out = []
    while not session.event_queue.empty():
        out.append(session.event_queue.get_nowait())
    return out


def _will_be_sent(request_id: str) -> dict[str, Any]:
    # M117+ 的 requestWillBeSent 里不再有 Cookie；只有部分头。
    return {"requestId": request_id, "type": "XHR",
            "request": {"url": "https://example.com/api/list",
                        "method": "GET",
                        "headers": {"Accept": "application/json", "User-Agent": "UA"}}}


def _extra_info(request_id: str) -> dict[str, Any]:
    return {"requestId": request_id,
            "headers": {"Cookie": "sid=abc123; csrftoken=zzz",
                        "Accept": "application/json",
                        "Sec-Fetch-Site": "same-origin",
                        "User-Agent": "UA"}}


def test_extra_info_before_request(tmp_path: Path) -> None:
    """正常顺序：ExtraInfo 先到 → 暂存，requestWillBeSent 到达时合并。"""
    async def run() -> None:
        session = make_session(tmp_path)
        cdp = FakeCDP()
        await session.on_request_extra_info(_extra_info("r1"), cdp)
        # 尚未配对：暂存在缓存里，不应泄漏成事件。
        assert "r1" in session.pending_extra
        assert drain(session) == []
        await session.on_request(_will_be_sent("r1"), cdp)
        events = drain(session)
        record = events[0]
        assert record["type"] == "request"
        headers = record["headers"]
        # Cookie 被脱敏为 name=***，analyzer 据此提取 cookie_names。
        assert headers.get("Cookie") == "sid=***; csrftoken=***", headers
        assert headers.get("Sec-Fetch-Site") == "same-origin"
        assert "r1" not in session.pending_extra, "配对后必须清理暂存缓存"
    asyncio.run(run())


def test_extra_info_after_request(tmp_path: Path) -> None:
    """乱序：ExtraInfo 后到 → 原地补丁已发出的记录 + 补发 headers_patch 事件。"""
    async def run() -> None:
        session = make_session(tmp_path)
        cdp = FakeCDP()
        await session.on_request(_will_be_sent("r2"), cdp)
        first = drain(session)[0]
        assert "Cookie" not in first["headers"]
        await session.on_request_extra_info(_extra_info("r2"), cdp)
        # 已入队（writer 持有同一对象引用）的记录被原地修正。
        assert first["headers"].get("Cookie") == "sid=***; csrftoken=***", first["headers"]
        patch = [e for e in drain(session) if e["type"] == "headers_patch"]
        assert len(patch) == 1 and patch[0]["requestId"] == "r2"
    asyncio.run(run())


def test_no_extra_info_still_works(tmp_path: Path) -> None:
    """ExtraInfo 从未到达（或站点无需 Cookie）时不应报错，也不产生空补丁事件。"""
    async def run() -> None:
        session = make_session(tmp_path)
        cdp = FakeCDP()
        await session.on_request(_will_be_sent("r3"), cdp)
        assert drain(session)[0]["headers"].get("Cookie") is None
        assert session.emitted_requests  # 等待配对
    asyncio.run(run())


def test_caches_cleaned_on_finish(tmp_path: Path) -> None:
    """请求完成后清理配对缓存，避免长会话内存泄漏。"""
    async def run() -> None:
        session = make_session(tmp_path)
        cdp = FakeCDP()
        await session.on_request_extra_info(_extra_info("r4"), cdp)
        await session.on_request(_will_be_sent("r4"), cdp)
        assert session.emitted_requests and not session.pending_extra
        await session.on_finished({"requestId": "r4"}, cdp)
        assert "r4" not in session.emitted_requests
        assert "r4" not in session.pending_extra
    asyncio.run(run())


def test_pending_extra_pruned(tmp_path: Path) -> None:
    """永远等不到 requestWillBeSent 的 ExtraInfo 会被 TTL 清理。"""
    async def run() -> None:
        session = make_session(tmp_path)
        cdp = FakeCDP()
        await session.on_request_extra_info(_extra_info("orphan"), cdp)
        session.pending_extra["orphan"] = (session.pending_extra["orphan"][0] - 10_000, {})
        session._prune_pending_extra()
        assert session.pending_extra == {}
    asyncio.run(run())
