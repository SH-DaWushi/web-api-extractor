# -*- coding: utf-8 -*-
"""Issue #1 回归测试：CDP requestWillBeSentExtraInfo 的合并与配对。

用模拟事件覆盖两种到达顺序（ExtraInfo 先到 / 后到），
断言合并后的 request 记录含 Cookie（且已脱敏为 ``name=***``）。
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import time
import types
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webapi_extractor import capture as capture_module  # noqa: E402
from webapi_extractor.analyzer import (  # noqa: E402
    _index_capture,
    _merge_headers,
    analyze_capture,
)
from webapi_extractor.capture import (  # noqa: E402
    _EMITTED_REQUEST_TTL,
    _MAX_EMITTED_REQUESTS,
    CaptureSession,
    _frame_key,
)
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


def test_unpaired_extra_is_flushed_on_pause_and_pairing_is_kept(tmp_path: Path) -> None:
    """S22：等不到配对的 ExtraInfo 也是「已经抓到的数据」，暂停时必须落盘。

    它只活在内存字典 ``pending_extra`` 里：``pause`` / ``stop`` 之后若无这一步，
    这坨真抓回来的 Cookie / Sec-* 头就随会话无声消失（配对永远等不到）。
    同时**配对缓存必须保留**——恢复后晚到的 requestWillBeSent 仍要能拿到这些头。
    """
    async def run() -> CaptureSession:
        session = make_session(tmp_path)
        await session.on_request_extra_info(_extra_info("orphan"), FakeCDP())
        assert "orphan" in session.pending_extra
        await session.pause("idle_timeout")
        await session.resume()
        await session.pause("idle_timeout")      # 第二次暂停不得重复写
        return session

    session = asyncio.run(run())
    lines = session.capture_path.read_text(encoding="utf-8").splitlines()
    flushed = [json.loads(line) for line in lines
               if json.loads(line)["type"] == "request_extra_info_unpaired"]
    assert [e["requestId"] for e in flushed] == ["orphan"], "未配对头必须落盘且只落一次"
    assert flushed[0]["reason"] == "idle_timeout"
    assert flushed[0]["headers"].get("Cookie"), "真抓到的 Cookie 头不能丢"
    assert flushed[0]["headers"]["Cookie"] == "sid=***; csrftoken=***", "落盘也要脱敏"
    assert "orphan" in session.pending_extra, "配对缓存被清掉了：恢复后晚到的请求配不上头"


def test_unpaired_extra_is_flushed_on_stop(tmp_path: Path) -> None:
    """会话直接结束（不经过暂停）时，未配对的头也必须落盘。"""
    async def run() -> CaptureSession:
        session = make_session(tmp_path)
        await session.on_request_extra_info(_extra_info("orphan2"), FakeCDP())
        await session.stop("agent_requested")
        return session

    session = asyncio.run(run())
    events = [json.loads(line) for line in
              session.capture_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(e["type"] == "request_extra_info_unpaired" and e["requestId"] == "orphan2"
               for e in events)


# --------------------------------------------------------------------------- #
# Defect B（analyzer 侧）：晚到的 headers_patch 必须折进被分析的 request
#
# capture.py 在 ExtraInfo 晚到时补发一条 ``headers_patch``：请求行**已经落盘**之后
# 才到达的 Cookie / Sec-* 只能靠它补上。但 analyzer 此前只认
# request / response / response_body，这条补丁被整个忽略 —— 落盘的 request 记录
# 永远缺 Cookie，auth_required / auth_schemes 因此判错，生成的工具不带鉴权
# （实测每个工具都 401）。下面把「合并规则」与「分析结果」两段各钉一次。
# --------------------------------------------------------------------------- #
def _write_capture(session_dir: Path, events: list[dict[str, Any]]) -> Path:
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "capture.jsonl").write_text(
        "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    return session_dir


def _listed_capture(patch: dict[str, Any] | None) -> list[dict[str, Any]]:
    """一次普通 XHR 抓包；``patch`` 非空时在 request 之后补一条 headers_patch。"""
    events: list[dict[str, Any]] = [
        {"type": "request", "requestId": "r1", "url": "https://example.com/api/list",
         "method": "GET", "resourceType": "XHR",
         # 与 M117+ 落盘形态一致：requestWillBeSent 里没有 Cookie。
         "headers": {"Accept": "application/json", "User-Agent": "UA"}},
    ]
    if patch is not None:
        events.append({"type": "headers_patch", "requestId": "r1", "headers": patch,
                       "reason": "requestWillBeSentExtraInfo_late"})
    events += [
        {"type": "response", "requestId": "r1", "status": 200,
         "headers": {"Content-Type": "application/json"}},
        {"type": "response_body", "requestId": "r1", "body": "{}", "size": 2},
    ]
    return events


def test_header_merge_keeps_headers_the_patch_does_not_carry() -> None:
    merged = _merge_headers({"Accept": "application/json", "X-Trace": "t1"},
                            {"Cookie": "sid=***"})
    assert merged == {"Accept": "application/json", "X-Trace": "t1", "Cookie": "sid=***"}


def test_header_merge_is_case_insensitive_and_the_patch_wins() -> None:
    """补丁是更晚、更权威的一批头：同名头以它为准，大小写不敏感。"""
    assert _merge_headers({"User-Agent": "old", "X-A": "1"}, {"user-agent": "new"}) == \
        {"user-agent": "new", "X-A": "1"}


def test_late_patch_reaches_the_analysed_request(tmp_path: Path) -> None:
    """核心回归：落盘后才到的 Cookie 必须出现在被分析的 request 头上。"""
    session = _write_capture(tmp_path / "cap", _listed_capture(
        {"Accept": "application/json", "Cookie": "sid=***", "User-Agent": "UA"}))

    headers = _index_capture(session / "capture.jsonl").requests[("r1", 0)]["headers"]

    assert headers["Cookie"] == "sid=***", "补丁没折进来 → 分析的请求永远缺 Cookie"
    assert headers["Accept"] == "application/json", "补丁没带的头一个都不能丢"


def test_patched_cookie_makes_the_endpoint_require_auth(tmp_path: Path) -> None:
    analysis = analyze_capture(_write_capture(tmp_path / "cap", _listed_capture(
        {"Cookie": "sid=***", "User-Agent": "UA"})))

    endpoint = analysis["endpoints"][0]
    assert endpoint["auth_required"] is True
    assert analysis["auth_metadata"]["auth_schemes"]["example.com"]["cookie_names"] == ["sid"]


def test_same_capture_without_the_patch_is_unauthenticated(tmp_path: Path) -> None:
    """对照组：没有补丁时维持原判——证明上面那条断言确实由 headers_patch 驱动。"""
    analysis = analyze_capture(_write_capture(tmp_path / "cap", _listed_capture(None)))

    assert analysis["endpoints"][0]["auth_required"] is False
    assert analysis["auth_metadata"]["auth_schemes"]["example.com"]["cookie_names"] == []


def test_request_meta_is_cleaned_on_finish(tmp_path: Path) -> None:
    """request_meta 此前**从不清理**：两小时 5 万请求就是 5 万条常驻字典。"""
    async def run() -> None:
        session = make_session(tmp_path)
        await session.on_request(_will_be_sent("r1"), FakeCDP())
        assert "r1" in session.request_meta
        await session.on_finished({"requestId": "r1"}, FakeCDP())
        assert "r1" not in session.request_meta
        assert "r1" not in session.emitted_requests
    asyncio.run(run())


def test_writer_isolates_a_write_failure(tmp_path: Path) -> None:
    """写盘失败必须被隔离，而不是杀掉 writer 任务。

    修复前没有 try：一次 OSError（磁盘满）就让本任务死掉，而 ``stop()`` 会
    ``await writer_task`` 把异常抛回调用方 —— 会话永久卡在 stopping，浏览器与
    node 驱动再也关不掉，且后续事件在内存里无界堆积。
    """
    from unittest import mock

    async def run() -> None:
        session = make_session(tmp_path)
        session.event_queue.put_nowait({"type": "request", "requestId": "r9"})
        session.event_queue.put_nowait(None)
        with mock.patch.object(Path, "open", side_effect=OSError("disk full")):
            await asyncio.wait_for(session._writer(), timeout=10)
        assert session.status == "failed"
        assert "disk full" in (session.write_error or "")
        assert session.event_queue.empty()
        assert "write_error" in session.metadata()
    asyncio.run(run())


# --------------------------------------------------------------------------- #
# Fix 2：emitted_requests 也必须是有界缓存
#
# 此前它**只在 on_finished 的 finally 里清理**。被中止 / 永不结束的请求（用户取消、
# 中途导航、页面关闭）不会触发 loadingFinished，那条记录（头 + 已脱敏的体）就一直
# 驻留到会话结束 —— 这是本文件最后一份无界 dict。修法是**复用 pending_extra 的同一套
# 机制**（TTL + 硬容量 + 在同一批路径上 prune），不另造一套。
#
# TTL 取 600 秒（10 分钟）：实测正常 XHR 从 requestWillBeSent 到 loadingFinished 通常
# 在 30 秒内，慢上传/大下载也就几分钟 —— 600 秒比最长真实请求还长一个数量级，
# 正常流程的记录绝不会在 on_finished 之前被回收。
# --------------------------------------------------------------------------- #
def _age(session: CaptureSession, request_id: str, seconds: float) -> None:
    """把某条已发记录的「发出时刻」往前拨，模拟早就发出、此后再无事件的请求。"""
    timestamp, record = session.emitted_requests[request_id]
    session.emitted_requests[request_id] = (timestamp - seconds, record)


def test_emitted_request_stale_record_is_pruned(tmp_path: Path) -> None:
    """(a) 过期记录被 TTL 回收（被中止的请求永远不会走到 on_finished）。"""
    async def run() -> None:
        session = make_session(tmp_path)
        await session.on_request(_will_be_sent("old"), FakeCDP())
        assert "old" in session.emitted_requests

        _age(session, "old", _EMITTED_REQUEST_TTL + 1)
        session._prune_emitted_requests()

        assert session.emitted_requests == {}
    asyncio.run(run())


def test_emitted_request_fresh_record_survives(tmp_path: Path) -> None:
    """(b) 新记录必须活着——prune 不能把正常流程要用的记录提前收走。"""
    async def run() -> None:
        session = make_session(tmp_path)
        await session.on_request(_will_be_sent("r1"), FakeCDP())

        session._prune_emitted_requests()
        assert "r1" in session.emitted_requests

        # 仍然能被晚到的 ExtraInfo 原地补丁（TTL 不影响正常路径）
        await session.on_request_extra_info(_extra_info("r1"), FakeCDP())
        assert session.emitted_requests["r1"][1]["headers"]["Cookie"] == "sid=***; csrftoken=***"
    asyncio.run(run())


def test_prune_is_wired_into_the_normal_event_paths(tmp_path: Path) -> None:
    """prune 必须挂在 on_request / on_request_extra_info 上（与 pending_extra 同路径）。

    只提供一个可以手动调用的 `_prune_*` 是不够的：被中止的请求此后再也不会有事件
    到达，能触发回收的只有「下一个请求」或「下一条无处配对的 ExtraInfo」。
    """
    async def run() -> None:
        session = make_session(tmp_path)
        await session.on_request(_will_be_sent("stale"), FakeCDP())
        _age(session, "stale", _EMITTED_REQUEST_TTL + 1)

        # 下一个 requestWillBeSent 到达时应当顺手回收
        await session.on_request(_will_be_sent("fresh"), FakeCDP())
        assert "stale" not in session.emitted_requests
        assert "fresh" in session.emitted_requests

        # 无处配对的 ExtraInfo 同样是一条回收路径
        _age(session, "fresh", _EMITTED_REQUEST_TTL + 1)
        await session.on_request_extra_info(_extra_info("never-seen"), FakeCDP())
        assert "fresh" not in session.emitted_requests
        assert "never-seen" in session.pending_extra
    asyncio.run(run())


def test_emitted_requests_is_bounded_by_capacity(tmp_path: Path) -> None:
    """硬容量兜底：即使 TTL 还没到，也不能无界增长（FIFO 丢最旧的）。"""
    async def run() -> None:
        session = make_session(tmp_path)
        now = time.monotonic()
        for index in range(_MAX_EMITTED_REQUESTS + 10):
            session.emitted_requests[f"r{index}"] = (now, {"type": "request"})

        session._prune_emitted_requests()

        assert len(session.emitted_requests) == _MAX_EMITTED_REQUESTS
        assert "r0" not in session.emitted_requests                 # 最旧的先丢
        assert f"r{_MAX_EMITTED_REQUESTS + 9}" in session.emitted_requests
    asyncio.run(run())


def test_ttl_outlasts_a_realistic_request_lifetime() -> None:
    """TTL 的取值本身也要守住：明显长于真实请求寿命，正常流程才不会被误伤。

    实测正常 XHR 从 requestWillBeSent 到 loadingFinished 通常在 30 秒内，
    慢上传/大下载也就几分钟。
    """
    assert _EMITTED_REQUEST_TTL >= 300, "TTL 太短，会在 on_finished 之前收走正常请求"
    assert _MAX_EMITTED_REQUESTS >= 256, "容量太小，正常并发下会被误回收"


def test_finished_still_clears_everything(tmp_path: Path) -> None:
    """正常结束仍由 on_finished 兜底清理（与 TTL 回收互补，两者都要在）。"""
    async def run() -> None:
        session = make_session(tmp_path)
        await session.on_request(_will_be_sent("r7"), FakeCDP())
        assert "r7" in session.emitted_requests

        await session.on_finished({"requestId": "r7"}, FakeCDP())

        assert session.emitted_requests == {}
    asyncio.run(run())


# --------------------------------------------------------------------------- #
# S21：OOPIF 子会话、WebSocket 帧，以及**会话维度的 requestId 隔离**
#
# 真机（Chromium，--site-per-process，跨站 iframe）实测到的三件事，下面逐条钉住：
#
# 1. 跨进程 iframe 内部发起的请求**不会**出现在主页面会话里：
#    Target.setAutoAttach 只让我们看到 Target.attachedToTarget 本身，子会话事件
#    被 Playwright 静默丢掉（CRConnection 按 sessionId 派发，未登记的会话丢弃）。
#    修法是对 OOPIF frame 单独 new_cdp_session；
# 2. CDP 的 requestId **只在各自会话里唯一**：主会话与每个 OOPIF 各有一套编号，
#    混用会让 ExtraInfo 配对、headers_patch、response_body 彼此串数据；
# 3. webSocketFrameSent/Received 会到达页面会话，但此前从未订阅 → 帧内容全丢。
#
# 这里的 CDP 是假的（没有真浏览器）；真机实测记录见交付报告。
# 本节的辅助名字统一带 sub_/Sub 前缀，避免与文件上半部分的同名夹具冲突。
# --------------------------------------------------------------------------- #
class SubSessionCDP:
    """记录 send 与 on 的假 CDP 会话。"""

    def __init__(self, body: str = '{"ok":true}') -> None:
        self.sent: list[str] = []
        self.handlers: dict[str, list[Any]] = {}
        self.body = body

    async def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.sent.append(method)
        if method == "Network.getResponseBody":
            return {"body": self.body, "base64Encoded": False}
        return {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers.setdefault(event, []).append(handler)

    def fire(self, event: str, payload: dict[str, Any]) -> None:
        for handler in self.handlers.get(event, []):
            handler(payload)


class SubFrame:
    def __init__(self, guid: str, url: str = "http://inner.test/i.html",
                 page: Any = None) -> None:
        self._impl_obj = types.SimpleNamespace(_guid=guid)
        self.url = url
        self.page = page


class SubPage:
    def __init__(self, main_frame: SubFrame) -> None:
        self.main_frame = main_frame
        self.handlers: dict[str, list[Any]] = {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers.setdefault(event, []).append(handler)


class _NoSeparateSession(Exception):
    pass


class SubContext:
    """只对列在 ``oopif_guids`` 里的 frame 建会话，其余（同进程 iframe）抛错。

    ``fail_first`` 用来模拟 frameattached 时序：iframe 当时还在父进程里，挂不上。
    """

    def __init__(self, oopif_guids: set[str] | None = None, fail_first: int = 0) -> None:
        self.oopif_guids = oopif_guids or set()
        self.fail_first = fail_first
        self.calls: list[str] = []
        self.sessions: list[SubSessionCDP] = []

    async def new_cdp_session(self, frame: Any) -> SubSessionCDP:
        key = _frame_key(frame)
        self.calls.append(key)
        # 真实调用是一次跨进程往返，必然让出事件循环——夹具也照做，否则并发路径
        # （frameattached 与 framenavigated 同时来）在测试里根本不会交错。
        await asyncio.sleep(0)
        if self.fail_first > 0:
            self.fail_first -= 1
            raise _NoSeparateSession("This frame does not have a separate CDP session")
        if key not in self.oopif_guids:
            raise _NoSeparateSession("This frame does not have a separate CDP session")
        session = SubSessionCDP()
        self.sessions.append(session)
        return session


def make_sub_session(tmp_path: Path, limit: int = 256 * 1024) -> CaptureSession:
    store = SessionStore(tmp_path)
    session = CaptureSession("s1", "https://example.com/", store, limit, 300)
    session.status = "capturing"
    session.directory.mkdir(parents=True, exist_ok=True)
    return session


def drain_sub(session: CaptureSession) -> list[dict[str, Any]]:
    out = []
    while not session.event_queue.empty():
        out.append(session.event_queue.get_nowait())
    return out


def _sub_will_be_sent(request_id: str, url: str = "https://example.com/api/list") -> dict[str, Any]:
    return {"requestId": request_id, "type": "XHR",
            "request": {"url": url, "method": "GET", "headers": {"Accept": "application/json"}}}


def _sub_extra_info(request_id: str, cookie: str = "sid=abc123") -> dict[str, Any]:
    return {"requestId": request_id, "headers": {"Cookie": cookie}}


def _register_sub_cdp(session: CaptureSession, tag: str = "sub1",
                          frame_url: str = "http://inner.test/i.html") -> SubSessionCDP:
    """模拟 attach_frame_if_needed 成功之后的状态。"""
    cdp = SubSessionCDP()
    session.cdp_meta[cdp] = {"tag": tag, "kind": "frame",
                             "target": {"kind": "frame", "frame": f"frame@{tag}",
                                        "url": frame_url}}
    return cdp


# --------------------------------------------------------------------------- #
# 1. 会话维度的 requestId
# --------------------------------------------------------------------------- #
def test_main_session_request_id_is_untouched(tmp_path: Path) -> None:
    """主页面会话的 tag 是空串 → 落盘 requestId 与修复前逐字节一致。"""
    async def run() -> list[dict[str, Any]]:
        session = make_sub_session(tmp_path)
        page_cdp = _register_sub_cdp(session, tag="")
        await session.on_request(_sub_will_be_sent("41100.2"), page_cdp)
        return drain_sub(session)

    events = asyncio.run(run())
    assert events[0]["requestId"] == "41100.2"
    assert "cdp_session" not in events[0] and "source_target" not in events[0]


def test_sub_session_request_id_is_prefixed_and_tagged(tmp_path: Path) -> None:
    """子会话（OOPIF）的事件带前缀，并记下来源 target/frame。"""
    async def run() -> list[dict[str, Any]]:
        session = make_sub_session(tmp_path)
        sub = _register_sub_cdp(session)
        await session.on_request(_sub_will_be_sent("1", "http://inner.test/api/inner"), sub)
        return drain_sub(session)

    record = asyncio.run(run())[0]
    assert record["requestId"] == "sub1:1", "子会话必须有会话维度前缀"
    assert record["cdp_session"] == "sub1"
    assert record["source_target"] == {"kind": "frame", "frame": "frame@sub1",
                                       "url": "http://inner.test/i.html"}


def test_same_request_id_on_two_sessions_does_not_cross(tmp_path: Path) -> None:
    """**本次最大的风险点**：两个会话出现同一个 requestId 时不得串数据。

    主会话与 OOPIF 子会话各有一套编号（真机实测：互不知情）。若不隔离：
      * 子会话的 ExtraInfo（Cookie 的权威来源）会被配到主会话的同名 request 上；
      * 子会话的响应体会挂到主会话的记录上（analyzer 随后按 requestId 配对）。
    """
    async def run() -> dict[str, Any]:
        session = make_sub_session(tmp_path)
        page_cdp = _register_sub_cdp(session, tag="")
        sub = _register_sub_cdp(session)
        # 子会话先到 ExtraInfo（真实时序：ExtraInfo 通常早于 requestWillBeSent）。
        await session.on_request_extra_info(_sub_extra_info("1", "sub_cookie=secret"), sub)
        await session.on_request(_sub_will_be_sent("1", "https://example.com/api/main"), page_cdp)
        main_record = drain_sub(session)[0]
        # 记录会被晚到的补丁**原地**改写，所以这里立刻快照。
        main_cookie = dict(main_record["headers"]).get("Cookie")
        await session.on_request(_sub_will_be_sent("1", "http://inner.test/api/inner"), sub)
        sub_record = drain_sub(session)[0]
        sub_cookie = dict(sub_record["headers"]).get("Cookie")
        # 子会话后到的 ExtraInfo 必须补到子会话那条上，而不是主会话那条。
        await session.on_request_extra_info(_sub_extra_info("1", "late=1"), sub)
        patch = [e for e in drain_sub(session) if e["type"] == "headers_patch"]
        await session.on_finished({"requestId": "1"}, sub)
        body = [e for e in drain_sub(session) if e["type"] == "response_body"][0]
        return {"main_id": main_record["requestId"], "sub_id": sub_record["requestId"],
                "main_cookie": main_cookie, "sub_cookie": sub_cookie,
                "patch": patch, "body": body, "session": session}

    result = asyncio.run(run())
    assert result["main_id"] == "1"
    assert result["sub_id"] == "sub1:1"
    assert result["main_cookie"] is None, "子会话的 Cookie 串到主会话的 request 上了"
    assert result["sub_cookie"] == "sub_cookie=***"
    assert len(result["patch"]) == 1 and result["patch"][0]["requestId"] == "sub1:1", \
        "补丁必须打回子会话的键"
    assert result["body"]["requestId"] == "sub1:1"
    # 主会话那条记录仍在等待自己的配对，没有被子会话的 on_finished 顺手清掉。
    assert "1" in result["session"].emitted_requests
    assert "sub1:1" not in result["session"].emitted_requests


def test_sub_session_response_body_pairs_with_its_own_request(tmp_path: Path) -> None:
    """响应体走子会话的 Network.getResponseBody，键也用子会话前缀。"""
    async def run() -> tuple[list[dict[str, Any]], SubSessionCDP]:
        session = make_sub_session(tmp_path)
        sub = _register_sub_cdp(session)
        await session.on_request(_sub_will_be_sent("7"), sub)
        drain_sub(session)
        await session.on_finished({"requestId": "7"}, sub)
        return drain_sub(session), sub

    events, sub = asyncio.run(run())
    assert events[0]["type"] == "response_body" and events[0]["requestId"] == "sub1:7"
    assert events[0]["cdp_session"] == "sub1"
    assert "Network.getResponseBody" in sub.sent


# --------------------------------------------------------------------------- #
# 2. OOPIF 挂载
# --------------------------------------------------------------------------- #
def test_attach_frame_skips_main_frame(tmp_path: Path) -> None:
    async def run() -> SubContext:
        session = make_sub_session(tmp_path)
        main = SubFrame("frame@main", url="https://example.com/")
        page = SubPage(main)
        main.page = page
        context = SubContext(oopif_guids={"frame@main"})
        session.context = context

        await session.attach_frame_if_needed(main)
        await session.attach_frame_if_needed(main, retry=True)
        return context

    context = asyncio.run(run())
    assert context.calls == [], "主框架已由页面会话覆盖，不能再挂一个（会记两遍）"


def test_attach_frame_ignores_in_process_iframe(tmp_path: Path) -> None:
    """同进程 iframe：new_cdp_session 抛错 → 静默跳过（父会话已覆盖），不抛异常。"""
    async def run() -> tuple[SubContext, CaptureSession]:
        session = make_sub_session(tmp_path)
        main = SubFrame("frame@main")
        page = SubPage(main)
        main.page = page
        frame = SubFrame("frame@same", url="https://example.com/same.html", page=page)
        context = SubContext(oopif_guids=set())
        session.context = context
        await session.attach_frame_if_needed(frame)
        return context, session

    context, session = asyncio.run(run())
    assert context.calls == ["frame@same"]
    assert session.attached_frames == set()
    assert session.cdp_meta == {}


def test_attach_frame_wires_oopif_session_into_the_same_handlers(tmp_path: Path) -> None:
    """OOPIF 有独立会话：Network.enable + 订阅全套网络事件，事件带前缀。"""
    async def run() -> tuple[CaptureSession, SubSessionCDP]:
        session = make_sub_session(tmp_path)
        main = SubFrame("frame@main")
        page = SubPage(main)
        main.page = page
        frame = SubFrame("frame@oopif", url="http://inner.test/i.html", page=page)
        context = SubContext(oopif_guids={"frame@oopif"})
        session.context = context
        await session.attach_frame_if_needed(frame)
        return session, context.sessions[0]

    session, sub = asyncio.run(run())
    assert "Network.enable" in sub.sent
    assert "Network.setCacheDisabled" in sub.sent
    for event in ("Network.requestWillBeSent", "Network.requestWillBeSentExtraInfo",
                  "Network.responseReceived", "Network.loadingFinished",
                  "Network.webSocketFrameSent", "Network.webSocketFrameReceived"):
        assert event in sub.handlers, f"子会话没订阅 {event}"

    # 通过订阅回调真正走一遍：事件必须带子会话前缀与来源。
    asyncio.run(_sub_fire(sub, "Network.requestWillBeSent", _sub_will_be_sent("1")))
    events = drain_sub(session)
    assert events[0]["requestId"] == "sub1:1"


async def _sub_fire(cdp: SubSessionCDP, event: str, payload: dict[str, Any]) -> None:
    cdp.fire(event, payload)
    # 回调是 asyncio.create_task 起的，跑完事件循环让它们执行
    await asyncio.sleep(0)


def test_attach_frame_is_idempotent_per_frame(tmp_path: Path) -> None:
    """framenavigated 每次导航都触发；同一 frame 只挂一次（否则事件抓两遍）。"""
    async def run() -> SubContext:
        session = make_sub_session(tmp_path)
        main = SubFrame("frame@main")
        page = SubPage(main)
        main.page = page
        frame = SubFrame("frame@oopif", page=page)
        context = SubContext(oopif_guids={"frame@oopif"})
        session.context = context
        await session.attach_frame_if_needed(frame)
        frame.url = "http://inner.test/next.html"      # 导航后 url 变了
        await session.attach_frame_if_needed(frame)
        await session.attach_frame_if_needed(frame, retry=True)
        return context

    context = asyncio.run(run())
    assert context.calls == ["frame@oopif"], "同一 frame 挂了不止一个会话 → 事件会重复"
    assert len(context.sessions) == 1


def test_concurrent_attach_attempts_create_only_one_session(tmp_path: Path) -> None:
    """**真机踩到过的坑**：frameattached 与 framenavigated 会并发进入挂载流程。

    中间有 await，若只在最后才登记「已挂」就会给同一个 frame 挂出两个会话——
    真机实测出现 sub1/sub2 同时抓同一批请求（同 target、同 requestId），
    正是本任务最怕的「同一批事件被抓两遍 / 串数据」。
    """
    async def run() -> tuple[SubContext, CaptureSession]:
        session = make_sub_session(tmp_path)
        main = SubFrame("frame@main")
        page = SubPage(main)
        main.page = page
        frame = SubFrame("frame@oopif", page=page)
        context = SubContext(oopif_guids={"frame@oopif"})
        session.context = context
        await asyncio.gather(
            session.attach_frame_if_needed(frame),
            session.attach_frame_if_needed(frame),
            session.attach_frame_if_needed(frame, retry=True),
        )
        return context, session

    context, session = asyncio.run(run())
    assert len(context.sessions) == 1, "同一 frame 被挂出了多个会话 → 事件会重复"
    assert len(session.cdp_meta) == 1
    assert session.attaching_frames == set()


def test_attach_frame_retries_until_it_becomes_oopif(tmp_path: Path) -> None:
    """frameattached 时 iframe 常还在父进程里；有界重试要能等到它变成 OOPIF。"""
    interval = capture_module._OOPIF_ATTACH_INTERVAL
    capture_module._OOPIF_ATTACH_INTERVAL = 0
    try:
        async def run() -> SubContext:
            session = make_sub_session(tmp_path)
            main = SubFrame("frame@main")
            page = SubPage(main)
            main.page = page
            frame = SubFrame("frame@here", page=page)
            context = SubContext(oopif_guids={"frame@here"}, fail_first=3)
            session.context = context
            await session.attach_frame_if_needed(frame, retry=True)
            return context

        context = asyncio.run(run())
    finally:
        capture_module._OOPIF_ATTACH_INTERVAL = interval
    assert len(context.sessions) == 1, "重试没挂上 OOPIF 会话"
    assert context.calls == ["frame@here"] * 4


def test_attach_frame_gives_up_after_bounded_attempts(tmp_path: Path) -> None:
    """同进程 iframe 不能无限重试（会一直占着任务）。"""
    interval = capture_module._OOPIF_ATTACH_INTERVAL
    attempts = capture_module._OOPIF_ATTACH_ATTEMPTS
    capture_module._OOPIF_ATTACH_INTERVAL = 0
    try:
        async def run() -> SubContext:
            session = make_sub_session(tmp_path)
            main = SubFrame("frame@main")
            page = SubPage(main)
            main.page = page
            frame = SubFrame("frame@same", page=page)
            context = SubContext()
            session.context = context
            await session.attach_frame_if_needed(frame, retry=True)
            return context

        context = asyncio.run(run())
    finally:
        capture_module._OOPIF_ATTACH_INTERVAL = interval
        assert capture_module._OOPIF_ATTACH_ATTEMPTS == attempts
    assert len(context.calls) == attempts
    assert context.sessions == []


def test_attached_frame_key_is_stable_across_navigations() -> None:
    """_frame_key 必须跨导航稳定——否则一次导航就会重复挂会话。"""
    frame = SubFrame("frame@stable")
    assert _frame_key(frame) == "frame@stable"
    frame.url = "http://inner.test/other.html"
    assert _frame_key(frame) == "frame@stable"
    assert _frame_key(object()) == ""


# --------------------------------------------------------------------------- #
# 3. WebSocket 帧
# --------------------------------------------------------------------------- #
def test_websocket_frame_is_recorded_with_redaction(tmp_path: Path) -> None:
    async def run() -> list[dict[str, Any]]:
        session = make_sub_session(tmp_path)
        page_cdp = _register_sub_cdp(session, tag="")
        await session.on_websocket_created(
            {"requestId": "41100.2", "url": "wss://example.com/socket"}, page_cdp)
        drain_sub(session)
        await session.on_websocket_frame(
            {"requestId": "41100.2",
             "response": {"opcode": 1, "mask": True,
                          "payloadData": '{"user":"a","password":"hunter2"}'}},
            page_cdp, "sent")
        return drain_sub(session)

    frame = asyncio.run(run())[0]
    assert frame["type"] == "websocket_frame"
    assert frame["direction"] == "sent"
    assert frame["opcode"] == 1
    assert frame["url"] == "wss://example.com/socket"
    payload = json.loads(frame["payload"])
    assert payload["password"] == "***", "帧体必须走 redact_payload"
    assert frame["payload_dropped"] is False
    assert frame["token_paths"] == []


def test_websocket_frame_body_over_limit_is_dropped(tmp_path: Path) -> None:
    """超限语义与响应体**完全一致**：不写体，只留 size 与 dropped 标记。"""
    async def run() -> dict[str, Any]:
        session = make_sub_session(tmp_path, limit=64)
        cdp = _register_sub_cdp(session, tag="")
        await session.on_websocket_frame(
            {"requestId": "1", "response": {"opcode": 1, "payloadData": "x" * 500}}, cdp)
        return drain_sub(session)[0]

    frame = asyncio.run(run())
    assert frame["payload"] is None
    assert frame["payload_dropped"] is True
    assert frame["payload_size"] == 500


def test_websocket_binary_frame_size_uses_decoded_length(tmp_path: Path) -> None:
    async def run() -> dict[str, Any]:
        session = make_sub_session(tmp_path)
        cdp = _register_sub_cdp(session, tag="")
        raw = b"\x00\x01\x02\x03"
        await session.on_websocket_frame(
            {"requestId": "1", "response": {"opcode": 2,
                                            "payloadData": base64.b64encode(raw).decode()}},
            cdp, "received")
        return drain_sub(session)[0]

    frame = asyncio.run(run())
    assert frame["payload_size"] == 4, "二进制帧要按 base64 解码后的长度算"
    assert frame["direction"] == "received"


def test_websocket_frame_from_sub_session_is_prefixed(tmp_path: Path) -> None:
    async def run() -> dict[str, Any]:
        session = make_sub_session(tmp_path)
        sub = _register_sub_cdp(session)
        await session.on_websocket_created(
            {"requestId": "9", "url": "wss://inner.test/socket"}, sub)
        drain_sub(session)
        await session.on_websocket_frame(
            {"requestId": "9", "response": {"opcode": 1, "payloadData": "hi"}}, sub)
        return drain_sub(session)[0]

    frame = asyncio.run(run())
    assert frame["requestId"] == "sub1:9"
    assert frame["cdp_session"] == "sub1"
    assert frame["url"] == "wss://inner.test/socket", "url 要按会话维度键取，不能取错别的会话"


def test_websocket_frame_error_is_recorded(tmp_path: Path) -> None:
    async def run() -> dict[str, Any]:
        session = make_sub_session(tmp_path)
        cdp = _register_sub_cdp(session, tag="")
        await session.on_websocket_frame_error(
            {"requestId": "1", "errorMessage": "Connection reset"}, cdp)
        return drain_sub(session)[0]

    event = asyncio.run(run())
    assert event["type"] == "websocket_frame_error"
    assert event["error_message"] == "Connection reset"


def test_paused_session_ignores_new_frames(tmp_path: Path) -> None:
    """暂停语义不变：暂停后**新**到的帧不记录（与其它 handler 一致）。"""
    async def run() -> list[dict[str, Any]]:
        session = make_sub_session(tmp_path)
        cdp = _register_sub_cdp(session, tag="")
        await session.pause("idle_timeout")
        await session.on_websocket_frame(
            {"requestId": "1", "response": {"opcode": 1, "payloadData": "x"}}, cdp, "sent")
        await session.on_websocket_frame_error({"requestId": "1"}, cdp)
        return drain_sub(session)

    assert asyncio.run(run()) == []


def test_ws_url_cache_is_bounded(tmp_path: Path) -> None:
    """握手 url 缓存必须有界（长会话里 ws 连接可以是几万个）。"""
    async def run() -> CaptureSession:
        session = make_sub_session(tmp_path)
        cdp = _register_sub_cdp(session, tag="")
        for index in range(capture_module._MAX_WS_URLS + 20):
            await session.on_websocket_created({"requestId": str(index), "url": "wss://x/"}, cdp)
        return session

    session = asyncio.run(run())
    assert len(session.ws_urls) == capture_module._MAX_WS_URLS
