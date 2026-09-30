# -*- coding: utf-8 -*-
"""Issue #2 回归测试：噪音规则通用化 + 体积/频次启发式 + 超限不写 body。"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scry_mcp_gen.analyzer import (  # noqa: E402
    _heavy_response_suggestion,
    _index_capture,
    _is_noise,
    analyze_capture,
    review_suggested_hint,
)
from scry_mcp_gen.capture import CaptureSession  # noqa: E402
from scry_mcp_gen.config import (  # noqa: E402
    MAX_RESPONSE_LIMIT_BYTES,
    RESPONSE_LIMIT_ENV,
    dropped_response_bodies_hint,
    response_limit_error,
)
from scry_mcp_gen.storage import SessionStore  # noqa: E402


def test_common_noise_domains_are_generic() -> None:
    for host in ("vortex.data.microsoft.com", "browser.pipe.aria.microsoft.com",
                 "fpc.msedge.net", "r.clarity.ms", "www.google-analytics.com",
                 "api.segment.io", "o123.ingest.sentry.io"):
        assert _is_noise(host, "/x"), host


def test_framework_metadata_paths_are_noise() -> None:
    for path in ("/api/data/v9.0/GetClientMetadata(ClientMetadataQuery=@q)",
                 "/uclient/blank.htm", "/_static/blank.htm",
                 "/%7b123%7d/webresources/x.html", "/api/data/v9.0/$metadata"):
        assert _is_noise("example.com", path), path


def test_business_paths_are_not_noise() -> None:
    for path in ("/api/data/v9.0/cr_sampleitems", "/api/data/v9.0/$batch",
                 "/api/orders", "/api/cms/posts"):
        assert not _is_noise("example.com", path), path


def test_noise_hosts_match_regardless_of_port() -> None:
    """F5：域名比对前必须剥端口。

    端点 host 保留端口是常态（生成的多域名路由要用它），而规则集里的域名不带端口。
    修复前直接比较，遥测域名挂在非默认端口上（``aegis.qq.com:8443``）就逃过噪音标记；
    反过来，把域名写成 ``host:port`` 放进 NOISE_DOMAINS 也永远匹配不到任何端点。
    """
    for host in ("aegis.qq.com:8443", "vortex.data.microsoft.com:443",
                 "o123.ingest.sentry.io:8443", "c.clarity.ms:8443"):
        assert _is_noise(host, "/x"), host


def test_business_hosts_with_a_port_are_still_not_noise() -> None:
    for host in ("oa.example.com:8443", "10.0.0.5:8080", "127.0.0.1:3000"):
        assert not _is_noise(host, "/api/orders"), host


def test_framework_ui_paths_are_not_silently_dropped() -> None:
    """`/admin_ui/` 这类框架 UI 路径**故意**不进噪音名单（S19 核实后的结论）。

    `noise=True` 会让端点在生成阶段**硬跳过**（见 project.generation_skip_flags）。
    把 `/admin_ui/` 收进 `NOISE_PATH_PATTERNS` 会连它下面真实提供业务数据的接口
    一起丢掉 —— 对非技术使用者，「多留一个无用工具」远好过「少一个能用的工具」。
    噪音规则因此只收**跨站点成立**的遥测/指纹形态；体积/频次启发式（下面那条）
    负责提示，不负责丢弃。
    """
    for path in ("/admin_ui/static/config.json", "/admin_ui/api/overview"):
        assert not _is_noise("example.com", path), path


def test_review_suggested_hint_explains_itself_in_plain_language() -> None:
    """S19：`review_suggested` 只标记不丢弃，必须附一句人能看懂的理由。"""
    hint = review_suggested_hint(["total_response_bytes=2000000>=1048576"])
    assert "体积" in hint
    assert "确认" in hint or "人工" in hint
    assert review_suggested_hint([]) == ""
    assert review_suggested_hint(None) == ""


def test_dropped_bodies_hint_names_a_real_knob() -> None:
    """S20/S24：补救提示必须指向**真实存在**且**读者做得到**的开关。

    改动前它让使用者去设环境变量 ``SCRY_RESPONSE_LIMIT`` —— 提示的读者是
    Agent（以及不具备技术能力的使用者），那是一件他们做不了的事。现在它必须说出
    **下一步动作**：调哪个工具、传哪个参数、传什么值。
    """
    hint = dropped_response_bodies_hint(3, 256 * 1024)
    assert "3" in hint
    assert "start_capture" in hint and "response_limit_bytes=" in hint
    # 反面：不能把使用者送去做不到的事（设环境变量）。
    assert RESPONSE_LIMIT_ENV not in hint
    assert dropped_response_bodies_hint(0, 256 * 1024) == ""


def test_dropped_bodies_hint_suggests_a_legal_value() -> None:
    """建议值必须落在合法范围内，而且要**比当前上限大**（否则照做也没用）。"""
    for limit in (1, 256 * 1024, 1024 * 1024):
        suggested = int(re.search(r"response_limit_bytes=(\d+)",
                                  dropped_response_bodies_hint(1, limit)).group(1))
        assert limit < suggested <= MAX_RESPONSE_LIMIT_BYTES
        assert response_limit_error(suggested) is None


def test_dropped_bodies_hint_admits_when_the_limit_is_already_maxed() -> None:
    """已经是硬上限时不能再假装「调大就好」——必须如实说清楚。"""
    hint = dropped_response_bodies_hint(1, MAX_RESPONSE_LIMIT_BYTES)
    assert "response_limit_bytes=" not in hint
    assert "最大" in hint


def test_response_limit_error_rejects_illegal_values() -> None:
    """非法值要在**调用入口**给明确错误，而不是抓包中途炸或静默忽略。"""
    for bad in (0, -1, 1.5, "abc", True, MAX_RESPONSE_LIMIT_BYTES + 1):
        message = response_limit_error(bad)
        assert message, f"{bad!r} 应当被拒绝"
        assert str(MAX_RESPONSE_LIMIT_BYTES) in message, "错误句必须写出合法上限"


def test_response_limit_error_accepts_legal_values() -> None:
    # None = 不传参数（沿用默认上限），必须放行 —— 否则默认路径会被自己的校验拦下。
    for good in (None, 1, 256 * 1024, MAX_RESPONSE_LIMIT_BYTES):
        assert response_limit_error(good) is None


def test_heavy_response_heuristic_is_review_not_noise() -> None:
    # 单端点累计超阈值 -> 仅 review_suggested，reasons 说明原因
    hint = _heavy_response_suggestion(3, 2_000_000, 1_000_000, 1_048_576, 50)
    assert hint and hint["review_suggested"] is True
    assert any("total_response_bytes" in r for r in hint["reasons"])
    # 高频采样
    hint = _heavy_response_suggestion(90, 100, 100, 1_048_576, 50)
    assert hint and any("sample_count" in r for r in hint["reasons"])
    # 小体量低频 -> 不标记
    assert _heavy_response_suggestion(2, 1000, 500, 1_048_576, 50) is None


class FakeCDP:
    def __init__(self, payload: str) -> None:
        self.payload = payload

    async def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"body": self.payload, "base64Encoded": False}


def _run_finished(payload: str, limit: int, tmp_path: Path) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        store = SessionStore(tmp_path)
        session = CaptureSession("s", "https://example.com/", store, limit, 300)
        session.status = "capturing"
        session.directory.mkdir(parents=True, exist_ok=True)
        await session.on_finished({"requestId": "r1"}, FakeCDP(payload))
        return session.event_queue.get_nowait()
    return asyncio.run(run())


def test_oversized_body_is_dropped_not_truncated(tmp_path: Path) -> None:
    """超限时只写元数据，不写 body——修复前会写入截断后的 response_limit 字节。"""
    event = _run_finished("x" * 5000, 1000, tmp_path)
    assert event["body"] is None
    assert event["body_dropped"] is True
    assert event["body_truncated"] is True
    assert event["size"] == 5000


def test_small_body_written_verbatim(tmp_path: Path) -> None:
    event = _run_finished('{"ok":true}', 1000, tmp_path)
    assert event["body"] == '{"ok":true}'
    assert event["body_dropped"] is False
    assert event["size"] == len('{"ok":true}')


def _run_session(payload: str, limit: int, tmp_path: Path,
                 explicit: bool = False) -> CaptureSession:
    async def run() -> CaptureSession:
        store = SessionStore(tmp_path)
        session = CaptureSession("s", "https://example.com/", store, limit, 300,
                                 response_limit_explicit=explicit)
        session.status = "capturing"
        session.directory.mkdir(parents=True, exist_ok=True)
        await session.on_finished({"requestId": "r1"}, FakeCDP(payload))
        return session
    return asyncio.run(run())


def test_metadata_reports_dropped_response_bodies(tmp_path: Path) -> None:
    """S20：丢过响应体，会话元数据必须如实上报（不能只藏在 capture.jsonl 里）。"""
    meta = _run_session("x" * 5000, 1000, tmp_path).metadata()

    assert meta["dropped_response_bodies"] == 1
    assert "start_capture" in meta["dropped_response_bodies_hint"]
    assert "上限" in meta["dropped_response_bodies_hint"]


def test_metadata_names_the_limit_only_when_it_was_chosen_explicitly(tmp_path: Path) -> None:
    """S24：显式指定过上限才把生效值记进元数据；默认路径的形状一字不变。

    analyze_traffic 是**无状态**的，只能靠这个字段说出「当前上限」到底是哪个值。
    """
    explicit = _run_session('{"ok":true}', 1000, tmp_path, explicit=True).metadata()
    default = _run_session('{"ok":true}', 1000, tmp_path).metadata()

    assert explicit["response_limit_bytes"] == 1000
    assert "response_limit_bytes" not in default


def test_metadata_stays_unchanged_when_nothing_was_dropped(tmp_path: Path) -> None:
    """没丢过就不加键 —— 正常会话的元数据形状保持不变。"""
    meta = _run_session('{"ok":true}', 1000, tmp_path).metadata()

    assert "dropped_response_bodies" not in meta
    assert "dropped_response_bodies_hint" not in meta


class TestCaptureIsParsedLineByLine:
    """C-3 #1：analyze_capture 不得先把整份 capture.jsonl 读进内存再建索引。

    修复前 ``_load_events`` 先 ``read_text()`` 整份文件、再拆成 ``list[dict]``，
    长抓包在建立索引前会以「原文 + 全部事件 dict」两份形态同时驻留。
    现在逐行解析（生成器）并直接建索引，只保留真正会被用到的记录。
    """

    def _capture(self, tmp_path: Path) -> Path:
        session = tmp_path / "cap"
        session.mkdir()
        (session / "capture.jsonl").write_text(
            "\n".join(json.dumps(event) for event in [
                {"type": "request", "requestId": "r1", "url": "https://example.com/api/orders",
                 "method": "GET", "headers": {}, "resourceType": "XHR"},
                {"type": "response", "requestId": "r1", "status": 200,
                 "headers": {"Content-Type": "application/json"}},
                {"type": "response_body", "requestId": "r1", "body": "{}", "size": 2},
            ]) + "\n", encoding="utf-8")
        return session

    def test_index_never_reads_the_whole_file(self, tmp_path: Path, monkeypatch) -> None:
        capture = self._capture(tmp_path) / "capture.jsonl"
        whole_reads: list[str] = []
        real_read_text = Path.read_text

        def counting_read_text(self, *args: Any, **kwargs: Any) -> str:
            if self.name == "capture.jsonl":
                whole_reads.append(str(self))
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", counting_read_text)

        index = _index_capture(capture)

        assert whole_reads == [], "整份抓包被 read_text() 读进了内存（C-3 回归）"
        assert ("r1", 0) in index.requests and index.request_count == 1

    def test_index_keeps_no_raw_event_list(self, tmp_path: Path) -> None:
        """索引里只有真正会用到的记录，不再挂一个「全部原始事件」的列表。"""
        import scry_mcp_gen.analyzer as analyzer_module

        index = _index_capture(self._capture(tmp_path) / "capture.jsonl")

        assert not hasattr(index, "events")
        assert not hasattr(analyzer_module, "_load_events"), \
            "整读 + 全量 list[dict] 的旧实现不得复活"

    def test_analysis_still_works_end_to_end(self, tmp_path: Path) -> None:
        result = analyze_capture(self._capture(tmp_path))

        assert [e["path"] for e in result["endpoints"]] == ["/api/orders"]


def _capture_request_body(post_data: str, limit: int, tmp_path: Path) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        store = SessionStore(tmp_path)
        session = CaptureSession("s", "https://example.com/", store, limit, 300)
        session.status = "capturing"
        session.directory.mkdir(parents=True, exist_ok=True)
        await session.on_request({
            "requestId": "r1", "type": "Fetch",
            "request": {"url": "https://example.com/api/x", "method": "POST",
                        "postData": post_data, "headers": {}}}, None)
        # Fix 2: emitted_requests 的值改成 (monotonic, record) —— 与 pending_extra
        # 同构，才能按 TTL / 容量回收「永不结束」的请求。这里取记录本身。
        return session.emitted_requests["r1"][1]
    return asyncio.run(run())


def test_request_body_over_limit_is_dropped(tmp_path: Path) -> None:
    """请求体此前**没有任何上限**：一个 500MB 上传会撑爆磁盘与内存。

    现在与响应体共用同一套语义：超限则整条不记录，只留大小与标记。
    """
    body = "password=Secret1&x=" + "A" * 500
    record = _capture_request_body(body, 200, tmp_path)
    assert record["postData"] is None
    assert record["body_dropped"] is True
    assert record["postData_size"] == len(body.encode("utf-8"))


def test_request_body_within_limit_is_redacted_not_dropped(tmp_path: Path) -> None:
    """限额内的表单体照旧脱敏，且**键名保留**（参数推断依赖它，不能整段遮蔽）。"""
    record = _capture_request_body("password=Secret1&submit", 200, tmp_path)
    assert record["body_dropped"] is False
    assert record["postData"] == "password=***&submit="
