# -*- coding: utf-8 -*-
"""Issue #2 回归测试：噪音规则通用化 + 体积/频次启发式 + 超限不写 body。"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webapi_extractor.analyzer import _heavy_response_suggestion, _is_noise  # noqa: E402
from webapi_extractor.capture import CaptureSession  # noqa: E402
from webapi_extractor.storage import SessionStore  # noqa: E402


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
