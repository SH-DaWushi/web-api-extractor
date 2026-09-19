# -*- coding: utf-8 -*-
"""Issue #10：服务重启回收会话时，应保留「数据仍可分析」的信息。

修复前一律置 stopped，用户看到状态是 stopped 就以为整轮抓包白干了，
而实际 capture.jsonl 是逐条落盘的、数据还在且可分析。
"""
from __future__ import annotations

import json

from webapi_extractor.storage import SessionStore


def _make_session(store: SessionStore, sid: str, status: str, payload_bytes: int) -> None:
    store.session_path(sid).mkdir(parents=True, exist_ok=True)
    store.write_metadata(sid, {"session_id": sid, "status": status, "url": "https://x/"})
    if payload_bytes:
        (store.session_path(sid) / "capture.jsonl").write_bytes(b"x" * payload_bytes)


class TestRecoverOrphans:
    def test_marks_active_session_as_recovered_with_data(self, tmp_path):
        store = SessionStore(tmp_path)
        _make_session(store, "s_with_data", "capturing", 5000)

        recovered = store.recover_orphans()

        assert recovered == ["s_with_data"]
        meta = store.read_metadata("s_with_data")
        assert meta["status"] == "stopped"
        assert meta["stop_reason"] == "server_restarted"
        # 关键：告知数据仍在
        assert meta["recovered"] is True
        assert meta["captured_bytes"] == 5000
        assert "分析" in meta["recovered_hint"]

    def test_empty_session_not_marked_recovered(self, tmp_path):
        """没有数据的会话不应标 recovered，避免误导。"""
        store = SessionStore(tmp_path)
        _make_session(store, "s_empty", "capturing", 0)

        store.recover_orphans()

        meta = store.read_metadata("s_empty")
        assert meta["status"] == "stopped"
        assert "recovered" not in meta
        assert meta["captured_bytes"] == 0

    def test_already_stopped_session_untouched(self, tmp_path):
        store = SessionStore(tmp_path)
        _make_session(store, "s_done", "stopped", 1000)

        assert store.recover_orphans() == []
        meta = store.read_metadata("s_done")
        assert "recovered" not in meta

    def test_status_history_recorded(self, tmp_path):
        store = SessionStore(tmp_path)
        _make_session(store, "s1", "paused", 100)

        store.recover_orphans()

        meta = store.read_metadata("s1")
        assert meta["status_history"][-1]["reason"] == "server_restarted"

    def test_all_active_states_recovered(self, tmp_path):
        store = SessionStore(tmp_path)
        for st in ("capturing", "paused", "stopping"):
            _make_session(store, f"s_{st}", st, 100)

        recovered = store.recover_orphans()

        assert set(recovered) == {"s_capturing", "s_paused", "s_stopping"}

    def test_hint_is_human_readable(self, tmp_path):
        store = SessionStore(tmp_path)
        _make_session(store, "s2", "capturing", 2048)

        store.recover_orphans()

        hint = store.read_metadata("s2")["recovered_hint"]
        assert "2.0 KB" in hint
        assert "analyze_traffic" in hint
