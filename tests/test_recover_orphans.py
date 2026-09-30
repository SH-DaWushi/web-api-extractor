# -*- coding: utf-8 -*-
"""Issue #10：服务重启回收会话时，应保留「数据仍可分析」的信息。

修复前一律置 stopped，用户看到状态是 stopped 就以为整轮抓包白干了，
而实际 capture.jsonl 是逐条落盘的、数据还在且可分析。
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from webapi_extractor.auth import _site_key
from webapi_extractor.storage import (
    ACTIVE_STATES,
    ALIVE,
    DEAD,
    UNKNOWN,
    InstanceRegistry,
    SessionStore,
    probe_process,
    sanitize_path_segment,
)


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

    def test_authenticating_is_an_active_state(self):
        """S1：登录阶段（server.py 对默认路径写的初始状态）也必须算「活着」。

        不在集合里 → 服务在用户登录期间重启后，会话永远卡在待登录：
        list_sessions/get_capture_status 报它活着，confirm_login_ready 报
        capture_session_not_found，陈旧行无限堆积在磁盘上。
        """
        assert "authenticating" in ACTIVE_STATES

    def test_all_active_states_recovered(self, tmp_path):
        store = SessionStore(tmp_path)
        for st in ("capturing", "paused", "stopping", "authenticating"):
            _make_session(store, f"s_{st}", st, 100)

        recovered = store.recover_orphans()

        assert set(recovered) == {"s_capturing", "s_paused", "s_stopping", "s_authenticating"}

    def test_authenticating_without_data_is_stopped_but_not_recovered(self, tmp_path):
        """S1：登录阶段通常**没有**落盘数据 —— 只落 stopped，不谎称「有数据可分析」。"""
        store = SessionStore(tmp_path)
        _make_session(store, "s_login", "authenticating", 0)

        assert store.recover_orphans() == ["s_login"]

        meta = store.read_metadata("s_login")
        assert meta["status"] == "stopped"
        assert meta["stop_reason"] == "server_restarted"
        assert "recovered" not in meta
        assert "recovered_hint" not in meta
        assert meta["captured_bytes"] == 0
        assert meta["status_history"][-1]["reason"] == "server_restarted"
        # 状态已离开活动集合：此后不再被 list_sessions 报成「活着」。
        assert meta["status"] not in ACTIVE_STATES

    def test_hint_is_human_readable(self, tmp_path):
        store = SessionStore(tmp_path)
        _make_session(store, "s2", "capturing", 2048)

        store.recover_orphans()

        hint = store.read_metadata("s2")["recovered_hint"]
        assert "2.0 KB" in hint
        assert "analyze_traffic" in hint


class TestSanitizePathSegment:
    """D1：session_id 是不可信输入，不得逃出 sessions_dir。"""

    VALID_IDS = [
        "s1",
        "sess-42",
        "s_with_data",
        "20260925_120000_oa.example.com_a1b2",
    ]

    @pytest.mark.parametrize("sid", VALID_IDS)
    def test_valid_ids_pass_through_byte_identically(self, sid):
        assert sanitize_path_segment(sid) == sid

    @pytest.mark.parametrize("hostile", [
        "../../../../PWNED",
        "..\\..\\PWNED",
        ".",
        "..",
        "...",
        "a/b/c",
        "C:\\Windows\\Temp",
        "\x00\x08evil",
        "x" * 500,
        "",
    ])
    def test_output_is_a_single_safe_segment(self, hostile):
        out = sanitize_path_segment(hostile)
        assert out, "净化结果不能为空"
        assert "/" not in out and "\\" not in out
        assert out not in {".", ".."}
        assert re.fullmatch(r"[A-Za-z0-9._-]+", out)
        assert len(out) <= 120
        # 幂等——recover_orphans / list_sessions 会用目录名再走一遍本函数。
        assert sanitize_path_segment(out) == out

    def test_distinct_inputs_do_not_collide(self):
        assert sanitize_path_segment("a/b") != sanitize_path_segment("a_b")

    def test_truncation_keeps_distinct_and_bounded(self):
        base = "x" * 200
        k1 = sanitize_path_segment(base + "1")
        k2 = sanitize_path_segment(base + "2")
        assert len(k1) <= 120 and len(k2) <= 120
        assert k1 != k2

    def test_traversal_cannot_escape_sessions_dir(self, tmp_path):
        store = SessionStore(tmp_path / "sessions")
        outside = tmp_path / "PWNED"
        for hostile in ("../PWNED", "../../../../PWNED", "..\\..\\PWNED"):
            path = store.session_path(hostile)
            assert path.resolve().parent == store.sessions_dir.resolve()
            assert store.sessions_dir.resolve() in path.resolve().parents
            assert path.resolve() != outside.resolve()
        # 真写一次：文件必须落在 sessions_dir 内，外面不能凭空出现 PWNED。
        store.write_metadata("../../../../PWNED", {"session_id": "x", "status": "stopped"})
        assert not outside.exists()
        assert list(store.sessions_dir.glob("PWNED")) == []
        # 仍然读得回来（路径确定且一致）。
        assert store.read_metadata("../../../../PWNED")["status"] == "stopped"

    def test_recover_orphans_ignores_crafted_directory_names(self, tmp_path):
        """构造目录名不得让回收逻辑越界或读到意外会话。"""
        store = SessionStore(tmp_path)
        crafted = store.sessions_dir / "..sneaky"
        crafted.mkdir()
        (crafted / "session.json").write_text(
            json.dumps({"session_id": "..sneaky", "status": "capturing"}),
            encoding="utf-8",
        )
        # 目录名不往返（净化后指向别处），故不会被回收，也不会写到 sessions_dir 外。
        assert store.recover_orphans() == []
        assert not (tmp_path / "sneaky").exists()


def _write_instance(
    data_root: Path,
    token: str,
    *,
    pid: int,
    start_fingerprint: str | None,
    heartbeat_age: float,
) -> InstanceRegistry:
    """手写一份「别人（或已死的进程）」的实例身份文件，供回收判定用。"""
    instances = data_root / "instances"
    instances.mkdir(parents=True, exist_ok=True)
    when = datetime.now(timezone.utc) - timedelta(seconds=heartbeat_age)
    (instances / f"{token}.json").write_text(json.dumps({
        "token": token,
        "pid": pid,
        "start_fingerprint": start_fingerprint,
        "started_at": when.isoformat(),
        "heartbeat_at": when.isoformat(),
    }), encoding="utf-8")
    return InstanceRegistry(instances, token=token)


class TestInstanceIdentity:
    """S8：每个运行中的实例有持久身份 + 心跳（写在数据根下）。"""

    def test_register_records_pid_fingerprint_and_heartbeat(self, tmp_path):
        registry = InstanceRegistry(tmp_path / "instances")

        assert registry.register() is True

        record = json.loads(registry.path.read_text(encoding="utf-8"))
        assert record["token"] == registry.token
        assert record["pid"] == os.getpid()
        assert record["heartbeat_at"]
        assert record["start_fingerprint"], "本机应能取到启动时间指纹（Windows: 文件时间）"

    def test_heartbeat_refreshes_the_timestamp(self, tmp_path):
        registry = InstanceRegistry(tmp_path / "instances")
        registry.register()
        first = json.loads(registry.path.read_text(encoding="utf-8"))["heartbeat_at"]
        _write_instance(tmp_path, registry.token, pid=os.getpid(),
                        start_fingerprint=registry.start_fingerprint, heartbeat_age=3600)

        registry.heartbeat(force=True)

        second = json.loads(registry.path.read_text(encoding="utf-8"))["heartbeat_at"]
        assert second != first
        assert "3600" not in second

    def test_register_is_best_effort_and_never_raises(self, tmp_path):
        """身份是旁路：写不进去（磁盘只读/路径被占）也不能让服务起不来。"""
        blocker = tmp_path / "instances"
        blocker.write_text("not a directory", encoding="utf-8")

        registry = InstanceRegistry(blocker)

        assert registry.register() is False
        assert registry.last_error

    def test_probe_of_own_process_reports_alive_with_fingerprint(self):
        alive, fingerprint = probe_process(os.getpid())
        assert alive is True
        assert fingerprint

    def test_probe_of_impossible_pid_reports_dead(self):
        alive, _ = probe_process(999_999_999)
        assert alive is False

    @pytest.mark.skipif(os.name != "nt", reason="Windows 专用：不能靠 os.kill(pid, 0) 判活")
    def test_windows_probe_does_not_go_through_os_kill(self, monkeypatch):
        """Windows 上 os.kill(pid, 0) 会真的发信号/抛错，判活必须走 OpenProcess 那条路。"""
        from webapi_extractor import storage

        def _boom(pid: int):
            raise AssertionError("Windows 分支不得调用 POSIX 的 os.kill(pid, 0)")

        monkeypatch.setattr(storage, "_posix_probe", _boom)
        assert probe_process(os.getpid())[0] is True


class TestOwnerState:
    """owner 活性的三态判定：只有 DEAD 才允许回收。"""

    def test_missing_record_is_unknown(self, tmp_path):
        registry = InstanceRegistry(tmp_path / "instances")
        assert registry.owner_state("never-registered") == UNKNOWN
        assert registry.owner_state(None) == UNKNOWN

    def test_fresh_heartbeat_is_alive_even_without_a_live_pid(self, tmp_path):
        """token + 心跳本身就是存活证据（心跳刚写过 → 那个进程刚刚还在跑）。"""
        registry = _write_instance(tmp_path, "beating", pid=999_999_999,
                                   start_fingerprint="win-filetime:1", heartbeat_age=0)
        assert registry.owner_state("beating") == ALIVE

    def test_stale_heartbeat_with_dead_pid_is_dead(self, tmp_path):
        registry = _write_instance(tmp_path, "gone", pid=999_999_999,
                                   start_fingerprint="win-filetime:1", heartbeat_age=3600)
        assert registry.owner_state("gone") == DEAD

    def test_stale_heartbeat_with_reused_pid_is_dead(self, tmp_path):
        """PID 复用：pid 活着（就是本测试进程）但启动时间对不上 → 原实例已死。"""
        registry = _write_instance(tmp_path, "reused", pid=os.getpid(),
                                   start_fingerprint="win-filetime:1", heartbeat_age=3600)
        assert registry.owner_state("reused") == DEAD

    def test_stale_heartbeat_with_live_process_and_matching_fingerprint_is_alive(self, tmp_path):
        """心跳陈旧 ≠ 已死：只要 pid + 启动指纹都对得上，就绝不能回收它的会话。"""
        fingerprint = probe_process(os.getpid())[1]
        registry = _write_instance(tmp_path, "quiet", pid=os.getpid(),
                                   start_fingerprint=fingerprint, heartbeat_age=3600)
        assert registry.owner_state("quiet") == ALIVE

    def test_unverifiable_fingerprint_is_unknown(self, tmp_path):
        """取不到指纹（无权限/平台不支持）→ 判定不了 → 不回收。"""
        registry = _write_instance(tmp_path, "opaque", pid=os.getpid(),
                                   start_fingerprint=None, heartbeat_age=3600)
        assert registry.owner_state("opaque") == UNKNOWN

    def test_prune_dead_removes_only_provably_dead_instances(self, tmp_path):
        dead = _write_instance(tmp_path, "dead", pid=999_999_999,
                               start_fingerprint="win-filetime:1", heartbeat_age=3600)
        alive = _write_instance(tmp_path, "alive", pid=999_999_999,
                                start_fingerprint="win-filetime:1", heartbeat_age=0)
        unknown = _write_instance(tmp_path, "unknown", pid=os.getpid(),
                                  start_fingerprint=None, heartbeat_age=3600)

        removed = alive.prune_dead()

        assert removed == ["dead"]
        assert not dead.path.exists()
        assert alive.path.exists()
        assert unknown.path.exists()


class TestRecoverOrphansAcrossInstances:
    """S8：多实例共享一个数据根时，谁也不许抢谁的会话。"""

    def _root(self, tmp_path: Path) -> Path:
        (tmp_path / "sessions").mkdir(parents=True, exist_ok=True)
        return tmp_path

    def test_two_live_instances_do_not_steal_each_others_sessions(self, tmp_path):
        """实例 A 启动时，实例 B 正在抓的会话必须原样不动（修复前被一律判死改写）。"""
        root = self._root(tmp_path)
        store = SessionStore(root / "sessions")
        registry_b = InstanceRegistry(root / "instances")
        registry_b.register()                       # B 正在跑
        _make_session(store, "s_b", "capturing", 5000)
        store.write_owner("s_b", token=registry_b.token, pid=registry_b.pid,
                          start_fingerprint=registry_b.start_fingerprint)
        registry_a = InstanceRegistry(root / "instances")
        registry_a.register()                       # A 也起来了，同一个数据根

        recovered = store.recover_orphans(registry_a)

        assert recovered == [], "活着的实例 B 的会话被 A 回收了"
        meta = store.read_metadata("s_b")
        assert meta["status"] == "capturing"
        assert "recovered" not in meta
        assert store.last_recovery_skipped == [
            {"session_id": "s_b", "owner": registry_b.token, "state": ALIVE}]
        # 两边的心跳文件都还在（谁也没被对方当成垃圾清掉）
        assert registry_a.path.exists() and registry_b.path.exists()

    def test_session_of_provably_dead_owner_with_stale_heartbeat_is_recovered(self, tmp_path):
        root = self._root(tmp_path)
        store = SessionStore(root / "sessions")
        registry = _write_instance(root, "corpse", pid=999_999_999,
                                   start_fingerprint="win-filetime:1", heartbeat_age=3600)
        _make_session(store, "s_dead", "capturing", 2048)
        store.write_owner("s_dead", token="corpse", pid=999_999_999,
                          start_fingerprint="win-filetime:1")

        recovered = store.recover_orphans(registry)

        assert recovered == ["s_dead"]
        meta = store.read_metadata("s_dead")
        assert meta["status"] == "stopped"
        assert meta["stop_reason"] == "server_restarted"
        assert meta["recovered"] is True
        assert meta["captured_bytes"] == 2048
        # 判据留痕：这是「owner 已死」的回收，而不是旧版的无条件回收
        assert meta["orphaned_owner"] == "corpse"
        assert meta["orphaned_owner_state"] == DEAD

    def test_legacy_session_without_owner_file_is_still_recovered(self, tmp_path):
        """反向兼容：升级前留下的、没有 owner.json 的旧会话不能变成永久垃圾。"""
        root = self._root(tmp_path)
        store = SessionStore(root / "sessions")
        registry = InstanceRegistry(root / "instances")
        registry.register()                        # 本机有活着的实例，但旧会话与它无关
        _make_session(store, "s_legacy", "capturing", 1024)
        assert store.read_owner("s_legacy") is None

        recovered = store.recover_orphans(registry)

        assert recovered == ["s_legacy"]
        meta = store.read_metadata("s_legacy")
        assert meta["status"] == "stopped"
        assert meta["recovered"] is True

    def test_owner_token_without_instance_record_is_left_alone(self, tmp_path):
        """判定不了（owner 文件在、实例记录没了）→ 保守方向：先不回收。"""
        root = self._root(tmp_path)
        store = SessionStore(root / "sessions")
        registry = InstanceRegistry(root / "instances")
        registry.register()
        _make_session(store, "s_opaque", "capturing", 10)
        store.write_owner("s_opaque", token="vanished-record")

        assert store.recover_orphans(registry) == []
        assert store.read_metadata("s_opaque")["status"] == "capturing"
        assert store.last_recovery_skipped == [
            {"session_id": "s_opaque", "owner": "vanished-record", "state": UNKNOWN}]

    def test_default_registry_is_derived_from_the_data_root(self, tmp_path):
        """不传 registry 时按「数据根 = 会话目录的父目录」推断，且绝不创建目录。"""
        root = self._root(tmp_path)
        store = SessionStore(root / "sessions")
        registry = InstanceRegistry(root / "instances")
        registry.register()
        registry.heartbeat(force=True)
        _make_session(store, "s_owned", "capturing", 64)
        store.write_owner("s_owned", token=registry.token, pid=registry.pid,
                          start_fingerprint=registry.start_fingerprint)

        assert store.recover_orphans() == []

        assert store.read_metadata("s_owned")["status"] == "capturing"
        # 只读路径：会话目录里不会凭空多出 instances/
        assert not (store.sessions_dir / "instances").exists()

    def test_unknown_state_never_recovers(self, tmp_path):
        """UNKNOWN（判定不了）一律按「可能还活着」处理。"""
        root = self._root(tmp_path)
        store = SessionStore(root / "sessions")
        registry = _write_instance(root, "opaque", pid=os.getpid(),
                                   start_fingerprint=None, heartbeat_age=3600)
        _make_session(store, "s_opaque", "paused", 0)
        store.write_owner("s_opaque", token="opaque", pid=os.getpid(), start_fingerprint=None)

        assert store.recover_orphans(registry) == []
        assert store.last_recovery_skipped[0]["state"] == UNKNOWN


class TestSiteKey:
    """D2：auth_states 文件名必须安全、有界，且不同目标不互相覆盖。"""

    def test_ordinary_host_keeps_readable_form(self):
        assert _site_key("https://oa.example.com/login") == "oa_example_com"
        assert _site_key("https://oa.example.com:8443/x") == "oa_example_com_8443"

    def test_empty_netloc_does_not_collapse_targets(self):
        a = _site_key("foo.example/login")
        b = _site_key("bar.example/login")
        assert a and b
        assert a != b

    def test_long_netloc_is_bounded_and_creatable(self, tmp_path):
        key = _site_key("https://" + "a" * 300 + ".example.com/")
        assert len(key) <= 120
        assert re.fullmatch(r"[A-Za-z0-9._-]+", key)
        state_dir = tmp_path / "auth_states"
        state_dir.mkdir()
        path = state_dir / f"{key}.json"
        path.write_text("{}", encoding="utf-8")   # 旧实现此处 OSError
        assert path.exists()

    def test_control_character_netloc_is_sanitised(self):
        key = _site_key("http://ex\x08ample.com/")
        assert re.fullmatch(r"[A-Za-z0-9._-]+", key)

    def test_malformed_url_does_not_raise(self):
        assert _site_key("http://[::1")   # urlparse 会抛 ValueError
