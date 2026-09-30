"""Persistent session metadata, instance identity, and orphan recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# S1：``authenticating`` 也是「活的」——server.py 对默认路径（未传
# ``auth_state_path``）写下的初始状态就是它，等待用户完成登录。若服务在
# 等待期间重启，浏览器已死，该会话却不在本集合里，于是永远不被回收：
# list_sessions / get_capture_status 一直报它活着，confirm_login_ready 报
# capture_session_not_found，陈旧行还会无限堆积在磁盘上。
ACTIVE_STATES = {"capturing", "paused", "stopping", "authenticating"}

# --------------------------------------------------------------------------- #
# S8：多实例共享一个数据根（``SCRY_DATA``）时，谁能回收谁
#
# 修复前 ``recover_orphans`` 把「任何处于活动状态的会话」都当孤儿，于是实例 A
# 启动时会把**实例 B 正在抓取**的会话判死并改写。现在每个运行中的实例有一个
# 持久身份 + 心跳（``<data_root>/instances/<token>.json``），每个会话目录里记下
# 它的 owner token（``owner.json``）；回收只对「owner 可证明已消失」的会话生效。
#
# 判定顺序（每一步都往**保守**方向兜底：宁可先不回收，也不误杀活实例）：
#
#   1. 无 owner 文件的旧会话（本修复之前创建的）→ 仍按旧行为回收（向后兼容，
#      否则升级后老孤儿会变成永久垃圾）；
#   2. owner 记录读不出来 / token 为空 → UNKNOWN → **不回收**；
#   3. 心跳新鲜（≤ INSTANCE_STALE_AFTER）→ ALIVE → 不回收
#      （token + 心跳本身就是存活证据）；
#   4. 心跳陈旧 → 用 ``pid + 进程启动时间指纹`` 复核：
#        * pid 已不存在 → DEAD → 回收；
#        * pid 存在但指纹对不上（Windows/POSIX 都会复用 pid）→ DEAD → 回收；
#        * 指纹对得上 → ALIVE → 不回收；
#        * 记录里没有 pid、或取不到指纹（权限/平台不支持）→ UNKNOWN → **不回收**。
#
# 只有 DEAD 会被回收。心跳过期只是「可疑」，单独不构成回收理由。
# --------------------------------------------------------------------------- #
_INSTANCE_HEARTBEAT_INTERVAL = 15.0     # 心跳写盘间隔（秒）
_INSTANCE_STALE_AFTER = 90.0            # 心跳早于它即「陈旧」（= 6 个心跳周期）
_OWNER_FILENAME = "owner.json"

# owner 活性判定结果（三态；旧代码里只有「活/死」两态，正是误杀的根因）
ALIVE = "alive"
DEAD = "dead"
UNKNOWN = "unknown"

# D1: session_id 由调用方（可能被提示注入的 Agent）提供，最终会拼进文件系统。
# 只允许这个白名单字符集，其余一律替换；结果保证是**单层**路径片段，
# 不可能逃出 sessions_dir。
_ALLOWED_SEGMENT_CHARS = re.compile(r"[^A-Za-z0-9._-]")
_MAX_SEGMENT_LENGTH = 120
_HASH_LENGTH = 8


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize_path_segment(
    value: Any,
    *,
    max_length: int = _MAX_SEGMENT_LENGTH,
    default: str = "session",
) -> str:
    """把任意调用方输入转成一个安全的、**单层**的路径片段。

    D1 修复：``session_id`` 会被直接用来拼 ``sessions_dir / session_id`` 并
    ``mkdir(parents=True)`` / ``os.replace``。``"../../.."`` 之类的输入因此能
    写到数据目录之外。本函数收敛所有这类片段。

    策略：**确定性净化，永不抛异常**（调用点遍布各 MCP 工具，抛异常会把
    一个恶意/笔误的 id 变成服务端 500，而不是一个安全的隔离目录）：

    * 只保留 ``[A-Za-z0-9._-]``；``/``、``\\``、控制字符、Unicode 等一律换成
      ``_``，故结果里不可能再出现路径分隔符；
    * 开头的点号替换为 ``_``；空串与纯点号（``.`` / ``..``）视为退化输入，
      改用 ``default``——结果既不是 ``.``/``..``，也不是隐藏文件；
    * 只要输入被改动过，就追加 8 位十六进制摘要（取自**原始**输入）：不同输入
      不会撞进同一片段，同一输入则稳定复现；
    * 结果长度封顶 ``max_length``（默认 120），超长时保留前缀 + 摘要后缀，
      不会因超长文件名触发 OSError。

    幂等：``sanitize_path_segment(sanitize_path_segment(x))`` 等于
    ``sanitize_path_segment(x)``——``recover_orphans`` / ``list_sessions``
    会用目录名再走一遍本函数，必须映射回同一路径。

    合法 id（``s1``、``sess-42``、``s_with_data``、
    ``20260925_120000_oa.example.com_a1b2``）原样返回（byte-identical）。
    """
    original = value if isinstance(value, str) else str(value)
    cleaned = _ALLOWED_SEGMENT_CHARS.sub("_", original)
    # 合法 id 不以 '.' 开头；把前导点号整体换成 '_' 可消灭 '.'/'..'/'...' 组件，
    # 同时保证输出永不以 '.' 开头（从而对再次净化是稳定不动点）。
    cleaned = re.sub(r"^\.+", "_", cleaned)
    if not cleaned:
        cleaned = default

    suffix = ""
    if cleaned != original or len(cleaned) > max_length:
        digest = hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()
        suffix = "_" + digest[:_HASH_LENGTH]
    budget = max_length - len(suffix)
    if budget < 1:
        # max_length 被设得极小：退回摘要本身，仍是安全且定长的片段。
        bounded = max(1, max_length)
        return hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()[:bounded]
    return cleaned[:budget] + suffix


def _parse_timestamp(value: Any) -> datetime | None:
    """解析 ISO 时间戳；无法解析（或类型不对）返回 None。"""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _windows_probe(pid: int) -> tuple[bool, str | None]:
    """Windows：(是否存活, 启动时间指纹)。

    ``OpenProcess`` + ``GetExitCodeProcess`` / ``GetProcessTimes``，与
    ``start_server.pid_alive`` 回答的是**同一个问题**（该 pid 的进程还在不在，
    那边用 ``tasklist``），只是这里顺带取回**进程启动时间**：Windows 会复用 pid，
    只看「pid 还在」会把一个无关的新进程误认成老实例，进而把老实例的会话判活
    （或反过来把活实例判死）。
    """
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    ERROR_ACCESS_DENIED = 5

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # 句柄必须声明为 64 位指针：ctypes 默认 restype=c_int 会在 64 位进程里把
    # HANDLE 截断成 32 位，后续 GetProcessTimes 就会失败（退化成「指纹未知」）。
    filetime_pointer = ctypes.POINTER(wintypes.FILETIME)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, filetime_pointer,
                                         filetime_pointer, filetime_pointer, filetime_pointer]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        # 拒绝访问 = 进程**存在**但我们查不了（判定为「活着、指纹未知」→ 保守）；
        # 其余（参数无效等）= 该 pid 上没有进程。
        if ctypes.get_last_error() == ERROR_ACCESS_DENIED:
            return True, None
        return False, None
    try:
        code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != STILL_ACTIVE:
            return False, None
        created, exited = wintypes.FILETIME(), wintypes.FILETIME()
        kernel, user = wintypes.FILETIME(), wintypes.FILETIME()
        ok = kernel32.GetProcessTimes(
            handle, ctypes.byref(created), ctypes.byref(exited),
            ctypes.byref(kernel), ctypes.byref(user))
        if not ok:
            return True, None
        ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
        return True, f"win-filetime:{ticks}"
    finally:
        kernel32.CloseHandle(handle)


def _posix_probe(pid: int) -> tuple[bool, str | None]:
    """POSIX：(是否存活, 启动时间指纹)。

    指纹取 ``/proc/<pid>/stat`` 的 starttime（第 22 字段）；存活判定与
    ``start_server.pid_alive`` 的 POSIX 分支一致（``os.kill(pid, 0)``——0 号信号
    只做存在性/权限检查，不发真信号）。**这一分支在 Windows 上永不执行**：那边
    ``os.kill(pid, 0)`` 会真的发信号/抛错，故走 ``_windows_probe``。
    """
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8", errors="replace")
        fields = stat.rsplit(")", 1)[-1].split()
        return True, f"proc-starttime:{fields[19]}"
    except OSError:
        pass
    except IndexError:
        pass
    try:
        os.kill(int(pid), 0)
    except OSError:
        return False, None
    return True, None


def probe_process(pid: Any) -> tuple[bool, str | None]:
    """探测 pid：(是否存活, 启动时间指纹)。

    指纹取不到时为 ``None``；**任何探测本身的异常都按「活着」上报**——调用方据此
    走保守分支（不回收），绝不会因为探测失败而误杀一个活着的实例。
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False, None
    if pid <= 0:
        return False, None
    try:
        if os.name == "nt":
            return _windows_probe(pid)
        if os.name == "posix":
            return _posix_probe(pid)
    except Exception:                                     # noqa: BLE001 — 见 docstring
        return True, None
    return True, None


class InstanceRegistry:
    """S8：本进程（一个「实例」）的持久身份 + 心跳，以及别人的活性判定。

    文件布局::

        <data_root>/instances/<token>.json     # 每个运行实例一个：pid / 启动指纹 / 心跳
        <data_root>/sessions/<sid>/owner.json  # 该会话由哪个实例创建

    一个数据根可以被多个正在运行的实例共享（``SCRY_DATA``）；
    ``owner_state`` 是 ``recover_orphans`` 唯一的判据。
    """

    def __init__(
        self,
        instances_dir: Path,
        *,
        token: str | None = None,
        pid: int | None = None,
        start_fingerprint: str | None = None,
    ) -> None:
        self.instances_dir = Path(instances_dir)
        self.token = token or secrets.token_hex(8)
        self.pid = os.getpid() if pid is None else int(pid)
        self.start_fingerprint = start_fingerprint
        self.heartbeat_interval = _INSTANCE_HEARTBEAT_INTERVAL
        self.stale_after = _INSTANCE_STALE_AFTER
        self.registered = False
        # 最近一次写失败的原因（诊断用；身份/心跳是旁路，失败绝不抛）。
        self.last_error: str | None = None
        self._started_at: str | None = None
        self._last_write = 0.0
        self._thread: threading.Thread | None = None
        self._stopped = threading.Event()

    # -- 自己的身份 ---------------------------------------------------------- #
    def path_for(self, token: str) -> Path:
        # token 是十六进制串，净化是恒等映射；这里仍走同一套净化，防止它被
        # 当成路径片段注入（token 也可能来自磁盘上的 owner.json）。
        return self.instances_dir / f"{sanitize_path_segment(token, default='instance')}.json"

    @property
    def path(self) -> Path:
        return self.path_for(self.token)

    def register(self) -> bool:
        """写下自己的身份文件；失败返回 False（永不抛）。"""
        if self.start_fingerprint is None:
            self.start_fingerprint = probe_process(self.pid)[1]
        self._started_at = utc_now()
        self.registered = self._write()
        return self.registered

    def heartbeat(self, *, force: bool = False) -> bool:
        """刷新心跳（默认按 ``heartbeat_interval`` 节流）；永不抛。"""
        if not self.registered and not self._write():
            return False
        if not force and time.monotonic() - self._last_write < self.heartbeat_interval:
            return True
        return self._write()

    def _write(self) -> bool:
        payload = {
            "token": self.token,
            "pid": self.pid,
            "start_fingerprint": self.start_fingerprint,
            "started_at": self._started_at or utc_now(),
            "heartbeat_at": utc_now(),
        }
        try:
            self.instances_dir.mkdir(parents=True, exist_ok=True)
            _write_json_atomically(self.path, payload, fsync=False)
        except OSError as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False
        self._last_write = time.monotonic()
        return True

    def start_heartbeat(self) -> None:
        """起一个守护线程周期刷新心跳（幂等）。"""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopped.clear()

        def _beat() -> None:
            while not self._stopped.wait(self.heartbeat_interval):
                self.heartbeat(force=True)

        self._thread = threading.Thread(
            target=_beat, name="webapi-extractor-heartbeat", daemon=True)
        self._thread.start()

    def stop_heartbeat(self) -> None:
        self._stopped.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    # -- 别人的活性 ---------------------------------------------------------- #
    def read_record(self, token: str) -> dict[str, Any] | None:
        """读某个 token 的身份文件；缺失/坏掉一律 None（永不抛）。"""
        if not token:
            return None
        try:
            payload = json.loads(self.path_for(token).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def owner_state(self, token: str | None, *, now: datetime | None = None) -> str:
        """owner 是否还活着：``ALIVE`` / ``DEAD`` / ``UNKNOWN``（判定不了）。

        判定顺序见本模块顶部 S8 的说明；只有 ``DEAD`` 允许回收，``UNKNOWN`` 一律
        按「可能还活着」处理。
        """
        if not token:
            return UNKNOWN
        record = self.read_record(token)
        if not record:
            return UNKNOWN
        reference = now or datetime.now(timezone.utc)
        stamp = _parse_timestamp(record.get("heartbeat_at"))
        if stamp is not None and (reference - stamp).total_seconds() <= self.stale_after:
            # 心跳新鲜：token + 心跳本身就是存活证据（不依赖 pid）。
            return ALIVE
        pid = record.get("pid")
        if not isinstance(pid, int):
            return UNKNOWN
        alive, fingerprint = probe_process(pid)
        if not alive:
            return DEAD
        recorded = record.get("start_fingerprint")
        if not recorded or not fingerprint:
            return UNKNOWN
        # pid 活着但启动时间对不上 → 原进程已死、pid 被复用。
        return ALIVE if recorded == fingerprint else DEAD

    def prune_dead(self) -> list[str]:
        """删掉**可证明已死**实例的身份文件（``UNKNOWN`` 一律保留）。

        只能在 ``recover_orphans`` 之后调用：那时死实例留下的活动会话已经回收完，
        删掉它的身份文件不会让任何会话从 DEAD 退化成 UNKNOWN。
        """
        removed: list[str] = []
        try:
            entries = list(self.instances_dir.iterdir())
        except OSError:
            return removed
        for path in entries:
            if path.suffix != ".json" or path.stem == self.token:
                continue
            record = self.read_record(path.stem)
            if record is None:
                continue
            token = record.get("token") or path.stem
            if token == self.token:
                continue
            if self.owner_state(token) != DEAD:
                continue
            try:
                path.unlink()
            except OSError:
                continue
            removed.append(token)
        return removed


def _write_json_atomically(target: Path, payload: dict[str, Any], *, fsync: bool = True) -> None:
    """同目录临时文件 + ``os.replace`` 原子落盘（会话元数据 / 实例身份共用）。"""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="session-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            if fsync:
                os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class SessionStore:
    def __init__(self, sessions_dir: Path) -> None:
        self.sessions_dir = sessions_dir
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        # 上一次 recover_orphans 里「因 owner 还活着/判不了而**没有**回收」的会话
        # （含原因），供诊断与测试取证：多实例下这里非空才是正确行为。
        self.last_recovery_skipped: list[dict[str, Any]] = []

    def session_path(self, session_id: str) -> Path:
        # D1：session_id 是不可信输入，必须净化成单层安全片段。
        return self.sessions_dir / sanitize_path_segment(session_id, default="unnamed")

    def metadata_path(self, session_id: str) -> Path:
        return self.session_path(session_id) / "session.json"

    # -- S8：会话的 owner（创建它的实例）------------------------------------- #
    def owner_path(self, session_id: str) -> Path:
        return self.session_path(session_id) / _OWNER_FILENAME

    def write_owner(
        self,
        session_id: str,
        *,
        token: str,
        pid: int | None = None,
        start_fingerprint: str | None = None,
    ) -> None:
        """记下「这个会话由哪个实例创建」。

        单独一个 ``owner.json``（不塞进 ``session.json``）有两个原因：会话元数据在
        ``stop()`` / ``_on_browser_closed()`` 等处会被**整体覆盖**写回，塞进去会丢；
        且 ``list_sessions`` 会把 ``session.json`` 原样返回，内部记账字段不该外泄。
        """
        _write_json_atomically(self.owner_path(session_id), {
            "instance_token": token,
            "pid": pid,
            "start_fingerprint": start_fingerprint,
            "recorded_at": utc_now(),
        })

    def read_owner(self, session_id: str) -> dict[str, Any] | None:
        """读会话的 owner 记录；无此文件（旧版本创建的会话）返回 None。"""
        path = self.owner_path(session_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def write_metadata(self, session_id: str, metadata: dict[str, Any]) -> None:
        _write_json_atomically(self.metadata_path(session_id), metadata)

    def read_metadata(self, session_id: str) -> dict[str, Any] | None:
        path = self.metadata_path(session_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _captured_bytes(self, session_id: str) -> int:
        """本会话已落盘的抓包体积（字节）。"""
        path = self.session_path(session_id) / "capture.jsonl"
        try:
            return path.stat().st_size
        except OSError:
            return 0

    def recover_orphans(self, registry: InstanceRegistry | None = None) -> list[str]:
        """回收**确定已死**的实例遗留的活动会话。

        这些会话的浏览器确实已经死了（无法继续抓包），但其 capture.jsonl
        是**逐条落盘的**——数据还在、且可直接分析。因此：

          * 状态置为 stopped（不能再抓），但打上 recovered=true 与
            captured_bytes，让上层知道"这不是白干，数据可以继续分析"；
          * 完全没有数据的会话不标 recovered，避免误导。登录阶段
            （``authenticating``）通常没有数据，于是只落 stopped
            + stop_reason=server_restarted，不会假装"有数据可分析"；
          * 待登录（``authenticating``）也算活动状态：服务在用户登录期间重启
            时，浏览器已经死了，若漏掉它，会话会永远卡在待登录（S1）。

        S8：多实例共享一个数据根时，「活动」**不等于**「孤儿」——另一个正在运行的
        实例完全可能正在抓这个会话。故带 owner 记录的会话只有在
        ``registry.owner_state(token) is DEAD``（心跳过期 **且** 进程不可证明存活，
        见模块顶部的判定顺序）时才回收；``ALIVE`` 与 ``UNKNOWN`` 都跳过，并把跳过
        原因记进 ``self.last_recovery_skipped``。**没有 owner 文件的会话仍按旧行为
        回收**（升级前留下的孤儿不能被永久卡住）。

        返回被回收的 session_id 列表。
        """
        if registry is None:
            # 默认按「会话目录的父目录就是数据根」推断（与 Settings.sessions_dir
            # 一致：data_root/sessions）。只读——不会创建 instances 目录。
            registry = InstanceRegistry(self.sessions_dir.parent / "instances")
        recovered: list[str] = []
        self.last_recovery_skipped = []
        for directory in self.sessions_dir.iterdir():
            if not directory.is_dir():
                continue
            session_id = directory.name
            metadata = self.read_metadata(session_id)
            if not metadata or metadata.get("status") not in ACTIVE_STATES:
                continue

            owner = self.read_owner(session_id)
            owner_token: str | None = None
            if owner is not None:
                owner_token = owner.get("instance_token")
                state = registry.owner_state(owner_token)
                if state != DEAD:
                    # 保守：owner 还活着，或判定不了它是否活着 → 一律不动这个会话。
                    self.last_recovery_skipped.append({
                        "session_id": session_id, "owner": owner_token, "state": state})
                    continue

            stats = self._captured_bytes(session_id)
            metadata["status"] = "stopped"
            metadata["stop_reason"] = "server_restarted"
            metadata["captured_bytes"] = stats
            if owner_token:
                # 留痕：这个会话是被判明已死的实例留下的（对账/排障用）。
                metadata["orphaned_owner"] = owner_token
                metadata["orphaned_owner_state"] = DEAD
            if stats > 0:
                metadata["recovered"] = True
                metadata["recovered_hint"] = (
                    f"服务重启导致抓包中断，但已落盘 {stats / 1024:.1f} KB 数据，"
                    "可直接对该会话调用 analyze_traffic 继续分析。"
                )
            metadata.setdefault("status_history", []).append(
                {"status": "stopped", "ts": utc_now(), "reason": "server_restarted"}
            )
            self.write_metadata(session_id, metadata)
            recovered.append(session_id)
        return recovered

    def list_sessions(self) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        for directory in sorted(self.sessions_dir.iterdir()):
            if directory.is_dir():
                metadata = self.read_metadata(directory.name)
                if metadata:
                    sessions.append(metadata)
        return sessions