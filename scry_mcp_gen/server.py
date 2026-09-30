"""FastMCP entry point and the M1 session lifecycle surface."""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Awaitable, Callable

from fastmcp import FastMCP

from .analyzer import (
    analyze_capture,
    login_post_summary,
    login_query_leads,
    login_query_unknown_count,
    review_suggested_hint,
)
from .audit import AuditLog
from .auth import LoginManager, http_login as perform_http_login
from .capture import CaptureSession
from .config import (
    MAX_RESPONSE_LIMIT_BYTES,
    Settings,
    dropped_response_bodies_hint,
    response_limit_error,
)
from .crypto_analyzer import detect_crypto
from .generator import baked_param_defaults, baked_param_notice, generate, regenerate
from .probe import probe_login as run_probe_login
from .proxy_env import proxy_failure_hint
from .project import (
    DESCRIPTION_SOURCE_USER,
    auth_change_message,
    auth_conflict_message,
    diff_hosts,
    diff_registry,
    endpoint_registry_id,
    export_user_package,
    generation_skip_reasons,
    is_conflict_change,
    load_registry,
    match_key,
    merge_registry,
    session_to_registry_entries,
)
from .storage import ACTIVE_STATES, InstanceRegistry, SessionStore, utc_now


settings = Settings.from_environment()
settings.ensure_directories()
store = SessionStore(settings.sessions_dir)
audit = AuditLog(settings.audit_path)
# S8：本进程的持久身份 + 心跳。多实例共享一个数据根
# （``SCRY_DATA``）时，recover_orphans 只能回收「owner 可证明已消失」
# 的会话——否则实例 A 启动时会把**实例 B 正在抓取**的会话判死/改写。
# 身份是尽力而为的旁路：写不进去（只读磁盘等）也不能让服务起不来，故整体兜异常。
instance = InstanceRegistry(settings.instances_dir)
try:
    instance.register()
    instance.start_heartbeat()
except Exception:                                      # noqa: BLE001 — 见上
    pass
store.recover_orphans(instance)
try:
    # 回收做完之后再删「可证明已死」实例的身份文件（顺序反了会让它们的会话从
    # DEAD 退化成 UNKNOWN，变成永久垃圾）。
    instance.prune_dead()
except Exception:                                      # noqa: BLE001
    pass
mcp = FastMCP("Web API Extractor")
login_manager = LoginManager(settings.auth_states_dir)
capture_sessions: dict[str, CaptureSession] = {}

# Defect D：start() 的等待上限。start() 里既有「起 node 驱动 + 开浏览器」
# （失败很快，几秒内就会抛），也有最长 30 秒的 page.goto。等满全程会把工具调用
# 拖住，所以这里给一个有界等待：窗口内失败 → 如实报错；窗口内没结束（页面加载慢）
# → 照旧返回 initial 状态，稍后的失败仍会落进 metadata（会话已从注册表摘掉）。
_START_UP_WAIT_SECONDS = 15.0


# --------------------------------------------------------------------------- #
# Defect E: 「已请用户确认」的服务端旁证 —— 只提示，绝不拒绝
#
# 文档要求「登录完成必须由用户确认」，但 confirm_login / confirm_login_ready 只是
# 普通工具调用，服务端没有任何证据证明「问过用户」——Agent（或被提示注入的 Agent）
# 可以立刻调它们。硬拒绝会打断文档里的正常流程（在对话里问用户，然后直接调
# confirm_login，未必用过对话框工具），所以这里只做**旁证记录 + 提示**：
#
#   * open_browser_login 返回时（它的提示语本身就是「请用户确认后再调 confirm_login」）、
#   * start_capture 以「等用户确认」状态返回时（同理），
#   * request_login_confirm_dialog / request_capture_confirm_dialog 真的把对话框
#     弹到了用户面前时（点「是」点「否」都算问过了），
#
# 各记一笔；confirm_login / confirm_login_ready 成功时若查无此记录，就在响应里
# 附上 confirmation_evidence="none" + confirmation_warning，**字段与成功语义一律不变**。
# 记录只在进程内存里（重启后登录会话本就失效，无需持久化）。
# --------------------------------------------------------------------------- #
_confirmation_requests: dict[str, str] = {}
_MAX_CONFIRMATION_RECORDS = 1024


def _note_confirmation_request(session_id: str | None, source: str) -> None:
    """记下「某个会话已经请过用户确认」。"""
    if not session_id:
        return
    _confirmation_requests[session_id] = source
    while len(_confirmation_requests) > _MAX_CONFIRMATION_RECORDS:
        _confirmation_requests.pop(next(iter(_confirmation_requests)))


def _confirmation_evidence(session_id: str | None) -> dict[str, Any]:
    """确认类工具成功响应要附加的旁证字段（只加字段，不改任何既有字段）。"""
    if _confirmation_requests.get(session_id or ""):
        return {"confirmation_evidence": "requested"}
    return {
        "confirmation_evidence": "none",
        "confirmation_warning": "no_confirmation_request_recorded",
        "confirmation_message": (
            "服务端没有记录到任何「已请用户确认」的动作：既没有 open_browser_login / "
            "start_capture 返回过「请用户确认」的流程，也没有弹出过确认对话框。"
            "请确认确实问过用户、并得到用户答复后再继续（不阻止，只是提示）。"
        ),
    }


def _canonical_session_id(session_id: str) -> str:
    """把调用方给的 ``session_id`` 收敛成**磁盘上的那个目录名**（唯一身份）。

    Defect A：``store.session_path`` 会用 ``sanitize_path_segment`` 把不可信 id
    净化成单层路径片段，而 ``capture_sessions`` 此前按**原始输入**做键，于是
    ``start_capture(session_id="my session")`` 与
    ``start_capture(session_id="my_session_b405683d")`` 是两个不同的键、却是
    **同一个目录**：两个 CaptureSession 往同一份 capture.jsonl / session.json
    里追加，analyze_traffic 对任一 id 都会把两份流量一起分析；而 stop_capture 等
    走 dict 的工具对「净化后的拼写」只会回 capture_session_not_found。

    这里统一以「磁盘目录名」为唯一身份（``sanitize_path_segment`` 是幂等的，
    合法 id 原样返回，故对默认路径 ``new_session_id()`` 是 byte-identical 的
    空操作）。策略：**别名即同一会话**，第二个调用按 ``session_already_exists``
    拒绝——不新建目录、不共享目录。原始输入若与规范化结果不同，会在元数据里
    留下 ``requested_session_id`` 供追溯。
    """
    return store.session_path(session_id).name


def _add_confirmation_evidence(result: dict[str, Any], session_id: str | None) -> dict[str, Any]:
    """给「确认类」工具的成功响应补上旁证字段（只加字段，语义一律不变）。"""
    for key, value in _confirmation_evidence(session_id).items():
        result.setdefault(key, value)
    return result


async def _release_failed_capture(capture: CaptureSession) -> None:
    """回收 ``start()`` 失败后留下的后台任务与半启动的浏览器（Defect D）。

    属性名一律用 ``getattr``：``browser`` / ``playwright`` 要等 start() 走到对应
    那一步才存在。每一步都单独兜住异常——**清理失败绝不能掩盖原始错误**（原始
    错误已经写进 metadata 与 ``capture.start_error``）。
    """
    for name in ("writer_task", "idle_task", "login_task"):
        task = getattr(capture, name, None)
        if not isinstance(task, asyncio.Task) or task.done():
            continue
        # writer 的唯一出口是 status == "stopping"，这条失败路径永远不会走到——
        # 不取消它，它就在后台空转一辈子，用户每重试一次就多一份。
        task.cancel()
        try:
            await task
        except (Exception, asyncio.CancelledError):
            pass
    browser = getattr(capture, "browser", None)
    if browser is not None:
        try:
            await browser.close()
        except Exception:
            pass
    playwright = getattr(capture, "playwright", None)
    if playwright is not None:
        try:
            await playwright.stop()
        except Exception:
            pass


async def _start_capture(capture: CaptureSession) -> None:
    try:
        await capture.start()
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        capture.status = "failed"
        capture.stop_reason = "startup_failed"
        capture.start_error = error
        # 调用侧的代理诊断：抓包侧（capture.py）在导航失败时已把代理提示写进消息，
        # 这里再显式取一份结构化结果，供响应里单列（便于 Agent/使用者一眼看到
        # 「可能是代理，可切成直连/系统代理」），而不是埋在长 traceback 文本里。
        # 契约借鉴 mcp_call.py：诊断只追加，不改变成功/失败语义与既有字段。
        capture.start_proxy_hint = getattr(exc, "proxy_hint", None)
        # 立刻摘掉：这个会话没有浏览器、没有开始抓包，留在注册表里只会让
        # get_capture_status / list_sessions / 上限检查把它当成活的（僵尸会话）。
        capture_sessions.pop(capture.session_id, None)
        metadata = capture.metadata()
        metadata["error"] = error
        try:
            store.write_metadata(capture.session_id, metadata)
        except OSError:
            pass
        await _release_failed_capture(capture)


def audited(function: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
    @wraps(function)
    async def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        params = {**dict(zip(function.__code__.co_varnames, args)), **kwargs}
        # S8：每次工具调用顺带刷一次心跳（内部按 15 秒节流）。这样即使这个实例长
        # 时间没人碰（空闲线程仍会刷，双保险），心跳也始终贴近「最近一次活动」，
        # 别的实例更不会把它看成可疑的孤儿 owner。
        try:
            instance.heartbeat()
        except Exception:                                  # noqa: BLE001 — 心跳失败不影响工具
            pass
        try:
            result = await function(*args, **kwargs)
        except Exception as exc:
            result = {"success": False, "error": f"{type(exc).__name__}: {exc}"}
        audit.record(function.__name__, params, result)
        return result

    return wrapper


def new_session_id(url: str) -> str:
    host = url.split("//", 1)[-1].split("/", 1)[0].replace(":", "_") or "unknown"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{timestamp}_{host}_{secrets.token_hex(2)}"


@mcp.tool()
@audited
async def probe_login(url: str) -> dict[str, Any]:
    return await run_probe_login(url)


@mcp.tool()
@audited
async def http_login(
    url: str,
    username: str,
    password: str,
    login_endpoint: str | None = None,
) -> dict[str, Any]:
    return await perform_http_login(url, username, password, settings.auth_states_dir, login_endpoint)


@mcp.tool()
@audited
async def open_browser_login(url: str, timeout_seconds: int = 300) -> dict[str, Any]:
    result = await login_manager.open(url, timeout_seconds)
    # Defect E：这条提示语本身就是「请用户确认后再调 confirm_login」的请求，
    # 记一笔旁证（confirm_login 时用来判断「到底有没有请过用户」）。
    _note_confirmation_request(result.get("login_session_id"), "open_browser_login")
    return result


@mcp.tool()
@audited
async def get_login_status(login_session_id: str) -> dict[str, Any]:
    return login_manager.status(login_session_id)


@mcp.tool()
@audited
async def start_capture(
    url: str,
    auth_state_path: str | None = None,
    session_id: str | None = None,
    response_limit_bytes: int | None = None,
) -> dict[str, Any]:
    """打开浏览器并开始记录该会话的网络流量（写入 ``<会话目录>/capture.jsonl``）。

    数据写到哪去：本工具只产出 ``capture.jsonl``（与 ``session.json`` 元数据），
    **不产出、也不分析** ``analysis.json`` —— 要拿结论得另调 `analyze_traffic`，
    要出项目再调 `generate_mcp_server`（它读的是 analyze_traffic 写的那份 analysis.json）。

    ``response_limit_bytes``（**可选**）：本次抓包的单条响应体 / 请求体 / WebSocket 帧
    体积上限（字节）。**不传就沿用服务的默认上限（256 KB），行为与以前完全一致**。
    它在两种情况下用得上：

    - 上一轮抓包有响应体因超限被**整条丢弃**（会话元数据 / `analyze_traffic` 里的
      ``dropped_response_bodies`` 与 ``dropped_response_bodies_hint`` 会报出来，端点条目
      上带 ``response_body_dropped: true``）—— 提示语里会给一个可照抄的建议值，照着传即可；
    - 你已经知道目标站点某些接口的响应很大。

    合法范围 ``1 ~ 67108864``（64 MB，见 ``config.MAX_RESPONSE_LIMIT_BYTES``）。
    非法值（0 / 负数 / 非整数 / 超过上限）**不会**开始抓包，直接返回
    ``error="invalid_response_limit_bytes"`` 与一句说明合法范围、该怎么办的 ``message``。
    """
    limit_error = response_limit_error(response_limit_bytes)
    if limit_error:
        # 校验在**任何副作用之前**（不开浏览器、不建会话、不写注册表）：参数写错时
        # 不能留下一个半启动的会话，也不能让错误推迟到抓包中途才爆出来。
        return {
            "success": False,
            "error": "invalid_response_limit_bytes",
            "response_limit_bytes": response_limit_bytes,
            "limit_range": {"min": 1, "max": MAX_RESPONSE_LIMIT_BYTES},
            "message": limit_error,
        }
    # 「活的」以 storage.ACTIVE_STATES 为准（含 authenticating：等用户登录的会话
    # 同样占着一个真浏览器）。此前这里抄了一份少了 authenticating 的字面量，
    # 两边一旦分叉，等登录的会话就不计入上限，可以无限开浏览器。
    active = [item for item in store.list_sessions() if item.get("status") in ACTIVE_STATES]
    if len(active) >= settings.max_sessions:
        return {"success": False, "error": "session_limit_reached", "active_sessions": active}
    requested_session_id = session_id or new_session_id(url)
    # Defect A：键与目录都必须是同一个规范 id（别名 = 同一会话 → 直接拒绝）。
    session_id = _canonical_session_id(requested_session_id)
    if session_id in capture_sessions:
        return {"success": False, "error": "session_already_exists", "session_id": session_id}
    # 上限真正生效的地方在这一行：CaptureSession 拿它判每一条响应体 / 请求体 / WS 帧
    # 要不要整条落盘（capture.py）。不传时用的仍是 Settings（= 环境变量 / 默认值），
    # 所以对既有调用方这一行与改动前等价。
    effective_limit = (settings.response_body_limit if response_limit_bytes is None
                       else response_limit_bytes)
    capture = CaptureSession(session_id, url, store, effective_limit, settings.idle_timeout_seconds,
                             auth_state_path, settings.proxy_mode,
                             response_limit_explicit=response_limit_bytes is not None)
    capture_sessions[session_id] = capture
    initial_status = "authenticating" if auth_state_path is None else "capturing"
    metadata = {
        "session_id": session_id,
        "url": url,
        "auth_state_path": auth_state_path,
        "status": initial_status,
        "created_at": utc_now(),
        "status_history": [{"status": initial_status, "ts": utc_now()}],
        "endpoint_count": 0,
    }
    if requested_session_id != session_id:
        # 调用方给的是别名（需要净化才成为合法目录名）：留痕，便于对账。
        metadata["requested_session_id"] = requested_session_id
    if response_limit_bytes is not None:
        # 显式指定过上限才记（默认路径的元数据形状不变）。首份 session.json 也要带上：
        # 它和之后由 CaptureSession.metadata() 覆写的那份必须给出同一个值。
        metadata["response_limit_bytes"] = effective_limit
    try:
        # S8：先把 owner 记下来，再写元数据。顺序很重要——没有 owner 文件的会话
        # 会被任何实例的 recover_orphans 按「旧版本遗留」回收，所以绝不能让一个
        # 新会话处于「有元数据、没 owner」的状态。
        store.write_owner(
            session_id,
            token=instance.token,
            pid=instance.pid,
            start_fingerprint=instance.start_fingerprint,
        )
        store.write_metadata(session_id, metadata)
    except Exception:
        # 元数据都写不下去（磁盘满/权限）时没有会话可言：不许把一个连状态都
        # 存不下的 CaptureSession 留在注册表里（Defect D 的同一条原则）。
        capture_sessions.pop(session_id, None)
        raise
    startup = asyncio.create_task(_start_capture(capture))
    try:
        # 有界等待：失败就如实报错（见下），慢启动则不阻塞工具调用。
        await asyncio.wait_for(asyncio.shield(startup), timeout=_START_UP_WAIT_SECONDS)
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass  # _start_capture 自己吞异常并落到 start_error，这里只防御
    start_error = getattr(capture, "start_error", None)
    if start_error:
        # Defect D：启动失败不得再告诉 Agent「浏览器已打开，请去登录」——
        # 那条指令会把用户带到一扇不存在的窗口前，Agent 只会不断重试并堆积
        # 孤儿 node 驱动。这里如实说明失败原因，且不出现任何「登录」指令。
        # 调用侧的**代理诊断**：抓包侧已把提示写进 detail（BrowserNavigationError）；
        # 这里优先用它，取不到再从错误文本里现推一份（launch 阶段失败等）。命中代理
        # 形态时把可行动建议单列成 ``proxy_hint`` 并追加到 message —— 否则使用者只看到
        # net::ERR_EMPTY_RESPONSE，根本想不到是系统代理。
        proxy_hint = (getattr(capture, "start_proxy_hint", None)
                      or proxy_failure_hint(start_error, mode=settings.proxy_mode))
        message = (
            "抓包会话启动失败：浏览器没有打开，也没有开始记录，该会话已从会话表里移除。"
            "请先修好本机环境（可用 doctor 查看诊断）后再重试。"
        )
        response = {
            "success": False,
            "error": "capture_start_failed",
            "session_id": session_id,
            "detail": start_error,
            "message": message,
        }
        if proxy_hint:
            response["proxy_hint"] = proxy_hint
            response["message"] = f"{message}{proxy_hint}"
        return response
    if initial_status == "authenticating":
        # 这条提示语就是「请用户确认」的请求，为 Defect E 记一笔旁证。
        _note_confirmation_request(session_id, "start_capture")
        message = (
            "浏览器已打开。请让用户先完成登录，**等用户确认已登录后**再调用 "
            "confirm_login_ready(session_id)，我才会开始记录；在那之前不记录任何流量。"
            "（get_capture_status 里的 auth_evidence 只是旁证，**不会自动开始记录**。）"
        )
    else:
        message = "请让用户正常操作网站，完成后回来告诉我或调用 stop_capture() 完成收集。"
    response: dict[str, Any] = {"session_id": session_id, "status": initial_status,
                                "message": message}
    fallback = getattr(capture, "proxy_fallback", None)
    if fallback:
        # R3：自动回退**发生了就必须说出来**。用户（和 Agent）只看到「成功了」，就无从
        # 知道服务在背后换了代理方式；下次换个站点失败时，他连「代理会自动切换」这件事
        # 都不知道，也就无从排查。结构化字段与 message 里的话**都**给。
        response["proxy_fallback"] = {"from": fallback["from"], "to": fallback["to"]}
        response["message"] = f"{message}{fallback['message']}"
    return response


@mcp.tool()
@audited
async def get_capture_status(session_id: str) -> dict[str, Any]:
    session_id = _canonical_session_id(session_id)
    if session_id in capture_sessions:
        return capture_sessions[session_id].metadata()
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    return metadata


@mcp.tool()
@audited
async def stop_capture(session_id: str) -> dict[str, Any]:
    session_id = _canonical_session_id(session_id)
    if session_id in capture_sessions:
        return await capture_sessions[session_id].stop("agent_requested")
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    if metadata.get("status") in {"stopped", "failed"}:
        return metadata
    metadata["status"] = "stopped"
    metadata["stop_reason"] = "agent_requested"
    metadata.setdefault("status_history", []).append({"status": "stopped", "ts": utc_now()})
    store.write_metadata(session_id, metadata)
    return metadata


@mcp.tool()
@audited
async def resume_capture(session_id: str) -> dict[str, Any]:
    session_id = _canonical_session_id(session_id)
    if session_id in capture_sessions:
        await capture_sessions[session_id].resume()
        return capture_sessions[session_id].metadata()
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    if metadata.get("status") != "paused":
        return {"success": False, "error": "session_not_paused", "status": metadata.get("status")}
    metadata["status"] = "capturing"
    metadata.setdefault("status_history", []).append({"status": "capturing", "ts": utc_now()})
    store.write_metadata(session_id, metadata)
    return metadata


@mcp.tool()
@audited
async def list_sessions() -> dict[str, Any]:
    return {"sessions": store.list_sessions()}


# S23：摘要**逐条列表的上限**。摘要是喂给 LLM 的（不是给人翻的完整报告），
# 大规模抓包（实测 300 个端点 ≈ 81 KB ≈ 20K tokens）会把上下文撑爆，而其中的
# 绝大多数是「这条接口叫什么、在哪个路径」的重复信息。超过上限时**有损但可解释**：
# 只列前 N 条，并在 `truncated` 里写明每个列表被省略了多少条 —— 被省略的部分在
# 完整的 analysis.json 里**一条不少**，所以信息没有丢，只是没塞进上下文。
# 上限只影响「列出来看」的部分，**不影响生成**：不传 endpoint_ids 时所有端点照旧生成。
SUMMARY_ENDPOINT_CAP = 150
SUMMARY_SIDE_LIST_CAP = 100


def _capped(items: list[dict[str, Any]], cap: int) -> tuple[list[dict[str, Any]], int]:
    """截到 cap 条，返回 (保留的列表, 被省略的条数)。cap<=0 表示不截。"""
    if cap <= 0 or len(items) <= cap:
        return items, 0
    return items[:cap], len(items) - cap


def _truncation_hint(omitted: dict[str, int], full_result_path: str) -> str:
    """把「省略了多少条、去哪找」写成一句给使用者看的话（S23）。"""
    if not omitted:
        return ""
    parts = "、".join(f"{key} {count} 条" for key, count in omitted.items())
    return (f"摘要为控制体积只列出了部分内容（省略：{parts}）。被省略的部分没有丢，"
            f"完整清单在 {full_result_path} 里可以查到；生成时不指定 endpoint_ids "
            "仍会把全部**可生成的**端点都生成出来（被标记跳过的照旧跳过）。")


@mcp.tool()
@audited
async def analyze_traffic(session_id: str) -> dict[str, Any]:
    """分析会话流量，返回一份**精简**摘要（完整结果含 schema，留在 analysis.json）。

    数据从哪来、写到哪去：本工具**从磁盘读这一次抓包的 `capture.jsonl`**（不读内存里
    的实时流量），把完整分析结果**覆写**进 ``<会话目录>/analysis.json``，并且只把一份
    精简摘要返回给调用方。因此可以重复调用（幂等，每次按当前 capture.jsonl 重算），
    而 `generate_mcp_server` / `diff_capture` / `merge_capture` 读的都是这份 analysis.json
    —— **抓包有新流量后必须重新调一次本工具**，否则后续工具用的还是上一版结论。

    顶层字段：

    - ``session_id`` / ``base_url`` / ``full_result_path``：会话标识与完整结果位置；
    - ``stats``：整机统计（``insufficient_samples`` 是**样本不足端点的个数**）；
    - ``host_counts`` / ``auth_schemes``：按 host 聚合的端点数与认证方式
      （``auth_schemes[host]`` 含主机级的 ``scheme`` / ``cookie_names`` /
      ``schemes`` —— ``schemes`` 列出该域名下**观测到的全部**方式，混用时不止一个）；
    - ``endpoints``：每个端点的衔接键 ``endpoint_id`` + ``method`` / ``host`` /
      ``path`` / ``auth_required`` / ``auth_hint`` / ``sample_count`` / ``description``
      （可选 ``review_suggested`` + ``review_suggested_hint`` / ``file_response`` /
      ``response_body_dropped``）；
    - ``not_generated``：生成阶段会跳过的端点 + 原因（衔接键 + 路径 + 原因，无 schema）；
    - ``needs_more_samples``：**证据不足的端点**（不同请求数 < 2，任何参数都分类不了）。
      只有衔接键 + 位置 + ``distinct_request_count``，没有 schema / 样本值 / 请求体；
      需要它们时让用户再用一次该功能再重新抓包分析。无此情况时为**空列表**；
    - ``auth_login_query_leads``：登录 query 参数的来源判定里**可行动**的那几条 ——
      ``class`` 为 ``suspected_response``（值疑似来自前面某个响应）且**真给出了来源端点**。
      每条只带 ``param`` / ``class`` / ``suspected_source`` / ``needs_confirmation`` /
      ``auto_fill`` / ``note``，**绝不带取值**。``auto_fill`` 是生成阶段会发射的**取用计划**
      （``{from: "GET https://…", field: "$.data.csrf"}``）：生成的服务会在登录前**自动**
      调这个接口取值，使用者什么都不用填；``auto_fill`` 为 ``null`` 时表示这次不满足自动
      取用条件（来源需要鉴权 / 需要参数 / 不是 GET / 字段定位不到），生成器会把该参数降级为
      必填并在文档里说明，``note`` 里写了原因。无此类线索时为**空列表**（与
      ``needs_more_samples`` 同风格，消费方可无条件读它）；
    - ``auth_login_post_login``：「这个站点能不能靠构造请求登录」的结论（两层判据：
      静态信号 + `http_login` 的**实测**结果，后者优先）。`verdict` 为 `post_ok`
      （产物里有 `login()` 与 401 自动重登录）或 `interactive`（产物里是**自带的交互式
      登录**：`login_interactive()` / `get_login_status()` / `confirm_login()`，
      由用户在弹出的真实浏览器窗口里完成验证）；`basis` 说明结论来自 `measured` 还是
      `static`，`signals` 列出静态信号，`measured_reason` 是实测失败的原因码
      （如 `interactive_required`）。无登录接口时各字段为 `None` / 空列表（键常驻）；
    - ``auth_login_query_unknown_count``：上面被滤掉的「不可知」条目**个数**（聚合计数，
      不逐条列）。「不可知」是常态（登录前必然先加载 HTML/JS/图片），逐条列只会每个登录
      query 参数一条、既不指向行动又制造噪音；逐参数的完整细节在 ``analysis.json`` 的
      ``auth_login["query_param_provenance"]`` 里。无登录 query 参数时为 ``0``；
    - ``baked_param_defaults`` / ``baked_param_notice``：**哪些参数沿用了抓包时的取值作
      默认值**（只给参数名与端点，**不含取值** —— 取值进 LLM 上下文既噪音又多一个泄漏面）。
      生成时同样会把这些参数写进子项目的 README。分享这个 MCP 给他人前应检查它们。
      **取值会切换响应形态的参数（`count` / `pagesize` / `bulkbindings` / `filter` / `page` /
      `sort` / `format` …，以及取值为 `yes`/`no`/`true`/`false`/`on`/`off` 的）不在其中**：
      它们一律不烘快照值 —— **实测过会切换形态的**（`behaviour_switch` 为 `True`）是必填，
      **只是名字/取值像开关、没有实测证据的**是可选、无默认值（不传就**不发**这个键，服务端
      用自己的默认值）—— 并在工具文档字符串里说明（见 `docs/reference.md` 的
      「取值会切换响应形态的参数」）—— 别把没烘的说成烘了。
      无此类参数时为空列表 / 空串；
    - ``dropped_response_bodies`` / ``dropped_response_bodies_hint``：有多少个接口的
      响应体因为**超过体积上限被整条丢弃**（因此推断不出响应结构），以及一句可行动的
      补救提示 —— 里面写着**下一步该做什么**：重新调 ``start_capture`` 并传一个具体的
      ``response_limit_bytes`` 值，然后再跑一次本工具。端点条目上对应
      ``response_body_dropped: true``。没有丢弃时为 ``0`` / 空串；
    - ``truncated`` / ``truncated_hint``：摘要为控制体积对长列表做了**有损**截断 ——
      ``truncated`` 给出每个列表被省略的条数，``truncated_hint`` 说明去哪里查完整清单
      （``full_result_path`` 的 analysis.json 里一条不少），并说明**生成不受影响**
      （不传 endpoint_ids 仍会生成全部端点）。没有省略时为 ``{}`` / 空串；
    - ``crypto_found``：是否检测到疑似加密参数。
    """
    # Defect A：一律以规范 id 回应（下面的 session_id 与 full_result_path 里的目录名
    # 必须是同一个字符串，否则 Agent 把摘要里的 id 喂回 stop_capture 会找不到会话）。
    session_id = _canonical_session_id(session_id)
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    result = analyze_capture(
        store.session_path(session_id),
        response_bytes_threshold=settings.noise_response_bytes,
        sample_count_threshold=settings.noise_sample_count,
    )
    crypto = detect_crypto(store.session_path(session_id), result)
    # Return a compact summary — the full result (schemas etc.) stays in analysis.json.
    host_counts: dict[str, int] = {}
    digest: list[dict[str, Any]] = []
    # F5：生成阶段会**跳过**这些端点。此前摘要里对它们只字不提，于是 Agent 在
    # 摘要里看到的端点到生成时凭空消失、任何地方都没有原因。这里单独列出来
    # （只给衔接键 + 路径 + 原因，不带 schema，保持精简），Agent 可以据此
    # 向用户交代「这些没有被生成，以及为什么」。
    not_generated: list[dict[str, Any]] = []
    # 参数分类规则要求「≥2 个不同请求」；少于它则该端点任何参数都分类不了。
    # stats.insufficient_samples 只给**个数**，Agent 无从得知是**哪些**端点需要用户
    # 再操作一次（只能去翻 analysis.json，那不是主界面）。这里补一份精简清单：
    # 只给衔接键 + 位置 + 不同请求数，不带 schema / 样本值 / 请求体，避免摘要重新膨胀。
    needs_more_samples: list[dict[str, Any]] = []
    for endpoint in result.get("endpoints", []):
        host_counts[endpoint["host"]] = host_counts.get(endpoint["host"], 0) + 1
        entry = {
            "endpoint_id": endpoint_registry_id(endpoint), "method": endpoint["method"],
            "host": endpoint["host"], "path": endpoint["path"],
            "auth_required": endpoint.get("auth_required"),
            # S13：这条端点**自己**实测到的鉴权方式（Bearer / Basic / cookie）。
            # 同一域名下不同接口可以不一样 —— 布尔回答「要不要凭据」，这里回答
            # 「要哪一种」，生成物据此逐端点发 Authorization 或 Cookie。
            "auth_hint": endpoint.get("auth_hint"),
            "sample_count": endpoint.get("sample_count"),
            "description": endpoint.get("description"),
        }
        if endpoint.get("review_suggested"):
            # 只是「待复核」，不会让端点消失——挂在端点自己身上，不混进 not_generated。
            # S19：以前只给一个裸 `true`，使用者不知道「为什么值得看一眼」。这里附上
            # 人话解释（体积大 / 请求频繁），阈值仍然只标记、绝不丢弃。
            entry["review_suggested"] = True
            hint = review_suggested_hint(endpoint.get("review_reasons"))
            if hint:
                entry["review_suggested_hint"] = hint
        if endpoint.get("response_body_dropped"):
            # S20：这个接口的响应体**没抓到**（超过体积上限被整条丢弃），所以推断不出
            # 响应结构。必须在摘要里说清，否则 LLM 会据不完整的数据猜出错的参数。
            entry["response_body_dropped"] = True
        if endpoint.get("file_response"):
            # Fix 1：文件/流式响应端点（响应不是 JSON，但**不会被跳过**，生成的是
            # 「原样返回响应体」的工具）。在摘要里就标出来，免得被当成数据接口。
            entry["file_response"] = True
        digest.append(entry)
        if endpoint.get("insufficient_samples"):
            needs_more_samples.append({
                "endpoint_id": entry["endpoint_id"], "method": endpoint["method"],
                "host": endpoint["host"], "path": endpoint["path"],
                "distinct_request_count": int(endpoint.get("distinct_request_count") or 0),
            })
        reasons = generation_skip_reasons(endpoint)
        if reasons:
            not_generated.append({
                "endpoint_id": entry["endpoint_id"], "method": endpoint["method"],
                "host": endpoint["host"], "path": endpoint["path"],
                "reason": reasons[0], "reasons": reasons,
                "detail": endpoint.get("not_callable_reason") if
                "not_independently_callable" in reasons else None,
            })
    baked_full = baked_param_defaults(result.get("endpoints"), result.get("auth_login"))
    # notice 由**完整清单**聚合（只含去重后的参数名），故即便下面的明细被截断，
    # 「分享前要检查哪些参数」这句话依然完整 —— 这是它与明细列表的分工。
    baked_notice = baked_param_notice(baked_full)
    # S23：逐条列表一律截到上限，并如实报出「省略了多少条」（键常驻，消费方可无条件读）。
    full_result_path = str(store.session_path(session_id) / "analysis.json")
    digest, digest_omitted = _capped(digest, SUMMARY_ENDPOINT_CAP)
    not_generated, not_generated_omitted = _capped(not_generated, SUMMARY_SIDE_LIST_CAP)
    needs_more_samples, needs_more_omitted = _capped(needs_more_samples, SUMMARY_SIDE_LIST_CAP)
    baked, baked_omitted = _capped(baked_full, SUMMARY_SIDE_LIST_CAP)
    truncated = {}
    for key, count in (("endpoints", digest_omitted),
                       ("not_generated", not_generated_omitted),
                       ("needs_more_samples", needs_more_omitted),
                       ("baked_param_defaults", baked_omitted)):
        if count:
            truncated[key] = count
    # S20：整机有多少个响应体被整条丢弃 —— 顶层给计数 + 一句可行动的话；无则为 0 / 空串，
    # 消费方可以无条件读。局限说明在 stats 里也有一份针对端点的计数。
    dropped_bodies = int((result.get("stats") or {}).get("response_body_dropped") or 0)
    summary = {
        "session_id": session_id,
        "stats": result.get("stats"),
        "base_url": result.get("base_url"),
        "host_counts": host_counts,
        "auth_schemes": (result.get("auth_metadata", {}) or {}).get("auth_schemes", {}),
        "endpoints": digest,
        "not_generated": not_generated,
        # 证据不足（不同请求数 < 2）的端点；无事可报时是空列表，消费方可以无条件读它。
        "needs_more_samples": needs_more_samples,
        # (a) 类「来源判定」：登录 query 参数的值疑似来自前面哪个响应（见
        # analyzer.analyze_query_param_provenance）。**只带可行动的**：class 为
        # suspected_response 且真给出了来源端点的那几条；带参数名 / 来源端点 / `auto_fill`
        # 取用计划 / 一句话说明，**绝不**带取值（避免二次泄漏，也避免被当成"可以烘的值"）。
        # `auto_fill` 非空 = 生成的服务会在登录前自己取（使用者什么都不用填）。
        # 两个键都**常驻**（无事可报时是空列表 / 0），风格同 needs_more_samples —— 消费方
        # 可以无条件读它们，不必先判键在不在。「不可知」整类只给聚合计数：它是常态（登录前
        # 必然先加载 HTML/JS/图片），逐条列就是每个登录 query 参数一条、既不指向行动又制造
        # 噪音；逐参数细节留在 analysis.json 的 auth_login["query_param_provenance"]。
        "auth_login_query_leads": login_query_leads(result.get("auth_login")),
        "auth_login_query_unknown_count": login_query_unknown_count(result.get("auth_login")),
        # 「能不能靠构造请求登录」的结论（两层判据见 analyzer.login_post_verdict）。
        # 生成期据此决定产物里是账号密码登录还是**自带的交互式登录**（弹浏览器窗口）；
        # 键常驻（无登录接口时各字段为 None / 空列表），消费方可无条件读它。
        "auth_login_post_login": login_post_summary(result.get("auth_login")),
        # R1：哪些参数把抓包取值当成了默认值 —— **只给参数名 + 端点**，绝不带取值。
        # 让 Agent 能在对话里直接告诉使用者「分享之前检查这几个参数」。
        "baked_param_defaults": baked,
        "baked_param_notice": baked_notice,
        # S20：有响应体被整条丢弃时的计数与可行动提示（无则 0 / 空串，键常驻）。
        # 本工具是**无状态**的（只读磁盘上的 capture.jsonl），所以「当前上限」取会话元数据里
        # 记下的那次真正生效的值（start_capture 显式传过 response_limit_bytes 才有这个键）；
        # 没有就用全局默认值 —— 否则显式调大过上限的会话会看到一句数值错误、照做也不生效的提示。
        "dropped_response_bodies": dropped_bodies,
        "dropped_response_bodies_hint": dropped_response_bodies_hint(
            dropped_bodies,
            int(metadata.get("response_limit_bytes") or settings.response_body_limit)),
        # S23：因体积上限被省略的条数与去处说明（无省略时为 {} / 空串，键常驻）。
        "truncated": truncated,
        "truncated_hint": _truncation_hint(truncated, full_result_path),
        "crypto_found": bool(crypto.get("found")),
        "full_result_path": full_result_path,
    }
    return summary


@mcp.tool()
@audited
async def update_endpoint(
    session_id: str,
    endpoint_id: str,
    description: str | None = None,
    notes: str | None = None,
    param_provenance: dict | None = None,
) -> dict[str, Any]:
    session_id = _canonical_session_id(session_id)
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"success": False, "error": "analysis_not_found", "session_id": session_id}
    import json
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    for endpoint in analysis.get("endpoints", []):
        if endpoint.get("endpoint_id") == endpoint_id:
            if description is not None:
                endpoint["description"] = description
                # F7：标记「这条描述是人写的」。merge_registry 只刷新非用户来源的
                # 描述，标记随 registry.json 落盘，用户改过的描述不会再被静默覆盖。
                endpoint["description_source"] = DESCRIPTION_SOURCE_USER
            if notes is not None:
                endpoint["notes"] = notes
            if param_provenance is not None:
                # 逐参数溯源（origin + impact）：记录「这个可变参数从哪来、影响什么」。
                # 生成器把它写进工具文档字符串（见 _provenance_note），调用方 LLM
                # 才知道该传什么。键是参数名，值可以是 {"origin":…, "impact":…} 或
                # 一段说明文字。按参数逐个并入，不整体覆盖 —— 分多次补充不会丢。
                merged = dict(endpoint.get("param_provenance") or {})
                merged.update(param_provenance)
                endpoint["param_provenance"] = merged
                endpoint["param_provenance_source"] = DESCRIPTION_SOURCE_USER
            analysis_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
            return endpoint
    return {"success": False, "error": "endpoint_not_found", "endpoint_id": endpoint_id}


@mcp.tool()
@audited
async def generate_mcp_server(
    session_id: str,
    output_dir: str,
    endpoint_ids: list[str] | None = None,
    include_endpoint_ids: list[str] | None = None,
    language: str = "python",
    framework: str = "fastmcp",
) -> dict[str, Any]:
    """生成 registry 项目（server.py / registry.json / README.md …）。

    - `endpoint_ids`：只生成这些衔接键（analyze_traffic 摘要里的 `endpoint_id`）；
      不传则生成全部保留端点。键按端点自带的 `endpoint_id` 解析，**未知或会被跳过
      的键一律报 `Unknown endpoint_ids`**（不静默换成别的端点）。
    - `include_endpoint_ids`：显式点名包含。你复核过 `not_generated`、决定某条
      「本该被跳过」的端点（噪音 / 不可独立调用 / 非 JSON 响应）确实要，就把它的
      `endpoint_id` 填在这里 —— 它绕过全部跳过规则照常生成，registry 条目带
      `forced_include: true`，生成的 README 会单列一节说明它为什么在。
      与 `endpoint_ids` 取并集。返回值里的 `forced_include` 列出实际生效的键
      （拼错的键不会被静默忽略而不报）。

    业务文件下载端点（响应是 CSV / PDF / XLSX / ZIP 等，无 JSON schema）会生成
    「原样返回响应体」的工具（文本在 `text`、二进制在 `base64`），README 的清单里
    带 `[FILE]` 标记 —— 这类端点的响应本来就不是 JSON，不该被当成「非 JSON 页面」
    丢掉。

    `output_dir` 里已经有项目时**不会拒绝**：那次生成会先把整个目录**整份备份**到旁边的
    `<dir>.bak-<时间戳>`，再照常覆盖（一次性生成是「analysis.json → 新项目」，会把旧
    registry 重建）。返回值里的 `backup_path` / `message` 会指明备份落在哪 ——
    **把这句话如实转告使用者**，别让他以为旧数据没了。续作更推荐 `regenerate_server`
    或 `diff_capture` → `merge_capture`（只增不减）。

    返回值还带 `param_defaults` / `param_defaults_notice`：哪些参数沿用了抓包取值作默认值
    （**只有参数名与端点，没有取值**）。分享这个 MCP 给他人前该检查什么，照这句告诉使用者。
    取值会切换响应形态的参数（`count` / `pagesize` / `bulkbindings` / `filter` / `page` /
    `sort` / `format` …，以及取值为 `yes`/`no`/`true`/`false`/`on`/`off` 的）**不在这份名单
    里**：它们一律不烘，并在工具文档字符串里说明 —— **实测过会切换形态的**（`behaviour_switch`
    为 `True`）是必填，**只是名字/取值像开关、没有实测证据的**是可选、无默认值（不传就**不发**
    这个键，服务端用自己的默认值）（见 `docs/reference.md` 的「取值会切换响应形态的参数」）。

    数据从哪来：本工具**只读会话目录里的 `analysis.json`**（不读实时流量、也不会自己
    再分析一次）。所以调用链是 `start_capture` → `analyze_traffic`（写出 analysis.json）
    → 本工具。没有 `analysis.json`（没分析过、会话 id 拼错）时返回 `analysis_not_found`
    并指向 `analyze_traffic`，而不是抛一个看不懂的 `FileNotFoundError`。
    """
    if language != "python" or framework != "fastmcp":
        return {"success": False, "error": "暂未支持，仅支持 python + fastmcp"}
    session_id = _canonical_session_id(session_id)
    # 与 diff_capture / merge_capture / extract_crypto_logic 同一道前置检查：四个工具
    # 读的是同一份 analysis.json，缺了就给同一句**可行动**的话。此前只有这里没有这道
    # 检查，于是「没分析就生成」直接抛出 `FileNotFoundError: [Errno 2] No such file or
    # directory: '…\\analysis.json'`：中文路径还会显示成乱码，使用者既看不懂也不知道
    # 下一步该干什么。
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"success": False, "error": "analysis_not_found",
                "message": "先对该 session 调用 analyze_traffic（它写出本工具要读的 "
                           "analysis.json）；确认 session_id 拼写与 get_capture_status 里的一致。"}
    try:
        return generate(store.session_path(session_id), Path(output_dir), endpoint_ids,
                        include_endpoint_ids)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
@audited
async def extract_crypto_logic(session_id: str) -> dict[str, Any]:
    session_id = _canonical_session_id(session_id)
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"found": False, "strategy": "none", "session_id": session_id, "details": "run analyze_traffic first"}
    import json
    result = detect_crypto(store.session_path(session_id), json.loads(analysis_path.read_text(encoding="utf-8")))
    result["session_id"] = session_id
    return result


@mcp.tool()
@audited
async def confirm_login(login_session_id: str) -> dict[str, Any]:
    """登录确认（主路径）：Agent 已在对话里问过用户、用户答复登录完成后调用。

    完成一律靠显式确认，工具不会自动判定。若返回 warning=no_credential_evidence，
    说明浏览器里没观察到凭据类 Cookie，存下的登录态可能是未认证状态。
    若返回 confirmation_evidence="none"（附 confirmation_warning），说明服务端
    没记录到任何「已请用户确认」的动作——只提示，不拒绝。
    """
    result = login_manager.confirm(login_session_id)
    if result.get("success") is True:
        _add_confirmation_evidence(result, login_session_id)
    return result


@mcp.tool()
@audited
async def request_login_confirm_dialog(login_session_id: str) -> dict[str, Any]:
    """可选兜底：弹出系统对话框让用户点选「是/否」确认登录，并返回用户的选择。

    在不方便用对话询问时使用。点「否」不会丢弃——会话保持等待，可再次调用本工具
    （对话框可重复弹出）。调用会阻塞到用户作答为止。会话已结束时会被拒绝，
    不会弹出必然变成死物的对话框。
    """
    result = await login_manager.request_confirm_dialog(login_session_id)
    if result.get("success") is True:
        # 对话框确实弹到了用户面前（点「是」或「否」都算问过了）。
        _note_confirmation_request(login_session_id, "request_login_confirm_dialog")
    return result


@mcp.tool()
@audited
async def confirm_login_ready(session_id: str) -> dict[str, Any]:
    """放行开始记录：Agent 问过用户、用户确认已登录后再调。

    会话从 authenticating 翻到 capturing。**这是主放行方式**——登录旁证
    （get_capture_status 的 auth_evidence）不会自动放行。
    """
    session_id = _canonical_session_id(session_id)
    capture = capture_sessions.get(session_id)
    if capture is None:
        return {"success": False, "error": "capture_session_not_found", "session_id": session_id}
    if capture.status != "authenticating":
        return {"success": False, "error": "not_authenticating", "status": capture.status}
    await capture._enter_capturing()
    store.write_metadata(session_id, capture.metadata())
    return _add_confirmation_evidence(
        {"success": True, "session_id": session_id, "status": capture.status}, session_id)


@mcp.tool()
@audited
async def request_capture_confirm_dialog(session_id: str) -> dict[str, Any]:
    """可选兜底：弹出系统对话框让用户点选「是/否」，是则开始记录。

    与 `confirm_login_ready` 等价，只是把「问用户」交给系统对话框，供 Agent
    不便在对话里询问时使用。点「否」不丢弃——会话保持等待，可再次调用
    （对话框可重复弹出）。调用会阻塞到用户作答为止。会话已结束时会被拒绝。
    """
    session_id = _canonical_session_id(session_id)
    capture = capture_sessions.get(session_id)
    if capture is None:
        return {"success": False, "error": "capture_session_not_found", "session_id": session_id}
    result = await capture.request_confirm_dialog()
    store.write_metadata(session_id, capture.metadata())
    if result.get("success") is True:
        # 对话框确实弹到了用户面前（点「是」或「否」都算问过了）。
        _note_confirmation_request(session_id, "request_capture_confirm_dialog")
    return result


# --------------------------------------------------------------------------- #
# 项目（registry）管理工具 —— 仅 IT 管理态；用户态子 MCP 不包含这些能力
# --------------------------------------------------------------------------- #
def _seen_keys(analysis: dict[str, Any]) -> set[tuple[str, str, str]]:
    """本轮抓包里**实际见过**的端点键（analysis 的全部端点，含会被跳过规则滤掉的）。

    ``session_to_registry_entries`` 交出来的 ``entries`` 是**过滤后**的：拿它当
    「见过的全集」，会把「见过、但本轮被判成噪音/非 JSON 因而不并入」的端点误报成
    「本轮未见」。两者必须分开（见 ``project.merge_registry`` 的 ``seen_keys``）。
    """
    return {match_key(endpoint) for endpoint in analysis.get("endpoints", []) or []}


def _not_merged(analysis: dict[str, Any],
                endpoint_keys: list[str] | None) -> list[dict[str, Any]]:
    """本轮抓包**见过、但不会被并入 registry** 的端点 + 原因（供工具层如实交代）。

    ``analyze_traffic`` 摘要在分析阶段就报过一份 ``not_generated``；这里是**写入侧**
    的同一份事实：使用者只看了合并结果、没回头看摘要时，不会以为「全都并进来了」，
    也就不会在事后才发现少了几条。只给衔接键 + 位置 + 原因，无 schema。
    """
    selected = None
    if endpoint_keys is not None:
        selected = {tuple(str(k).split("|", 2)) for k in endpoint_keys}
    skipped: list[dict[str, Any]] = []
    for endpoint in analysis.get("endpoints", []) or []:
        reasons = generation_skip_reasons(endpoint)
        if not reasons:
            continue
        if selected is not None and match_key(endpoint) not in selected:
            continue  # 调用方本就没挑它，不算「该并没并」
        skipped.append({
            "endpoint_id": endpoint_registry_id(endpoint),
            "method": endpoint.get("method"), "host": endpoint.get("host"),
            "path": endpoint.get("path"),
            "reason": reasons[0], "reasons": reasons,
        })
    return skipped


def _not_merged_hint(skipped: list[dict[str, Any]]) -> str:
    """把「哪些没并进来、为什么、接下来怎么办」写成一句给使用者看的话。"""
    if not skipped:
        return ""
    return ("这些端点在本次抓包里出现过，但按既有规则**不会生成 MCP 工具**，所以没有并进"
            " registry（合并结果里的 added/updated 不含它们）："
            + "、".join(f"{item['method']} {item['path']}（{item['reason']}）" for item in skipped)
            + "。确实需要其中某一条时，用 generate_mcp_server(include_endpoint_ids=[…]) "
              "把它的衔接键显式点名包含，它会照常生成并在 README 里单列说明。")


@mcp.tool()
@audited
async def diff_capture(project_dir: str, session_id: str) -> dict[str, Any]:
    """只读：对比一次新抓包与项目 registry 的差异（新增/参数变化/未见/鉴权漂移）。

    鉴权部分有两个键**常驻**，直接转述给用户即可：

    * ``auth_changes`` + ``auth_changes_hint``：登录方式变了（含「这一轮一条 Authorization
      都没再抓到」这种**降级**，修复前它是静默的）。``auth_changes_hint`` 是一句面向非技术
      用户的说明；真出现时**合并会被拒**，除非显式传 ``allow_auth_change=true``；
    * ``auth_conflicts`` + ``auth_conflicts_hint``：同一台服务器上不同接口用了不同的登录方式。
      这是受支持的形态（工具会按每个接口实际的方式各自带上凭据），只告知、**不拦合并**。
    """
    try:
        registry = load_registry(project_dir)
    except FileNotFoundError as exc:
        return {"success": False, "error": str(exc)}
    session_id = _canonical_session_id(session_id)
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"success": False, "error": "analysis_not_found",
                "message": "先对该 session 调用 analyze_traffic。"}
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    entries, hosts = session_to_registry_entries(analysis, session_id)
    report = diff_registry(registry, entries, seen_keys=_seen_keys(analysis))
    auth_changes = diff_hosts(registry.get("hosts", {}), hosts)
    report["auth_changes"] = auth_changes
    # 鉴权变化分两类，措辞分开给（都由本工具输出，Agent 直接转述给用户）：
    #   * 漂移 / 降级：合并会被拒（除非 allow_auth_change=true）—— 必须让用户先知道；
    #   * 同一域名混用多种方式：受支持，只是告知。S13 之前「混用」被静默取其一，
    #     用户没有任何渠道看到它发生过（现在也可能发生在旧项目上）。
    drift = [c for c in auth_changes if not is_conflict_change(c)]
    conflicts = [c for c in auth_changes if is_conflict_change(c)]
    report["auth_changes_hint"] = auth_change_message(drift) if drift else ""
    report["auth_conflicts"] = conflicts
    report["auth_conflicts_hint"] = auth_conflict_message(conflicts)
    report["success"] = True
    report["project_dir"] = project_dir
    report["registry_version"] = registry.get("registry_version")
    return report


@mcp.tool()
@audited
async def merge_capture(
    project_dir: str,
    session_id: str,
    endpoint_keys: list[str] | None = None,
    allow_auth_change: bool = False,
) -> dict[str, Any]:
    """确认后把抓包合并进 registry（version+1）。鉴权 scheme 变化须显式 allow_auth_change=true。

    endpoint_keys 形如 ["GET|api.example.com|/pets"]；**不传则合并这次抓包里全部会被
    生成的端点**。注意「全部」不等于「抓到的每一条」：噪音端点、不可独立调用的端点、
    非 JSON 页面端点按既有规则**不生成工具**，因此也不会并入 registry（它们不会凭空消失，
    而是列在返回值的 ``not_merged`` 里，附原因与下一步 —— 见下）。

    返回值的 ``not_merged`` / ``not_merged_hint``：本次抓包见过、但**没有**并入 registry
    的端点的衔接键 + 原因，以及「确实要其中某一条该怎么办」（``generate_mcp_server`` 的
    ``include_endpoint_ids`` 可显式点名包含）。这两个键**常驻**（无事可报时是空列表 /
    空串），消费方可以无条件读它们 —— 不要只报 added/updated 就以为「全都并进来了」。

    鉴权方式变化时返回 ``auth_scheme_changed``（含 ``message`` 一句面向非技术用户的说明）
    并**不做任何写入**（需显式 ``allow_auth_change=true``）；「这一轮一条 Authorization
    都没再抓到」同样算变化，且合并本身绝不把已有的 scheme 降级成空。项目被 ``locked`` 时返回
    ``project_locked``。

    成功时返回值带 ``auth_conflicts`` / ``auth_conflicts_hint``（**常驻**，无事可报时是
    ``[]`` / 空串）：同一台服务器上不同接口用了不同登录方式的**告知** —— 工具会按每个接口
    实际的方式各自带凭据，用户不需要做任何配置，合并也不受影响。把这句话转告用户。
    """
    session_id = _canonical_session_id(session_id)
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"success": False, "error": "analysis_not_found",
                "message": "先对该 session 调用 analyze_traffic。"}
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    entries, hosts = session_to_registry_entries(analysis, session_id)
    keys = None
    if endpoint_keys is not None:
        keys = [tuple(k.split("|", 2)) for k in endpoint_keys]
    result = merge_registry(project_dir, entries, hosts, session_id, keys, allow_auth_change,
                            seen_keys=_seen_keys(analysis))
    if result.get("success") is True:
        # 写入侧如实交代「哪些见过、但没并进来」：使用者（和 Agent）不必回头翻
        # analyze_traffic 的摘要也不会在事后才发现少了几条端点。
        skipped = _not_merged(analysis, endpoint_keys)
        result["not_merged"] = skipped
        result["not_merged_hint"] = _not_merged_hint(skipped)
    return result


@mcp.tool()
@audited
async def regenerate_server(project_dir: str) -> dict[str, Any]:
    """从 registry 重出 server.py 等文件（旧文件自动留 .bak）。locked 项目拒绝。"""
    return regenerate(project_dir)


@mcp.tool()
@audited
async def export_project(project_dir: str, output_dir: str) -> dict[str, Any]:
    """导出用户态分发包：仅运行与诊断能力，不含任何 registry 写入/再生成代码。"""
    try:
        load_registry(project_dir)
    except FileNotFoundError as exc:
        return {"success": False, "error": str(exc)}
    return export_user_package(project_dir, output_dir)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()