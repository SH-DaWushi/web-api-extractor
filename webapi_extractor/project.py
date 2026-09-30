# -*- coding: utf-8 -*-
"""Registry-driven project model for iterative sub-MCP maintenance.

A "project" is the unit the extractor generates and keeps evolving:

    <project_dir>/
    ├─ project.json      # site name, registry_version, locked flag
    ├─ registry.json     # single source of truth: hosts + endpoints + provenance
    ├─ server.py         # rendered FROM the registry; regenerate at any time
    ├─ requirements.txt / .env.example / README.md / smoke_test.py
    └─ captures/         # provenance notes (which sessions fed which versions)

Role separation:
  * IT/admin side (this extractor) may diff/merge/regenerate/export.
  * User side (the distributed sub-MCP) physically contains NO write capability:
    its server.py never imports or includes any registry-writing code.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# 本次重做：参数证据的合并规则只写一份（analyzer 里那份），合并/生成两处不得各写一套。
# URL/query 凭据擦除也同理：规则只写在 analyzer 一份，project 与生成侧共用。
from .analyzer import (
    INSUFFICIENT_SAMPLES_HINT,
    merge_param_evidence,
    sanitize_query_param_evidence,
    sanitize_query_params,
    sanitize_sample_url,
)


# --------------------------------------------------------------------------- #
# project.json / registry.json I/O
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def project_path(project_dir: str | Path) -> Path:
    return Path(project_dir)


def load_project(project_dir: str | Path) -> dict[str, Any]:
    path = project_path(project_dir) / "project.json"
    if not path.exists():
        raise FileNotFoundError(f"not a project directory (missing project.json): {project_dir}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_registry(project_dir: str | Path) -> dict[str, Any]:
    path = project_path(project_dir) / "registry.json"
    if not path.exists():
        raise FileNotFoundError(f"missing registry.json in: {project_dir}")
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# registry 不得残留抓包 URL / query 的凭据取值
# --------------------------------------------------------------------------- #
# registry.json 既是产品的持久产物，也会**随用户态分发包原样交给同事**
# （见 USER_PACKAGE_FILES）。抓包 URL 的 query 里可能带着 `?token=…` /
# `?signature=…` / session id —— 那些**取值**绝不能进 registry.json，更不能被分发。
# 擦除规则只写在 analyzer 一份（sanitize_sample_url / sanitize_query_params /
# sanitize_query_param_evidence），这里只负责把 registry 里每条端点都过一遍。
def _sanitize_registry_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(endpoint, dict):
        return endpoint
    if "sample_url" in endpoint:
        endpoint["sample_url"] = sanitize_sample_url(endpoint.get("sample_url"))
    if endpoint.get("query_params"):
        endpoint["query_params"] = sanitize_query_params(endpoint["query_params"])
    if endpoint.get("query_param_evidence"):
        endpoint["query_param_evidence"] = sanitize_query_param_evidence(
            endpoint["query_param_evidence"])
    return endpoint


def _sanitize_registry_auth_login(auth_login: Any) -> Any:
    """``auth_login`` 里 query 参数的取值同样不得进 registry / 分发包。

    ``auth_login`` **不属** ``registry["endpoints"]``，所以此前整条漏掉了：抓包第一次
    登录请求的 query 取值（``?tenant=acme`` / ``?signature=…``）会原样落进
    registry.json，随 ``export_user_package`` 交给同事，生成物还会拿它去登录。
    规则与端点共用（analyzer.sanitize_query_params / sanitize_query_param_evidence），
    这里只负责把它接上——良性固定参数（`encrypt=2`）照旧保留。
    """
    if not isinstance(auth_login, dict):
        return auth_login
    if "query_params" in auth_login:
        auth_login["query_params"] = sanitize_query_params(auth_login.get("query_params"))
    if auth_login.get("query_param_evidence"):
        auth_login["query_param_evidence"] = sanitize_query_param_evidence(
            auth_login["query_param_evidence"])
    return auth_login


def _sanitize_registry_urls(registry: dict[str, Any]) -> dict[str, Any]:
    """就地把 registry 里所有端点的 URL/query 凭据洗掉（返回同一份 registry）。

    这一跳也给**本次修改之前写下的老 registry** 兜底：老文件里的原始取值会在下一次
    save/merge 落盘时被洗掉（load 仍照常成功，见 load_registry）。

    ``auth_login`` 走的是**同一个出口**（save_registry / export_user_package 都经过
    这里），于是登录接口的 query 取值也一并擦掉——它既不属 endpoints，又要一起分发。
    """
    for endpoint in registry.get("endpoints") or []:
        _sanitize_registry_endpoint(endpoint)
    _sanitize_registry_auth_login(registry.get("auth_login"))
    return registry


def save_registry(project_dir: str | Path, registry: dict[str, Any]) -> None:
    path = project_path(project_dir) / "registry.json"
    _sanitize_registry_urls(registry)
    path.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")


def init_project(project_dir: str | Path, site_name: str) -> dict[str, Any]:
    directory = project_path(project_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "captures").mkdir(exist_ok=True)
    project = {"site_name": site_name, "registry_version": 0, "locked": False,
               "created_at": _now(), "tool": "webapi_extractor"}
    (directory / "project.json").write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
    registry = {"site_name": site_name, "registry_version": 0, "updated_at": _now(),
                "hosts": {}, "endpoints": [], "auth_login": None}
    save_registry(directory, registry)
    return project


def set_auth_login(project_dir: str | Path, auth_login: dict[str, Any] | None) -> None:
    """记录账号密码登录接口定义（curate 阶段识别，生成 login/auth_status 工具用）。

    落盘前先清洗：抓包第一次登录请求的 query 取值（身份/凭据类）换成 ``***``，
    良性固定参数照旧保留。这里显式洗一遍（`save_registry` 那一跳也会洗），
    免得以后有人绕过 save_registry 写这个字段。传进来的 dict 不被就地修改。
    """
    registry = load_registry(project_dir)
    registry["auth_login"] = (
        _sanitize_registry_auth_login(dict(auth_login))
        if isinstance(auth_login, dict) else auth_login)
    save_registry(project_dir, registry)


# --------------------------------------------------------------------------- #
# 覆盖已有项目：自动备份 + 覆盖 + 告知（不再拦截）
# --------------------------------------------------------------------------- #
# 命中任一文件即认定「这个目录里已经有一个项目」。registry.json 是真正的数据，
# project.json 单独存在也算（生成到一半、被人工删过 registry 的项目同样是项目目录）。
PROJECT_MARKER_FILES = ("registry.json", "project.json")


def project_marker_files(project_dir: str | Path) -> list[str]:
    """列出目录里存在的项目标记文件（空列表 = 不是项目目录，可安全新建）。"""
    directory = project_path(project_dir)
    return [name for name in PROJECT_MARKER_FILES if (directory / name).is_file()]


def existing_project_summary(project_dir: str | Path) -> dict[str, Any] | None:
    """已有项目的概况（registry_version / 端点数）；不是项目 → None。

    读不出来（registry 缺失或损坏）时给 None 值而不是抛异常：这是**覆盖面**上的
    辅助信息，不能让「读不出概况」把「覆盖」变成「崩溃」。
    """
    if not project_marker_files(project_dir):
        return None
    try:
        registry = load_registry(project_dir)
    except (OSError, ValueError):
        return {"registry_version": None, "endpoint_count": None}
    return {"registry_version": registry.get("registry_version"),
            "endpoint_count": len(registry.get("endpoints") or [])}


def backup_existing_project(project_dir: str | Path) -> str | None:
    """把已有项目**整份复制**到旁边，返回备份目录路径；不是项目目录则返回 None。

    为什么不再拦：``generate()`` 走 ``init_project()``，后者**无条件**重写
    project.json 与 registry.json。以前的做法是「检测到已有项目就报错拒绝」——
    这对**不懂这套目录语义**的使用者等于死路：他既判断不出「已有项目」意味着什么，
    也不知道该换哪个目录。改成**自动备份 + 照常覆盖**：数据一个不丢（备份里就是覆盖前
    的那一份），流程不中断，返回消息里明确告知备份落在哪。

    备份目录名是**可读**的兄弟目录 ``<dir>.bak-<YYYYmmdd-HHMMSS>``（同秒重名则加序号）。
    它只影响目录名，不写进任何一个生成物 —— 生成物内容不因此变得非确定性。
    """
    directory = project_path(project_dir)
    if not project_marker_files(directory):
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = directory.parent / f"{directory.name}.bak-{stamp}"
    suffix = 2
    while target.exists():
        target = directory.parent / f"{directory.name}.bak-{stamp}-{suffix}"
        suffix += 1
    shutil.copytree(directory, target)
    return str(target)


def overwrite_notice(backup_path: str | None, summary: dict[str, Any] | None) -> str:
    """覆盖已有项目时给使用者的一句话（**明确告知备份在哪**）。

    ``summary`` 必须是**覆盖之前**读到的概况（覆盖之后读到的已经是新一轮的数字）。
    """
    if not backup_path:
        return ""
    version = (summary or {}).get("registry_version")
    count = (summary or {}).get("endpoint_count")
    if version is None or count is None:
        state = "里面原有项目数据"
    else:
        state = f"它原有 registry_version={version}、{count} 个端点"
    return (f"输出目录里已有一个项目（{state}），已先**整份备份**到 {backup_path}，"
            "然后按这次抓包重新生成。需要找回旧版本时，从那个备份目录里取即可 —— "
            "没有任何文件被静默删除。")


# --------------------------------------------------------------------------- #
# session analysis → registry entries
# --------------------------------------------------------------------------- #
# MCP 工具名上限 128 字符（SEP-986）。超限时 fastmcp 只告警放行，但严格校验的
# 客户端可能拒绝注册，故在命名出口统一压到限内。
MCP_TOOL_NAME_MAX = 128
# 压缩后缀保留的内容哈希长度：够短以免吃掉可读前缀，够长以免同前缀碰撞。
_NAME_HASH_LEN = 8


def _shorten_tool_name(name: str, limit: int = MCP_TOOL_NAME_MAX) -> str:
    """把超长工具名压到 limit 以内：可读前缀 + 确定性哈希后缀。

    哈希用 sha1 而非内置 ``hash()``——后者按进程随机化，会让同一端点在每轮
    生成时拿到不同名字，registry 会反复 diff 出噪音。
    """
    if len(name) <= limit:
        return name
    suffix = "_" + hashlib.sha1(name.encode("utf-8")).hexdigest()[:_NAME_HASH_LEN]
    head = name[: limit - len(suffix)]
    # 尽量在词边界截断，避免切出半截标识符（削得太狠则退回硬截断结果）。
    if "_" in head:
        trimmed = head.rsplit("_", 1)[0]
        if len(trimmed) >= limit // 2:
            head = trimmed
    return head + suffix


def _tool_name(endpoint: dict[str, Any], used: set[str]) -> str:
    # 上游（curate 阶段）可显式指定 tool_name；语义化命名优先于从路径机械推导。
    explicit = re.sub(r"[^0-9a-zA-Z_]+", "_", str(endpoint.get("tool_name") or "")).strip("_")
    if explicit[:1].isdigit():
        explicit = "_" + explicit
    parts = [p for p in endpoint.get("path", "").split("/") if p and not p.startswith("{")]
    resource = "_".join(re.sub(r"[^a-zA-Z0-9]+", "_", p).strip("_") for p in parts) or "endpoint"
    verb = {"GET": "get", "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}.get(
        endpoint.get("method", "GET"), "call")
    name = explicit or f"{verb}_{resource}"
    if not explicit and "{" in endpoint.get("path", ""):
        name += "_by_id"
    # 超长名字先压到 MCP 上限内（#18）。碰撞序号同样要过闸门——加序号后可能
    # 又超限，而哈希随序号变化，压缩后仍保持唯一。
    candidate = _shorten_tool_name(name)
    index = 2
    while candidate in used:
        candidate = _shorten_tool_name(f"{name}_{index}")
        index += 1
    used.add(candidate)
    return candidate


# --------------------------------------------------------------------------- #
# F6: 端点衔接键（endpoint_id）
#
# endpoint_id 是 analyze_traffic 摘要交给 Agent 的**唯一衔接键**：Agent 拿它调
# update_endpoint / generate_mcp_server(endpoint_ids=[...])。因此它必须来自端点自身
# 的数据，而不是「在某个被过滤过的列表里的位置」——按位置解释时，只要前面的端点被
# 丢掉或合并，同一个键就指向另一个端点。
# --------------------------------------------------------------------------- #
_ID_FALLBACK_LENGTH = 12


def endpoint_registry_id(endpoint: dict[str, Any]) -> str:
    """端点的稳定衔接键：优先用 analyzer 分配的 ``endpoint_id``。

    F6 向后兼容：analyzer 修改前写下的 analysis.json、以及更早写下的 registry.json
    里都没有 ``endpoint_id``。此时按 ``(method, host, path)`` 派生一个**确定性** id ——
    同一端点在任何一次调用里都得到同一个键，老项目照常打开、``endpoint_ids`` 照常可用。
    """
    explicit = endpoint.get("endpoint_id")
    if explicit:
        return str(explicit)
    material = "\x00".join(
        str(endpoint.get(field) or "") for field in ("method", "host", "path"))
    return "ep_" + hashlib.sha1(material.encode("utf-8")).hexdigest()[:_ID_FALLBACK_LENGTH]


# 生成阶段会**跳过**（不生成工具）的标记。顺序即判定优先级。
# review_suggested 不在此列：它只是「待复核」提示，不会让端点消失。
GENERATION_SKIP_FLAGS = ("noise", "not_independently_callable", "non_json_response")

# Fix 1: `file_response`（业务文件下载，见 analyzer.is_business_file_download）能
# **抵消** `non_json_response` 这一条跳过理由 —— 报表/导出端点的响应本来就不是
# JSON，用「非 JSON」把它丢掉等于把用户要的下载能力整个抹掉。它是唯一一处
# 「标记可以豁免另一条标记」的关系，故在这里显式写出并只豁免这一条：噪音域名、
# 不可独立调用依旧是硬跳过理由（与是不是文件无关）。
FILE_RESPONSE_EXEMPT_FLAGS = ("non_json_response",)


def generation_skip_reasons(endpoint: dict[str, Any]) -> list[str]:
    """该端点会在生成阶段被跳过的原因（空列表 = 会被生成）。

    这是 ``session_to_registry_entries(include_noise=False)`` 的过滤条件的**唯一来源**，
    ``analyze_traffic`` 摘要也用它告诉 Agent「哪些端点不会被生成、为什么」。
    """
    reasons = [flag for flag in GENERATION_SKIP_FLAGS if endpoint.get(flag)]
    if endpoint.get("file_response"):
        reasons = [flag for flag in reasons if flag not in FILE_RESPONSE_EXEMPT_FLAGS]
    return reasons


# description 的来源标记：抓包/档案推导出来的可以被下一轮抓包刷新；用户手写的不能。
DESCRIPTION_SOURCE_CAPTURE = "capture"
DESCRIPTION_SOURCE_USER = "user"


def _description_is_user_edited(entry: dict[str, Any]) -> bool:
    return str(entry.get("description_source") or "").lower() == DESCRIPTION_SOURCE_USER


def _accumulate_values(existing: list[Any] | None, incoming: list[Any] | None) -> list[Any]:
    """合并参数样本值：**累积**去重，顺序保持（旧的在前）。

    只累加不覆盖，是 Issue #23 的向后兼容约定；但「只加新的参数名、不扩已有参数的值」
    会让「>=2 个样本才写默认值」这条闸门被第一次抓包的单个值永远满足——后来抓到该
    参数其实会变，也照样把抓包当时的真实值烘进代码。
    """
    merged = list(existing or [])
    for value in incoming or []:
        if value not in merged:
            merged.append(value)
    return merged


def session_to_registry_entries(analysis: dict[str, Any], session_id: str,
                                include_noise: bool = False,
                                include_endpoint_ids: list[str] | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Convert an analyze_capture() result into registry endpoint entries + host auth info.

    include_noise=False（默认）跳过标记为噪音的端点；显式传 True 保留全部。

    Issue #15：默认同时跳过 `not_independently_callable` 的端点
    （OData 绑定函数依赖父请求上下文参数，独立成工具必失败）。
    Issue #16：默认跳过 `non_json_response` 的端点（页面/控件端点，响应为
    HTML/302，非 JSON 数据接口），但 `file_response`（业务文件下载）会被豁免。
    传 include_noise=True 可保留（用于人工复核）。

    过滤条件集中在 `generation_skip_reasons()`：`analyze_traffic` 摘要用它报告
    「哪些端点不会被生成、为什么」，两处共用同一份判据，不会各说各话。

    ``include_endpoint_ids`` 是**显式点名**的开关（Feature）：列在这里的衔接键
    **绕过全部跳过规则**（`noise` / `not_independently_callable` /
    `non_json_response`）照常生成，并在条目上留 `forced_include: True`、在生成的
    README 里单独说明 —— 免得同事看到一条噪音端点却不知道它为什么在这儿。
    这正是「用户复核 `not_generated` 后决定我就是要它」的唯一出路
    （`endpoint_ids` 仍然只接受**可生成**的键，不做隐式别名）。
    """
    forced_ids = {str(i) for i in (include_endpoint_ids or [])}
    used: set[str] = set()
    entries: list[dict[str, Any]] = []
    for endpoint in analysis.get("endpoints", []):
        forced = endpoint_registry_id(endpoint) in forced_ids
        if not forced and not include_noise and generation_skip_reasons(endpoint):
            continue
        path = endpoint.get("path", "")
        path_params = [seg.strip("{}") for seg in path.split("/") if seg.startswith("{")]
        entries.append({
            # F6: 衔接键原样透传（analyzer 分配，或旧数据按 method/host/path 派生）。
            # 生成阶段按这个键解释 endpoint_ids，不能再按列表位置重编号。
            "endpoint_id": endpoint_registry_id(endpoint),
            "tool_name": _tool_name(endpoint, used),
            "method": endpoint.get("method", "GET"),
            "host": endpoint.get("host", ""),
            "path": path,
            "path_params": path_params,
            # 落进 registry 的 query 样本先去凭据（见 analyzer.sanitize_query_params）：
            # 参数名保留（工具签名需要它），身份/凭据类取值换成 `***`。
            "query_params": sanitize_query_params(endpoint.get("query_params", {}) or {}),
            # Issue #23: 表单编码体字段（传统服务端渲染系统的实际传参方式）
            "request_body_params": endpoint.get("request_body_params") or {},
            "sample_count": int(endpoint.get("sample_count", 1)),
            # 本次重做：默认值只由「不同请求之间的比较」决定，故证据必须随条目
            # 落进 registry（生成器不再看 sample_count）。
            "distinct_request_count": int(endpoint.get("distinct_request_count") or 0),
            "insufficient_samples": bool(endpoint.get("insufficient_samples")),
            "evidence_hint": endpoint.get("evidence_hint"),
            "query_param_evidence": sanitize_query_param_evidence(
                endpoint.get("query_param_evidence") or {}),
            "request_body_param_evidence": endpoint.get("request_body_param_evidence") or {},
            # 逐参数溯源（来源 + 影响）：用户经 update_endpoint 写入，生成器写进工具
            # 文档字符串，调用方才知道该传什么。
            "param_provenance": endpoint.get("param_provenance") or {},
            "param_provenance_source": endpoint.get("param_provenance_source"),
            "request_schema": endpoint.get("request_schema"),
            "response_schema": endpoint.get("response_schema"),
            "auth_required": bool(endpoint.get("auth_required")),
            # S13：本端点**实测**的鉴权载体（Bearer / Basic / cookie 的并集）。
            # 生成器据此逐端点决定发 Authorization 还是 Cookie —— 同一域名下不同接口
            # 可以不一样，按主机记一种会让「只认 Cookie 的接口」稳定 401。
            "auth_hint": list(endpoint.get("auth_hint") or []),
            "description": endpoint.get("description"),
            # F7: description 的来源标记（随 registry.json 落盘，round-trip 后仍在）。
            "description_source": (endpoint.get("description_source")
                                   or DESCRIPTION_SOURCE_CAPTURE),
            "notes": endpoint.get("notes"),
            "noise": bool(endpoint.get("noise")),
            # Issue #15: 透传可独立生成性标记，供生成阶段注入默认分页上限
            "not_independently_callable": bool(endpoint.get("not_independently_callable")),
            "not_callable_reason": endpoint.get("not_callable_reason"),
            # Issue #16: 透传非 JSON 响应标记，供人工复核
            "non_json_response": bool(endpoint.get("non_json_response")),
            # Fix 1: 业务文件下载标记 —— 生成器据此改为「原样返回响应体 + 内容类型」，
            # 而不是假装它有 JSON schema（见 generator._render_tool）。
            "file_response": bool(endpoint.get("file_response")),
            # Feature: 该条目是**显式点名**进来的（绕过了跳过规则）。落进 registry
            # 与生成的 README，供人工复核时解释「为什么这条噪音端点在这儿」。
            "forced_include": forced,
            "pagination_suggested": endpoint.get("pagination_suggested"),
            "required_query_param": endpoint.get("required_query_param"),
            "status": "active",
            "unseen_since": None,
            "source_sessions": [session_id],
            "sample_url": sanitize_sample_url(endpoint.get("url")),
        })
    hosts = (analysis.get("auth_metadata", {}) or {}).get("auth_schemes", {}) or {}
    return entries, hosts


# --------------------------------------------------------------------------- #
# diff / merge
# --------------------------------------------------------------------------- #
def match_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    """端点的同一性键 ``(method, host, path)``。

    对 registry 条目与 analysis 端点**通用**（analysis 端点同样有这三个字段），
    所以「本轮抓包里到底见过哪些端点」可以用同一个键从 analysis 直接算出来，而不必
    绕经已经被跳过规则过滤过的 registry 条目（见 ``merge_registry`` 的 ``seen_keys``）。
    """
    return (entry.get("method", ""), entry.get("host", ""), entry.get("path", ""))


def _match_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return match_key(entry)


def diff_registry(registry: dict[str, Any], entries: list[dict[str, Any]],
                  seen_keys: Iterable[tuple[str, str, str]] | None = None) -> dict[str, Any]:
    """Compare fresh capture entries against the registry. Read-only.

    ``seen_keys``：本轮抓包里**实际见过**的端点键（可以是 analysis 里的**全部**端点，
    含那些会被跳过规则滤掉的）。给了它，「未见」就只统计「抓包里根本没有的端点」——
    否则一条「见过、但被判定为噪音/非 JSON 因而不进 registry」的端点会被误报成
    「本轮未见」，把使用者引向「网站把这个接口下线了」的错误结论。
    不给则退化为与 ``entries`` 同义（保住库层的既有行为）。
    """
    existing = {_match_key(e): e for e in registry.get("endpoints", []) if e.get("status") != "deprecated"}
    fresh = {_match_key(e): e for e in entries}
    seen = set(fresh) if seen_keys is None else {tuple(key) for key in seen_keys}
    new = [e for key, e in fresh.items() if key not in existing]
    changed: list[dict[str, Any]] = []
    for key, e in fresh.items():
        old = existing.get(key)
        if not old:
            continue
        old_qp = {k: v for k, v in (old.get("query_params") or {}).items()}
        new_qp = {k: v for k, v in (e.get("query_params") or {}).items()}
        if set(old_qp) != set(new_qp):
            changed.append({"tool_name": old["tool_name"], "change": "query_params",
                            "registry": sorted(old_qp), "capture": sorted(new_qp)})
    # 鉴权方式的差异**不在**这里算：`diff_registry` 只比对端点本身，主机级鉴权由
    # 调用方拿 `diff_hosts(registry["hosts"], hosts)` 单独比对（`diff_registry` 拿不到
    # registry 的 hosts 与本次抓包的 hosts，硬塞会在两处各算一遍、还可能不一致）。
    unseen = [{"tool_name": e["tool_name"], "method": e["method"], "host": e["host"], "path": e["path"]}
              for key, e in existing.items() if key not in seen]
    return {"new_endpoints": new, "changed_endpoints": changed, "unseen_endpoints": unseen,
            "counts": {"new": len(new), "changed": len(changed), "unseen": len(unseen)}}


def auth_change_message(changes: list[dict[str, Any]]) -> str:
    """把鉴权漂移写成**非技术用户**看得懂、且能照着做的一句话。

    不出现 scheme / registry / 合并 这类词：用户看到的是「网站换登录方式了」以及
    「确认之后怎么继续」。
    """
    parts = []
    for change in changes:
        host = change.get("host")
        old, new = change.get("registry_scheme"), change.get("capture_scheme")
        if new is None:
            parts.append(f"{host} 这次没再抓到登录凭据（之前用的是 {old}）")
        else:
            parts.append(f"{host} 的登录方式从 {old} 变成了 {new}")
    detail = "；".join(parts) if parts else "登录方式与本项目原来的记录不一致"
    return (f"检测到{detail}。为免生成的工具在你不注意的时候换成另一种登录方式、"
            f"到用的时候才发现它们全都用不了，这里先停下来。"
            f"如果确认网站确实改了，重新调用一次并传 allow_auth_change=true 就会照这次的抓包继续。")


def auth_conflict_message(conflicts: list[dict[str, Any]]) -> str:
    """「同一域名混用多种登录方式」的**告知**（非技术措辞，且说明不必做任何事）。"""
    if not conflicts:
        return ""
    parts = [f"{c.get('host')}（{' / '.join(c.get('conflict_schemes') or [])}）"
             for c in conflicts]
    return ("已合并且不影响使用：这些网站同一台服务器上不同接口用了不同的登录方式（"
            + "、".join(parts)
            + "）。生成的工具会按每个接口实际的方式各自带上对应凭据，"
              "你不需要为它做任何配置。")


def is_conflict_change(change: dict[str, Any]) -> bool:
    """这条 host 变化是否只是「同一域名混用了多种登录方式」的**告知**。

    混用本身是受支持的形态（S13：生成物按端点各发各的凭据），所以它只报告、不拦截合并；
    真正的**漂移/降级**（原来会发的凭据这一轮不发了）才是硬停。
    """
    return bool(change.get("conflict_schemes"))


def diff_hosts(registry_hosts: dict[str, Any], capture_hosts: dict[str, Any]) -> list[dict[str, Any]]:
    """本轮抓包与本项目 registry 的**鉴权方式**差异。只读。

    三类结论（每条都带 ``host``，消费方不必自己比对）：

      * 方案变了：``registry_scheme != capture_scheme``（两侧都非空）；
      * 方案**降级**：registry 有方案、这一轮一条 Authorization 都没再抓到
        （``capture_scheme`` 为 ``None``）。这是**必须报**的 —— 修复前它被静默放过，
        于是合并后生成物不再发 Authorization，Bearer 站点的工具会全部 401，而用户
        在任何输出里都看不到发生过这件事；
      * 同一域名**混用**多种登录方式：``conflict_schemes`` 给出观测到的全部 scheme
        （如 ``["Bearer", "Basic"]``）。它不是错误（S13 起按端点各自取用），
        但要让用户知道，免得以为是抓包串了。

    新主机（registry 里没有）不算漂移 —— 否则每扩一个域名都会被判成鉴权变化而拒绝合并。
    """
    changes: list[dict[str, Any]] = []
    for host, raw in (capture_hosts or {}).items():
        info = raw or {}
        if host not in (registry_hosts or {}):
            continue
        old_scheme = (registry_hosts.get(host) or {}).get("scheme")
        new_scheme = info.get("scheme")
        if old_scheme and new_scheme and old_scheme != new_scheme:
            changes.append({"host": host, "registry_scheme": old_scheme,
                            "capture_scheme": new_scheme})
        elif old_scheme and not new_scheme:
            changes.append({"host": host, "registry_scheme": old_scheme,
                            "capture_scheme": None})
        observed = sorted({str(s) for s in (info.get("schemes") or []) if s})
        if len(observed) > 1:
            changes.append({"host": host, "registry_scheme": old_scheme,
                            "capture_scheme": new_scheme,
                            "conflict_schemes": observed})
    return changes


def merge_registry(
    project_dir: str | Path,
    entries: list[dict[str, Any]],
    hosts: dict[str, Any],
    session_id: str,
    endpoint_keys: list[tuple[str, str, str]] | None = None,
    allow_auth_change: bool = False,
    seen_keys: Iterable[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    """Merge confirmed capture entries into the registry. Bumps registry_version.

    ``seen_keys``：本轮抓包里**实际见过**的端点键（analysis 里的**全部**端点，含被
    跳过规则滤掉的那些）。只影响「未见」的判定：``entries`` 是已经过滤过的，若拿它当
    「见过的全集」，一条「见过、但本轮被判成噪音/非 JSON」的端点会被标成
    ``unseen_since`` —— 明明是这次抓到的，却告诉使用者「本轮没见到」，方向完全反了。
    不给则退化为与 ``entries`` 同义（保住库层的既有行为）。

    Safety rules:
      * locked project → refuse;
      * Authorization scheme drift → refuse unless allow_auth_change=True;
      * merge is additive: existing entries are never deleted, only marked
        unseen_since if absent from this capture; parameter changes update the
        entry but never remove old defaults (backward compatible);
      * parameter **samples accumulate** and `sample_count` grows, so a value that
        later captures show to vary stops qualifying as a baked-in default (F7);
      * `description` is refreshed from the capture only while the stored entry is
        still capture-sourced — a user-edited description survives every merge
        (`description_source == "user"`, persisted in registry.json) (F7).
    """
    directory = project_path(project_dir)
    project = load_project(directory)
    if project.get("locked"):
        return {"success": False, "error": "project_locked",
                "message": "project.json 标记为 locked，拒绝合并。解锁需人工修改 project.json。"}
    registry = load_registry(directory)

    # Hard stop on auth scheme drift. 「同一域名混用多种方式」只是告知（S13 起生成物
    # 按端点各自取用），不拦合并 —— 否则正常站点会被判成「鉴权变化」而卡死。
    host_changes = diff_hosts(registry.get("hosts", {}), hosts)
    scheme_drift = [c for c in host_changes if not is_conflict_change(c)]
    if scheme_drift and not allow_auth_change:
        return {"success": False, "error": "auth_scheme_changed", "auth_changes": scheme_drift,
                "message": auth_change_message(scheme_drift)}

    existing = {_match_key(e): e for e in registry.get("endpoints", [])}
    # F6 向后兼容：旧 registry 里的条目没有 endpoint_id，合并时补齐（确定性派生），
    # 于是老项目打开后照常能用端点衔接键。
    for entry in existing.values():
        if not entry.get("endpoint_id"):
            entry["endpoint_id"] = endpoint_registry_id(entry)
    version = int(registry.get("registry_version", 0)) + 1
    selected = set(endpoint_keys) if endpoint_keys else None

    added, updated, unseen_now = 0, 0, 0
    fresh_keys = {_match_key(e) for e in entries}
    # 「本轮见过」是**抓包里出现过的全部端点**，不是过滤后的 entries —— 见 seen_keys。
    seen = fresh_keys if seen_keys is None else {tuple(key) for key in seen_keys}
    for key, entry in existing.items():
        if key not in seen and entry.get("unseen_since") is None and entry.get("status") == "active":
            entry["unseen_since"] = version
            unseen_now += 1
    # 见过、但**这一轮不需要并入**的端点（被跳过规则滤掉，如本轮被判成噪音/非 JSON）：
    # 它的 unseen_since 必须清掉。它明明在抓包里出现了，留着旧标记等于继续告诉使用者
    # 「本轮没见到」——与上面给的 seen_keys 是同一条道理的另一半。
    for key, entry in existing.items():
        if key in seen and key not in fresh_keys and entry.get("unseen_since") is not None:
            entry["unseen_since"] = None
    for key, entry in ((k, e) for k, e in {_match_key(e): e for e in entries}.items()):
        if selected is not None and key not in selected:
            continue
        old = existing.get(key)
        if old is None:
            old = dict(entry)
            old["source_sessions"] = [session_id]
            registry["endpoints"].append(old)
            added += 1
        else:
            # Additive update: 参数样本**累积**去重（旧值在前），新参数名照旧新增。
            # F7：修复前只加新参数名、从不扩已有参数的值列表，于是「>=2 个样本才写默认值」
            # 这条闸门被第一次抓包的单个值永远满足——后面抓到该参数会变，也照样把
            # 抓包当时的真实值烘进生成的代码。
            merged_qp = {k: list(v or []) for k, v in (old.get("query_params") or {}).items()}
            for k, v in (entry.get("query_params") or {}).items():
                merged_qp[k] = _accumulate_values(merged_qp.get(k), v)
            old["query_params"] = merged_qp
            # Issue #23: 表单体字段同样累积（旧值保留）
            merged_body = {k: list(v or [])
                           for k, v in (old.get("request_body_params") or {}).items()}
            for k, v in (entry.get("request_body_params") or {}).items():
                merged_body[k] = _accumulate_values(merged_body.get(k), v)
            old["request_body_params"] = merged_body
            # F7：样本计数随累积增长（**仅供噪音启发式**：它只回答「这个端点被采样
            # 了多少次」，不再参与任何默认值判定 —— 本次重做后那条路只看
            # `*_param_evidence` 里的「不同请求」比较）。
            old["sample_count"] = (int(old.get("sample_count") or 0)
                                   + int(entry.get("sample_count") or 0))
            # 本次重做：参数证据跨轮合并。**不能累加不同请求数**——同一个请求在两轮
            # 里各抓一次仍然是同一个请求，累加会把它洗成「有对照」，默认值照烘
            # （正是 `sample_count >= 2` 旧门槛的错法换了个形态）。见
            # analyzer.merge_param_evidence：requests 取 max、present_in 取 min、
            # values 取并集 —— 证据只会变弱，不会变强。
            old["distinct_request_count"] = max(
                int(old.get("distinct_request_count") or 0),
                int(entry.get("distinct_request_count") or 0))
            old["insufficient_samples"] = old["distinct_request_count"] < 2
            for field in ("query_param_evidence", "request_body_param_evidence"):
                merged_evidence = dict(old.get(field) or {})
                for name, evidence in (entry.get(field) or {}).items():
                    merged_evidence[name] = merge_param_evidence(
                        merged_evidence.get(name), evidence)
                old[field] = merged_evidence
            # 逐参数溯源：用户写的优先（抓包不产生溯源，故不会被抓包刷掉）。
            old["param_provenance"] = {
                **(entry.get("param_provenance") or {}),
                **(old.get("param_provenance") or {})}
            # S13：端点级鉴权载体跨轮取并集。只增不减 —— 上一轮抓到 Bearer、这一轮
            # 只抓到 cookie，说明该接口两种都可能需要；去掉任何一种都可能让工具 401。
            merged_hints = [h for h in (old.get("auth_hint") or []) if h and h != "none"]
            for hint in entry.get("auth_hint") or []:
                if hint and hint != "none" and hint not in merged_hints:
                    merged_hints.append(hint)
            if merged_hints or not old.get("auth_hint"):
                old["auth_hint"] = merged_hints or list(entry.get("auth_hint") or [])
            # 「样本不足」提示必须与合并后的证据状态一致：证据够了就撤掉，
            # 否则会把一条早已过期的警告一直挂在工具文档里。
            old["evidence_hint"] = (
                INSUFFICIENT_SAMPLES_HINT.format(count=old["distinct_request_count"])
                if old["insufficient_samples"] else None)
            # F7：description 只在**用户没有改过**时才被抓包文本刷新。
            # 来源标记存在 registry 条目里（随 registry.json round-trip），
            # 用户手写过的描述不会被下一轮 merge 静默抹掉。
            if entry.get("description") and not _description_is_user_edited(old):
                old["description"] = entry["description"]
                old["description_source"] = (
                    DESCRIPTION_SOURCE_USER if _description_is_user_edited(entry)
                    else DESCRIPTION_SOURCE_CAPTURE)
            old.setdefault("description_source", DESCRIPTION_SOURCE_CAPTURE)
            # Fix 1 / Feature：这两条标记只能「置上」不能「抹掉」——
            # 已经被显式点名包含过的端点，重渲染时仍要显示在 README 的「显式点名」一节；
            # 而由抓包证据认定是文件下载的端点，也不能因为下一次合并没有再算出来就
            # 悄悄退回「按 JSON 解析」的工具形态。
            old["forced_include"] = bool(old.get("forced_include") or entry.get("forced_include"))
            old["file_response"] = bool(old.get("file_response") or entry.get("file_response"))
            if entry.get("request_schema"):
                old["request_schema"] = entry["request_schema"]
            if entry.get("response_schema"):
                old["response_schema"] = entry["response_schema"]
            old["unseen_since"] = None
            if session_id not in old.get("source_sessions", []):
                old.setdefault("source_sessions", []).append(session_id)
            updated += 1

    # Merge host auth info (additive).
    registry_hosts = registry.setdefault("hosts", {})
    for host, info in (hosts or {}).items():
        info = info or {}
        slot = registry_hosts.setdefault(host, {})
        # S13：Cookie 名单与「观测到的全部 scheme」一律取**并集**，不再整键覆盖。
        # 覆盖会让某一轮的窄集合把之前抓到的名字冲掉（实测 NITRO_SK 就是这么丢的），
        # 而 Cookie 是集合语义，少一个就 401 且服务端不说是缺谁。
        merged_names = list(slot.get("cookie_names") or [])
        for name in info.get("cookie_names") or []:
            if name not in merged_names:
                merged_names.append(name)
        if merged_names:
            slot["cookie_names"] = merged_names
        merged_schemes = list(slot.get("schemes") or [])
        for scheme in info.get("schemes") or []:
            if scheme and scheme not in merged_schemes:
                merged_schemes.append(scheme)
        if merged_schemes:
            slot["schemes"] = merged_schemes
        # scheme 只增不减：这一轮没抓到 Authorization（None）**不得**把已有的方案抹掉。
        # 抹掉之后生成物就不再发 Authorization，Bearer 站点的工具会全 401；真要换方式
        # 得由一次明确抓到新方案的抓包来完成（或人工改 registry.json）。
        new_scheme = info.get("scheme")
        if new_scheme or not slot.get("scheme"):
            slot["scheme"] = new_scheme or slot.get("scheme")

    registry["registry_version"] = version
    registry["updated_at"] = _now()
    project["registry_version"] = version
    (directory / "project.json").write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
    save_registry(directory, registry)
    # Provenance note.
    note = {"session_id": session_id, "merged_at": _now(), "version": version,
            "added": added, "updated": updated, "marked_unseen": unseen_now}
    (directory / "captures" / f"{session_id}.json").write_text(
        json.dumps(note, ensure_ascii=False, indent=2), encoding="utf-8")
    # 「同一域名混用多种登录方式」只告知、不拦（S13：生成物按端点各自取用凭据）。
    # 键常驻，消费方可无条件读；无事可报时是空列表 / 空串。
    conflicts = [c for c in host_changes if is_conflict_change(c)]
    return {"success": True, "registry_version": version, "added": added, "updated": updated,
            "marked_unseen": unseen_now, "total_endpoints": len(registry["endpoints"]),
            "auth_conflicts": conflicts,
            "auth_conflicts_hint": auth_conflict_message(conflicts)}


# --------------------------------------------------------------------------- #
# export (user-mode package: physically no write capability)
# --------------------------------------------------------------------------- #
USER_PACKAGE_FILES = ["server.py", "requirements.txt", ".env.example", "README.md",
                      "smoke_test.py", "registry.json", "project.json"]


def export_user_package(project_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Copy the user-facing subset of a project. The user package keeps
    registry.json/project.json only as read-only metadata (for tool_catalog);
    it contains no code able to modify them.

    ``registry.json`` 是**分发给第三方的产物**，所以这里不直接 copy：先反序列化、
    把 ``sample_url`` 去凭据再写出。老项目即使从没被 re-save 过，导出的包也不会
    夹带抓包 URL 里的 query 取值（结构不变，仍是收件人调用工具所依赖的那份 registry）。
    """
    src = project_path(project_dir)
    dst = Path(output_dir)
    dst.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in USER_PACKAGE_FILES:
        source = src / name
        if not source.exists():
            continue
        if name == "registry.json":
            registry = json.loads(source.read_text(encoding="utf-8"))
            (dst / name).write_text(
                json.dumps(_sanitize_registry_urls(registry), ensure_ascii=False, indent=2),
                encoding="utf-8")
        else:
            shutil.copy2(source, dst / name)
        copied.append(name)
    return {"success": True, "output_dir": str(dst), "files": copied,
            "note": "用户态分发包：仅含运行与诊断能力，不含任何 registry 写入/再生成代码。"}
