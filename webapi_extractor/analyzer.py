"""Pure analysis helpers used by the capture analyzer."""

from __future__ import annotations

import re
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .crypto_analyzer import detect_password_encryption


VALUE_SHAPES = (
    re.compile(r"^\d+$"),                      # 123, 6463
    re.compile(r"^[0-9a-f]{8,}$", re.I),       # hex ids
    # Generic alphanumeric ids MUST contain a digit and be >= 6 chars — otherwise
    # plain words like "community" (9 chars, no digit) or "next2" (5 chars) match
    # and whole literal path segments get wrongly collapsed into {id}.
    re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{6,}$"),
)


# --------------------------------------------------------------------------- #
# C-3: 内置噪音规则（标记 noise:true，不删除——保留人工复核权）
#
# Issue #2: 规则保持**通用**——只收录跨站点成立的遥测/指纹域名与框架内部
# 元数据路径，不得硬编码单一目标系统（Issue #8 的教训）。
# --------------------------------------------------------------------------- #
NOISE_PATH_PATTERNS = (
    # 通用埋点/统计路径
    r"/system/stat/", r"/system/traffic/", r"/tracking/", r"heartbeat",
    r"/breadcrumb", r"/config/menu/", r"/config/banner", r"/visit-history/",
    r"/analytics/", r"/telemetry/", r"/beacon", r"^(?:log|collect)[/-]",
    # 框架/服务端内部元数据（Dynamics/CRM、SAP、SharePoint、Graph 等常见形态）
    r"GetClientMetadata", r"/uclient/", r"/_static/", r"/webresources/",
    r"/formattedvalue|/metadata/|/\$metadata\b",
)

# 遥测/埋点/浏览器指纹域名（通用生态，可被 tracking_domains 参数扩展）
NOISE_DOMAINS = {
    # 中文互联网生态
    "r.clarity.ms", "otheve.beacon.qq.com", "aegis.qq.com", "graph.qq.com",
    "www.google-analytics.com", "analytics.google.com", "log.zhugeio.com",
    # Microsoft 生态（遥测 + 浏览器配置/指纹）
    "vortex.data.microsoft.com", "browser.pipe.aria.microsoft.com",
    "fpc.msedge.net", "v10.events.data.microsoft.com",
    "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
    # 其它常见遥测/分析生态
    "www.googletagmanager.com", "stats.g.doubleclick.net",
    "api.segment.io", "cdn.segment.com", "sentry.io", "browser.sentry-cdn.com",
    "js.sentry-cdn.com", "rum.browser-intake-datadoghq.com",
    "browser-intake-datadoghq.com", "api.amplitude.com", "cdn.amplitude.com",
    "api.mixpanel.com", "cdn.mxpnl.com", "static.hotjar.com", "script.hotjar.com",
    "in.hotjar.com", "connect.facebook.net", "www.facebook.com",
    "bat.bing.com", "c.clarity.ms", "sb.scorecardresearch.com",
}
# 子域后缀匹配（同域下大量随机子域的埋点）
NOISE_HOST_SUFFIXES = (
    ".clarity.ms", ".hotjar.com", ".sentry.io", ".datadoghq.com",
    ".amplitude.com", ".mixpanel.com", ".segment.io", ".doubleclick.net",
)


def _is_noise(host: str, path: str) -> bool:
    if host in NOISE_DOMAINS or host.endswith(NOISE_HOST_SUFFIXES):
        return True
    return any(re.search(p, path, re.I) for p in NOISE_PATH_PATTERNS)


def _heavy_response_suggestion(
    sample_count: int,
    total_size: int,
    max_size: int,
    response_bytes: int,
    sample_threshold: int,
) -> dict[str, Any] | None:
    """Issue #2 体积/频次启发式：只标记「待复核」，绝不直接当噪音删除。

    命中条件（任一）：
      * 累计响应体 >= 阈值（默认 1MB）——通常是框架元数据/静态资源；
      * 单个响应体 >= 阈值且累计 >= 阈值/2——单次巨型响应；
      * 采样次数 >= 阈值（默认 50）——轮询/心跳类高频端点。
    """
    reasons: list[str] = []
    if total_size >= response_bytes:
        reasons.append(f"total_response_bytes={total_size}>={response_bytes}")
    if max_size >= response_bytes and total_size >= response_bytes // 2:
        reasons.append(f"single_response_bytes={max_size}>={response_bytes}")
    if sample_count >= sample_threshold:
        reasons.append(f"sample_count={sample_count}>={sample_threshold}")
    if not reasons:
        return None
    return {"review_suggested": True, "reasons": reasons,
            "total_response_bytes": total_size, "max_response_bytes": max_size,
            "sample_count": sample_count}


# --------------------------------------------------------------------------- #
# B-1: 命名参数化（单样本也能参数化——SPA 每个资源通常只请求一次）
# --------------------------------------------------------------------------- #
# 通用层只保留真·通用映射；站点专属语义（article_id / message_id 等）必须外置到
# site_profiles/<site>.py 的 param_alias，由 get_param_alias() 按 host 覆盖/扩展（Issue #8）。
PARAM_ALIAS = {"id": "id", "page": "page"}
PARAM_ALIAS_TEMPLATE = "{name}_id"


def get_param_alias(host: str | None = None) -> dict[str, str]:
    """通用别名 + 站点档案别名（站点优先）。无档案时退化为纯通用映射。"""
    if not host:
        return dict(PARAM_ALIAS)
    profile = _load_site_profile(host)
    if not profile:
        return dict(PARAM_ALIAS)
    try:
        from .site_profiles import merge_param_alias
        return merge_param_alias(PARAM_ALIAS, profile)
    except Exception:
        return dict(PARAM_ALIAS)


def _is_id_segment(seg: str) -> bool:
    """数字 ID、下划线/逗号分隔数字（item_merged.10_773）、<type>-<id>（achievement-12782）。"""
    return bool(
        re.fullmatch(r"\d+([_,]\d+)*", seg)
        or re.fullmatch(r"item_merged\.\d+(_\d+)*", seg)
        or re.fullmatch(r"[a-z_]+-\d+([_,]\d+)*", seg)
    )


def parameterize(path: str, host: str | None = None) -> tuple[str, list[str]]:
    """把路径中的 ID 段替换为按前段命名的参数，返回 (新路径, 参数名列表)。

    host 用于加载站点档案的专属别名（Issue #8）；不传则只用通用映射。
    """
    alias = get_param_alias(host)
    segs = path.split("/")
    out: list[str] = []
    names: list[str] = []
    for i, seg in enumerate(segs):
        if not (_is_id_segment(seg) or re.fullmatch(r"\{[^}]+\}", seg)):
            out.append(seg)
            continue
        if re.fullmatch(r"\{[^}]+\}", seg):
            out.append(seg)  # 已参数化的占位符保持原样
            continue
        prev = segs[i - 1] if i > 0 else ""
        base = re.sub(r"[^a-z0-9]+", "_", prev.lower()).strip("_")
        name = alias.get(base) or (PARAM_ALIAS_TEMPLATE.format(name=base) if base else "id")
        if name in names:
            name = f"{name}_{names.count(name) + 1}"
        names.append(name)
        out.append(f"{{{name}}}")
    return "/".join(out), names


# --------------------------------------------------------------------------- #
# C-1: 账号密码登录接口识别（生成 login/auth_status 专用工具）
# --------------------------------------------------------------------------- #
LOGIN_HINTS = ("login", "signin", "sign_in", "authorize", "auth/token")
ACCOUNT_KEYS = ("account", "username", "user_name", "phone", "mobile", "email", "user")
PASSWORD_KEYS = ("password", "passwd", "pwd", "secret")
TOKEN_KEYS = ("token", "access_token", "accesstoken", "jwt")


def _match_key(props: dict, candidates: tuple[str, ...]) -> str | None:
    for key in props:
        if key.lower() in candidates:
            return key
    for key in props:
        if any(c in key.lower() for c in candidates):
            return key
    return None


def _find_token_path(schema: Any, path: tuple[str, ...] = ()) -> list[str] | None:
    if not isinstance(schema, dict):
        return None
    for key, sub in (schema.get("properties") or {}).items():
        if key.lower() in TOKEN_KEYS and (sub or {}).get("type") == "string":
            return list(path) + [key]
    for key, sub in (schema.get("properties") or {}).items():
        found = _find_token_path(sub, path + (key,))
        if found:
            return found
    return None


def detect_auth_login(endpoints: list[dict[str, Any]], session_dir: Path | None = None) -> dict[str, Any] | None:
    """找到「账号+密码换取 token」的接口；找不到强信号则返回 None。"""
    for ep in endpoints:
        props = ((ep.get("request_schema") or {}).get("properties")) or {}
        if not props:
            continue
        path_low = ep["path"].lower()
        if not any(h in path_low for h in LOGIN_HINTS):
            continue
        account_field = _match_key(props, ACCOUNT_KEYS)
        password_field = _match_key(props, PASSWORD_KEYS)
        if not (account_field and password_field):
            continue
        token_path = _find_token_path(ep.get("response_schema")) or ["data", "token"]
        verify = next(
            (c for c in endpoints
             if c["method"] == "GET" and c.get("auth_required") and "/my" in c["path"].lower()),
            None,
        )
        login = {
            "host": ep["host"],
            "method": ep.get("method", "POST"),
            "path": ep["path"],
            "query_params": {k: (v or [""])[0] for k, v in (ep.get("query_params") or {}).items()},
            "account_field": account_field,
            "password_field": password_field,
            "token_path": token_path,
            "verify": ({"host": verify["host"], "path": verify["path"]} if verify else None),
        }
        enc = detect_password_encryption(session_dir, login)
        if enc:
            login["password_encryption"] = enc
        return login
    return None


# --------------------------------------------------------------------------- #
# 站点档案（可选加载：语义化命名与站点专属噪音规则外置在 site_profiles/）
# --------------------------------------------------------------------------- #
def _load_site_profile(host: str) -> dict[str, Any] | None:
    try:
        from .site_profiles import get_profile
        return get_profile(host)
    except Exception:
        return None


def _looks_like_parameter(value: str) -> bool:
    return any(pattern.fullmatch(value) for pattern in VALUE_SHAPES)


@dataclass(frozen=True)
class NormalizedPath:
    path: str
    sample_indexes: tuple[int, ...]
    parameter_names: tuple[str, ...]


def normalize_paths(paths: list[str]) -> list[NormalizedPath]:
    """Group paths conservatively, preserving literals such as ``latest``."""
    groups: dict[tuple[int, ...], list[tuple[int, list[str]]]] = defaultdict(list)
    for index, path in enumerate(paths):
        segments = [segment for segment in urlsplit(path).path.split("/") if segment]
        groups[tuple([len(segments)])].append((index, segments))

    results: list[NormalizedPath] = []
    for entries in groups.values():
        if len(entries) == 1:
            index, segments = entries[0]
            results.append(NormalizedPath("/" + "/".join(segments), (index,), ()))
            continue
        columns = list(zip(*(segments for _, segments in entries)))
        variants: dict[tuple[str, ...], list[int]] = defaultdict(list)
        for row, (index, _) in enumerate(entries):
            normalized: list[str] = []
            for column in columns:
                values = list(column)
                # Strict ">" : with 2 identical samples distinct_ratio == 0.5 exactly,
                # and a constant column must never be parameterized.
                distinct_ratio = len(set(values)) / len(values)
                shaped_ratio = sum(_looks_like_parameter(value) for value in values) / len(values)
                current = values[row]
                normalized.append("{id}" if distinct_ratio > 0.5 and shaped_ratio >= 0.8 and _looks_like_parameter(current) else current)
            variants[tuple(normalized)].append(index)
        for normalized, indexes in variants.items():
            names = tuple("id" for value in normalized if value == "{id}")
            results.append(NormalizedPath("/" + "/".join(normalized), tuple(indexes), names))
    return sorted(results, key=lambda result: result.sample_indexes)


STATIC_TYPES = {"Script", "Stylesheet", "Image", "Font", "Media"}
STATIC_EXTENSIONS = re.compile(r"\.(?:js|css|map|png|jpg|jpeg|gif|svg|woff2?|ico|webp)(?:\?|$)", re.I)


def _json_schema(value: Any, samples: list[Any] | None = None) -> dict[str, Any]:
    samples = samples or [value]
    if isinstance(value, dict):
        properties = {}
        for key in value:
            values = [sample[key] for sample in samples if isinstance(sample, dict) and key in sample]
            properties[key] = _json_schema(values[0], values)
        return {"type": "object", "properties": properties, "required": [key for key in value if all(isinstance(sample, dict) and key in sample for sample in samples)]}
    if isinstance(value, list):
        return {"type": "array", "items": _json_schema(value[0]) if value else {}}
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    return {"type": "string"}


# --------------------------------------------------------------------------- #
# Issue #3: OData / OData-like $batch 子请求解析
#
# POST /api/data/v9.0/$batch（multipart/mixed）内部的子请求才是真正的业务查询，
# 顶层 URL 只看到 $batch 一个端点。此机制通用于所有 multipart 批处理服务端：
# Dynamics 365 / SharePoint / SAP Gateway / Salesforce Composite / Graph API。
# 子请求解析为独立端点后，才能被生成为独立 MCP 工具（调用方无需手工拼 multipart）。
# --------------------------------------------------------------------------- #
_MULTIPART_CT = re.compile(r"multipart/\w+", re.I)
_BOUNDARY_RE = re.compile(r'boundary\s*=\s*"?([^";,\s]+)"?', re.I)
# 子请求起始行：METHOD <relative-path> HTTP/1.1（路径可能含复杂查询串）
_METHOD_LINE = re.compile(r"^([A-Z]{3,7})[ \t]+(\S+)[ \t]+HTTP/[\d.]+", re.M)
# 显式声明 OData 批处理的 URL 形态
_BATCH_URL = re.compile(r"(?:^|/)\$(?:batch|b1)\b", re.I)
# 抓包中的 postData 可能是 CRLF 或 LF（Chromium/存储链路会归一化），两者都要兼容。
_BLANK_LINE = re.compile(r"\r?\n\r?\n")


def _header_value(headers: dict[str, Any] | None, name: str) -> str:
    """大小写不敏感地取头值（redact_headers 保留原始大小写，可能是 content-type）。"""
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _parse_json_batch(body: str) -> list[dict[str, Any]]:
    """OData JSON-batch / Graph batch：{"requests": [{method, url, body}]}。"""
    try:
        payload = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return []
    requests = (payload or {}).get("requests") if isinstance(payload, dict) else None
    if not isinstance(requests, list):
        return []
    return [{"method": str(item.get("method", "GET")).upper(), "path": item.get("url", ""),
             "headers": item.get("headers") or {}, "body": item.get("body")}
            for item in requests if isinstance(item, dict) and item.get("url")]


def _parse_multipart_requests(body: str | None,
                              content_type: str | None = None) -> list[dict[str, Any]]:
    """解析 multipart/mixed 批处理请求体，返回 [{method, path, headers, body}]。

    兼容三种形态（通用，不针对单一站点）：
      * OData multipart/mixed（Dynamics / SharePoint / SAP Gateway）；
      * Salesforce Composite 风格的 JSON batch（{"batchRequests": [...]}）；
      * Graph JSON-batch（{"requests": [...]}）。
    boundary 优先取 Content-Type，缺失时从 body 首个 ``--`` 行推断——
    抓包的 postData 存的就是 multipart 原文。
    """
    if not body:
        return []
    lowered = (content_type or "").lower()
    if "json" in lowered:
        parsed = _parse_json_batch(body)
        if parsed:
            return parsed

    boundary = ""
    match = _BOUNDARY_RE.search(content_type or "")
    if match:
        boundary = match.group(1)
    if not boundary:
        first_line = body.lstrip("﻿ \t\r\n").split("\n", 1)[0].strip()
        if first_line.startswith("--"):
            boundary = first_line[2:].strip()
    if not boundary:
        return _parse_json_batch(body)

    out: list[dict[str, Any]] = []
    for chunk in body.split("--" + boundary)[1:]:
        if chunk.startswith("--"):
            continue  # 结束标记 --boundary--
        match = _METHOD_LINE.search(chunk)
        if not match:
            continue
        method, target = match.group(1).upper(), match.group(2)
        # 子请求自身的头与体以空行分隔；无体时空行后即为下一个 boundary 段。
        remainder = chunk[match.end():]
        pieces = _BLANK_LINE.split(remainder, 1)
        request_body = pieces[1] if len(pieces) == 2 else ""
        # 嵌套 changeset 的结尾 boundary（--cs1--）不属于子请求体，需截掉。
        request_body = re.split(r"\r?\n--", request_body, 1)[0].strip("\r\n")
        out.append({"method": method, "path": target, "headers": {}, "body": request_body or None})
    return out


def _absolute_url(base_netloc: str, scheme: str, target: str) -> str:
    """把子请求的相对路径与父请求的 scheme+host 拼接成绝对 URL。"""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"{scheme or 'https'}://{base_netloc}" + (target if target.startswith("/") else "/" + target)


def _load_events(capture_path: Path) -> list[dict[str, Any]]:
    events = []
    if not capture_path.exists():
        return events
    for line in capture_path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                events.append(value)
        except json.JSONDecodeError:
            continue
    return events


def analyze_capture(
    session_dir: Path,
    tracking_domains: set[str] | None = None,
    response_bytes_threshold: int = 1024 * 1024,
    sample_count_threshold: int = 50,
) -> dict[str, Any]:
    """分析一次抓包。response_bytes_threshold / sample_count_threshold 为
    Issue #2 的体积与频次启发式阈值（只产生 review_suggested 标记）。"""
    events = _load_events(session_dir / "capture.jsonl")
    tracking_domains = tracking_domains or set()
    requests = {event.get("requestId"): event for event in events if event.get("type") == "request"}
    responses = {event.get("requestId"): event for event in events if event.get("type") == "response"}
    bodies = {event.get("requestId"): event for event in events if event.get("type") == "response_body"}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    filtered = 0
    auth_candidates: list[dict[str, Any]] = []
    for request_id, request in requests.items():
        url = request.get("url", "")
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if request.get("method") == "OPTIONS" or request.get("resourceType") in STATIC_TYPES or STATIC_EXTENSIONS.search(path) or parsed.netloc in tracking_domains:
            filtered += 1
            continue
        response = responses.get(request_id, {})
        body = bodies.get(request_id, {})
        sample = {"request": request, "response": response, "body": body}
        grouped[(request.get("method", "GET"), parsed.netloc)].append(sample)
        if request.get("auth_candidate"):
            auth_candidates.append({"request_id": request_id, "url": url, "method": request.get("method"), "token_paths": request.get("token_paths", [])})
        # Issue #3: 解析 multipart/mixed（或 JSON-batch）里的子请求，作为独立端点。
        # 仅对显式批处理 URL 或 multipart Content-Type 的请求尝试，避免误伤普通 POST。
        content_type = _header_value(request.get("headers"), "Content-Type")
        post_data = request.get("postData")
        if post_data and (_BATCH_URL.search(path) or _MULTIPART_CT.search(content_type)):
            scheme = parsed.scheme or "https"
            for sub in _parse_multipart_requests(post_data, content_type):
                sub_url = _absolute_url(parsed.netloc, scheme, sub["path"])
                grouped[(sub["method"], parsed.netloc)].append({
                    "request": {
                        "url": sub_url, "method": sub["method"],
                        "headers": request.get("headers", {}),
                        "postData": sub.get("body"),
                        "resourceType": "XHR", "auth_candidate": request.get("auth_candidate"),
                        "token_paths": request.get("token_paths", []),
                    },
                    "response": {},
                    # 子请求响应体无独立记录；复用父请求的元数据（size 等）
                    "body": {},
                    "batch_parent": {"request_id": request_id, "url": url,
                                     "method": request.get("method"), "path": path},
                })
    endpoints: list[dict[str, Any]] = []
    for (method, host), samples in grouped.items():
        normalized = normalize_paths([sample["request"].get("url", "") for sample in samples])
        for item in normalized:
            selected = [samples[index] for index in item.sample_indexes]
            first = selected[0]
            request_body_values = []
            response_values = []
            total_size = 0
            max_size = 0
            for sample in selected:
                request_body = sample["request"].get("postData")
                response_body = sample["body"].get("body")
                size = int(sample["body"].get("size") or 0)
                total_size += size
                max_size = max(max_size, size)
                for target, values in ((request_body, request_body_values), (response_body, response_values)):
                    try:
                        parsed_value = json.loads(target) if target else None
                    except (TypeError, json.JSONDecodeError):
                        parsed_value = None
                    if parsed_value is not None:
                        values.append(parsed_value)
            endpoint_id = f"ep_{len(endpoints) + 1:03d}"
            auth_required = any(sample["request"].get("headers", {}).get("Authorization") or sample["request"].get("auth_candidate") for sample in selected)
            # Query-parameter samples across all captured URLs of this endpoint —
            # the generator turns these into typed function signatures.
            query_params: dict[str, list[str]] = defaultdict(list)
            for sample in selected:
                for key, value in parse_qsl(urlsplit(sample["request"].get("url", "")).query):
                    if value not in query_params[key]:
                        query_params[key].append(value)
            endpoints.append({
                "endpoint_id": endpoint_id,
                "method": method,
                "host": host,
                "path": item.path,
                "url": first["request"].get("url"),
                "sample_count": len(selected),
                "single_sample": len(selected) < 2,
                "auth_required": auth_required,
                "query_params": {k: v for k, v in query_params.items()},
                "request_schema": _json_schema(request_body_values[0], request_body_values) if request_body_values else None,
                "response_schema": _json_schema(response_values[0], response_values) if response_values else None,
                "description": None,
                "notes": None,
                "param_name_guessed": bool(item.parameter_names),
                "total_response_bytes": total_size,
                "max_response_bytes": max_size,
                # Issue #3 溯源：子请求记录其父 $batch，便于人工复核拼装关系
                "batch_parent": first.get("batch_parent"),
            })
    # ---- C-3: 噪音标记（不删除，保留人工复核权） --------------------------
    for endpoint in endpoints:
        endpoint["noise"] = _is_noise(endpoint["host"], endpoint["path"])

    # ---- B-1: 命名参数化二遍处理 + 同构合并 -------------------------------
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ep in endpoints:
        new_path, param_names = parameterize(ep["path"], ep["host"])
        ep["path_params"] = param_names or [seg.strip("{}") for seg in new_path.split("/") if seg.startswith("{")]
        key = (ep["method"], ep["host"], new_path)
        if key not in merged:
            ep = dict(ep)
            ep["path"] = new_path
            ep["query_params"] = dict(ep.get("query_params") or {})
            merged[key] = ep
        else:
            keep = merged[key]
            keep["sample_count"] = keep.get("sample_count", 1) + ep.get("sample_count", 1)
            keep["auth_required"] = keep.get("auth_required") or ep.get("auth_required")
            keep["noise"] = keep.get("noise") and ep.get("noise")  # 任一非噪音即保留
            keep["total_response_bytes"] = keep.get("total_response_bytes", 0) + ep.get("total_response_bytes", 0)
            keep["max_response_bytes"] = max(keep.get("max_response_bytes", 0), ep.get("max_response_bytes", 0))
            for k, v in (ep.get("query_params") or {}).items():
                bucket = keep["query_params"].setdefault(k, [])
                for val in v:
                    if val not in bucket:
                        bucket.append(val)
    endpoints = list(merged.values())
    for i, ep in enumerate(endpoints, start=1):
        ep["endpoint_id"] = f"ep_{i:03d}"

    # ---- Issue #2: 体积/频次启发式——只标记「待复核」，不删除、不当噪音 -----
    for ep in endpoints:
        hint = _heavy_response_suggestion(
            ep.get("sample_count", 1),
            ep.get("total_response_bytes", 0),
            ep.get("max_response_bytes", 0),
            response_bytes_threshold,
            sample_count_threshold,
        )
        ep["review_suggested"] = bool(hint)
        ep["review_reasons"] = hint["reasons"] if hint else []

    # ---- 站点档案（可选）：语义化 tool_name / 描述 / 站点专属噪音 ----------
    profile = _load_site_profile(base_host) if (base_host := _majority_host(endpoints)) else None
    if profile:
        for ep in endpoints:
            info = profile["describe"](ep["host"], ep["path"])
            if info:
                ep["tool_name"], ep["description"] = info
            if any(re.search(p, ep["path"]) for p in profile.get("drop_path_patterns", [])) \
                    or ep["host"] in profile.get("drop_hosts", []):
                ep["noise"] = True

    # ---- C-1: 登录接口识别（移出普通工具列表，转 auth_login） --------------
    auth_login = detect_auth_login(endpoints, session_dir)
    if auth_login:
        endpoints = [e for e in endpoints
                     if not (e["host"] == auth_login["host"] and e["path"] == auth_login["path"])]

    host_counts = defaultdict(int)
    for endpoint in endpoints:
        host_counts[endpoint["host"]] += 1
    base_host = max(host_counts, key=host_counts.get) if host_counts else None
    for endpoint in endpoints:
        endpoint["cross_host"] = endpoint["host"] != base_host
    # Per-host auth schemes: redacted headers keep the scheme ("Basic ***") and
    # cookie names, which is exactly what the generator needs to emit correct auth.
    auth_schemes: dict[str, dict[str, Any]] = {}
    for (method, host), samples in grouped.items():
        scheme: str | None = None
        cookie_names: list[str] = []
        for sample in samples:
            headers = sample["request"].get("headers", {}) or {}
            for name, value in headers.items():
                if name.lower() == "authorization" and value:
                    scheme = str(value).split(" ", 1)[0]
                elif name.lower() == "cookie" and value:
                    for part in str(value).split(";"):
                        cname = part.split("=", 1)[0].strip()
                        if cname and cname not in cookie_names:
                            cookie_names.append(cname)
        if host not in auth_schemes or scheme:
            auth_schemes[host] = {"scheme": scheme or auth_schemes.get(host, {}).get("scheme"), "cookie_names": cookie_names or auth_schemes.get(host, {}).get("cookie_names", [])}
    result = {
        "endpoints": endpoints,
        "auth_login": auth_login,
        "auth_metadata": {"auth_candidates": auth_candidates, "auth_schemes": auth_schemes},
        "stats": {"total": len(requests), "filtered": filtered, "unique": len(endpoints),
                  "noise_marked": sum(1 for e in endpoints if e.get("noise")),
                  "review_suggested": sum(1 for e in endpoints if e.get("review_suggested")),
                  "noise_response_bytes": sum(e.get("total_response_bytes", 0) for e in endpoints if e.get("noise")),
                  "total_response_bytes": sum(e.get("total_response_bytes", 0) for e in endpoints)},
        "base_url": f"https://{base_host}" if base_host else None,
    }
    (session_dir / "analysis.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _majority_host(endpoints: list[dict[str, Any]]) -> str | None:
    counts: dict[str, int] = defaultdict(int)
    for ep in endpoints:
        counts[ep.get("host", "")] += 1
    return max(counts, key=counts.get) if counts else None