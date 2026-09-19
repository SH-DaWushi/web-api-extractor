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
# --------------------------------------------------------------------------- #
NOISE_PATH_PATTERNS = (
    r"/system/stat/", r"/system/traffic/", r"/tracking/", r"heartbeat",
    r"/breadcrumb", r"/config/menu/", r"/config/banner", r"/visit-history/",
    r"/analytics/", r"/telemetry/", r"/beacon", r"^(?:log|collect)[/-]",
)
NOISE_DOMAINS = {
    "r.clarity.ms", "otheve.beacon.qq.com", "aegis.qq.com", "graph.qq.com",
    "www.google-analytics.com", "analytics.google.com", "log.zhugeio.com",
}


def _is_noise(host: str, path: str) -> bool:
    if host in NOISE_DOMAINS or host.endswith(".clarity.ms"):
        return True
    return any(re.search(p, path, re.I) for p in NOISE_PATH_PATTERNS)


# --------------------------------------------------------------------------- #
# B-1: 命名参数化（单样本也能参数化——SPA 每个资源通常只请求一次）
# --------------------------------------------------------------------------- #
PARAM_ALIAS = {"is_my": "article_id", "content_meta": "content_meta_id",
               "read": "message_id", "id": "id", "page": "page"}


def _is_id_segment(seg: str) -> bool:
    """数字 ID、下划线/逗号分隔数字（item_merged.10_773）、<type>-<id>（achievement-12782）。"""
    return bool(
        re.fullmatch(r"\d+([_,]\d+)*", seg)
        or re.fullmatch(r"item_merged\.\d+(_\d+)*", seg)
        or re.fullmatch(r"[a-z_]+-\d+([_,]\d+)*", seg)
    )


def parameterize(path: str) -> tuple[str, list[str]]:
    """把路径中的 ID 段替换为按前段命名的参数，返回 (新路径, 参数名列表)。"""
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
        name = PARAM_ALIAS.get(base) or (base + "_id" if base else "id")
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


def analyze_capture(session_dir: Path, tracking_domains: set[str] | None = None) -> dict[str, Any]:
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
    endpoints: list[dict[str, Any]] = []
    for (method, host), samples in grouped.items():
        normalized = normalize_paths([sample["request"].get("url", "") for sample in samples])
        for item in normalized:
            selected = [samples[index] for index in item.sample_indexes]
            first = selected[0]
            request_body_values = []
            response_values = []
            for sample in selected:
                request_body = sample["request"].get("postData")
                response_body = sample["body"].get("body")
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
            })
    # ---- C-3: 噪音标记（不删除，保留人工复核权） --------------------------
    for endpoint in endpoints:
        endpoint["noise"] = _is_noise(endpoint["host"], endpoint["path"])

    # ---- B-1: 命名参数化二遍处理 + 同构合并 -------------------------------
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ep in endpoints:
        new_path, param_names = parameterize(ep["path"])
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
            for k, v in (ep.get("query_params") or {}).items():
                bucket = keep["query_params"].setdefault(k, [])
                for val in v:
                    if val not in bucket:
                        bucket.append(val)
    endpoints = list(merged.values())
    for i, ep in enumerate(endpoints, start=1):
        ep["endpoint_id"] = f"ep_{i:03d}"

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
                  "noise_marked": sum(1 for e in endpoints if e.get("noise"))},
        "base_url": f"https://{base_host}" if base_host else None,
    }
    (session_dir / "analysis.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _majority_host(endpoints: list[dict[str, Any]]) -> str | None:
    counts: dict[str, int] = defaultdict(int)
    for ep in endpoints:
        counts[ep.get("host", "")] += 1
    return max(counts, key=counts.get) if counts else None