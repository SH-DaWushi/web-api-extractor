"""Pure analysis helpers used by the capture analyzer."""

from __future__ import annotations

import re
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


VALUE_SHAPES = (
    re.compile(r"^\d+$"),
    re.compile(r"^[0-9a-f]{8,}$", re.I),
    re.compile(r"^[A-Za-z0-9]{8,}$"),
)


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
                distinct_ratio = len(set(values)) / len(values)
                shaped_ratio = sum(_looks_like_parameter(value) for value in values) / len(values)
                current = values[row]
                normalized.append("{id}" if distinct_ratio >= 0.5 and shaped_ratio >= 0.8 and _looks_like_parameter(current) else current)
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
            endpoints.append({
                "endpoint_id": endpoint_id,
                "method": method,
                "host": host,
                "path": item.path,
                "url": first["request"].get("url"),
                "sample_count": len(selected),
                "single_sample": len(selected) < 2,
                "auth_required": auth_required,
                "request_schema": _json_schema(request_body_values[0], request_body_values) if request_body_values else None,
                "response_schema": _json_schema(response_values[0], response_values) if response_values else None,
                "description": None,
                "notes": None,
                "param_name_guessed": bool(item.parameter_names),
            })
    host_counts = defaultdict(int)
    for endpoint in endpoints:
        host_counts[endpoint["host"]] += 1
    base_host = max(host_counts, key=host_counts.get) if host_counts else None
    for endpoint in endpoints:
        endpoint["cross_host"] = endpoint["host"] != base_host
    result = {"endpoints": endpoints, "auth_metadata": {"auth_candidates": auth_candidates}, "stats": {"total": len(requests), "filtered": filtered, "unique": len(endpoints)}, "base_url": f"https://{base_host}" if base_host else None}
    (session_dir / "analysis.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result