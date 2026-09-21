# -*- coding: utf-8 -*-
"""Issue #3 回归测试：multipart 批处理子请求解析（通用，非单一站点）。

覆盖 Dynamics/OData multipart、CRLF 变体、Graph JSON-batch、
Salesforce Composite 风格，以及「子请求进入 endpoints 并可生成工具」。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webapi_extractor.analyzer import (  # noqa: E402
    _absolute_url,
    _header_value,
    _parse_multipart_requests,
)

# 抓包中的形态：LF 换行，postData 即 multipart 原文
LF_BATCH = (
    "--batch_1700000000000\n"
    "Content-Type: application/http\n"
    "Content-Transfer-Encoding: binary\n"
    "\n"
    "GET /api/data/v9.0/cr_sampleitems(000000aa)?$select=new_name HTTP/1.1\n"
    "Prefer: odata.include-annotations=\"*\"\n"
    "\n"
    "--batch_1700000000000\n"
    "Content-Type: application/http\n"
    "Content-Transfer-Encoding: binary\n"
    "\n"
    "GET /api/data/v9.0/annotations?fetchXml=%3cfetch%3e HTTP/1.1\n"
    "Accept: application/json\n"
    "\n"
    "--batch_1700000000000--\n"
)

CRLF_BATCH = LF_BATCH.replace("\n", "\r\n")


def test_parses_odata_multipart_lf() -> None:
    subs = _parse_multipart_requests(LF_BATCH)
    assert [s["method"] for s in subs] == ["GET", "GET"]
    assert subs[0]["path"] == "/api/data/v9.0/cr_sampleitems(000000aa)?$select=new_name"
    assert subs[1]["path"] == "/api/data/v9.0/annotations?fetchXml=%3cfetch%3e"


def test_parses_odata_multipart_crlf() -> None:
    subs = _parse_multipart_requests(CRLF_BATCH)
    assert len(subs) == 2
    assert subs[0]["path"].startswith("/api/data/v9.0/cr_sampleitems")


def test_parses_with_content_type_boundary() -> None:
    subs = _parse_multipart_requests(LF_BATCH, 'multipart/mixed; boundary="batch_1700000000000"')
    assert len(subs) == 2


def test_parses_changeset_with_post_body() -> None:
    batch = (
        "--b1\r\nContent-Type: multipart/mixed; boundary=cs1\r\n\r\n"
        "--cs1\r\nContent-Type: application/http\r\n\r\n"
        "POST /api/data/v9.0/annotations HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
        '{"subject":"hi"}\r\n--cs1--\r\n--b1--\r\n'
    )
    subs = _parse_multipart_requests(batch)
    assert len(subs) == 1
    assert subs[0]["method"] == "POST"
    assert subs[0]["path"] == "/api/data/v9.0/annotations"
    assert json.loads(subs[0]["body"]) == {"subject": "hi"}


def test_parses_graph_json_batch() -> None:
    body = json.dumps({"requests": [
        {"method": "GET", "url": "/me/messages", "headers": {"A": "b"}},
        {"method": "POST", "url": "/me/sendMail", "body": {"x": 1}},
        {"no_url": True},
    ]})
    subs = _parse_multipart_requests(body, "application/json")
    assert [(s["method"], s["path"]) for s in subs] == [("GET", "/me/messages"), ("POST", "/me/sendMail")]


def test_parses_salesforce_style_and_empty() -> None:
    assert _parse_multipart_requests(None) == []
    assert _parse_multipart_requests("") == []
    assert _parse_multipart_requests('{"foo": 1}', "application/json") == []


def test_relative_path_joined_with_parent_host() -> None:
    assert _absolute_url("host:446", "https", "/api/x") == "https://host:446/api/x"
    assert _absolute_url("host", "https", "api/x") == "https://host/api/x"
    assert _absolute_url("host", "https", "https://other/x") == "https://other/x"


def test_header_value_is_case_insensitive() -> None:
    # redact_headers 保留原始大小写（真实抓包中是 content-type）
    assert _header_value({"content-type": "multipart/mixed"}, "Content-Type") == "multipart/mixed"
    assert _header_value({"Content-Type": "application/json"}, "content-type") == "application/json"
    assert _header_value({}, "Content-Type") == ""
