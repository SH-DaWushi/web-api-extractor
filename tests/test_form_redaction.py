# -*- coding: utf-8 -*-
"""Issue #22：表单编码的请求体必须脱敏（此前完全不脱敏）。

修复前 `redact_payload()` 只处理 JSON，非 JSON 直接 `return payload, [], {}`
原样返回——**表单提交的明文密码会被完整写进 capture.jsonl**，
与「凭据字段值必然脱敏为 ***」的硬规则矛盾。
"""
from __future__ import annotations

import json

import pytest

from webapi_extractor.redaction import _is_secret_field, redact_payload


class TestSecretFieldNames:
    """复合命名的凭据字段同样必须脱敏（精确匹配会全漏）。"""

    @pytest.mark.parametrize("name,expected", [
        ("password", True),
        ("user_password", True),      # 传统 OA 系统 的实际字段名
        ("login_password", True),
        ("oldPwd", True),
        ("secretKey", True),
        ("captcha_code", True),
        ("username", False),
        ("username", False),
        ("page", False),
    ])
    def test_detection(self, name, expected):
        assert _is_secret_field(name) is expected


class TestFormRedaction:
    def test_password_value_is_masked(self):
        body = "username=alice&user_password=SuperSecret123"
        red, _, _ = redact_payload(body)
        assert "SuperSecret123" not in red
        assert "user_password=***" in red

    def test_non_secret_fields_preserved(self):
        """非敏感字段保留原值——脱敏不能把请求变成不可读。"""
        body = "username=alice&user_password=x&loginType=1"
        red, _, _ = redact_payload(body)
        assert "username=alice" in red
        assert "loginType=1" in red

    def test_exact_password_field(self):
        red, _, _ = redact_payload("username=bob&password=hunter2")
        assert "hunter2" not in red
        assert "username=bob" in red

    def test_token_field_masked_and_tracked(self):
        token = "A" * 40
        red, paths, meta = redact_payload(f"access_token={token}&x=1")
        assert token not in red
        assert "$.access_token" in paths
        assert meta["$.access_token"]["len"] == 40

    def test_url_encoded_password(self):
        """值是 URL 编码的（%40 = @、%2B = +）——脱敏按解码后的语义判定。"""
        red, _, meta = redact_payload("user_password=a%40b%2Bc")
        assert "a%40b%2Bc" not in red or "***" in red
        assert "user_password=***" in red
        assert "$.user_password" in meta

    def test_shape_meta_recorded(self):
        """形态元数据必须产出（issue #21 的密文判定依赖它）。"""
        cipher_like = "A" * 344
        _, _, meta = redact_payload(f"user_password={cipher_like}")
        assert meta["$.user_password"]["shape"] == "base64"
        assert meta["$.user_password"]["len"] == 344

    def test_empty_value_not_masked(self):
        red, _, meta = redact_payload("user_password=&username=x")
        assert "username=x" in red
        assert meta == {}


class TestNonFormPayloadsUntouched:
    """不能把 JSON / HTML 误当表单处理。"""

    def test_json_still_works(self):
        red, _, _ = redact_payload(json.dumps({"password": "p@ss", "page": 1}))
        assert "p@ss" not in red
        assert json.loads(red)["page"] == 1

    def test_html_body_preserved(self):
        html = "<html><body>hello</body></html>"
        red, _, _ = redact_payload(html)
        assert red == html

    def test_plain_text_without_equals_preserved(self):
        assert redact_payload("just some text")[0] == "just some text"

    def test_none_passthrough(self):
        assert redact_payload(None) == (None, [], {})
