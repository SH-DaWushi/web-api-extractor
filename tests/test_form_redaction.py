# -*- coding: utf-8 -*-
"""Issue #22：表单编码的请求体必须脱敏（此前完全不脱敏）。

修复前 `redact_payload()` 只处理 JSON，非 JSON 直接 `return payload, [], {}`
原样返回——**表单提交的明文密码会被完整写进 capture.jsonl**，
与「凭据字段值必然脱敏为 ***」的硬规则矛盾。
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote_plus

import pytest

from scry_mcp_gen.bodies import parse_form_urlencoded
from scry_mcp_gen.redaction import _is_secret_field, redact_headers, redact_payload


class TestSecretFieldNames:
    """复合命名的凭据字段同样必须脱敏（精确匹配会全漏）。"""

    @pytest.mark.parametrize("name,expected", [
        ("password", True),
        ("user_password", True),      # 复合命名：含 password 但不精确匹配
        ("login_password", True),
        ("oldPwd", True),
        ("secretKey", True),
        ("captcha_code", True),
        # D2：常见同义词此前完全不在识别范围内（短值更是被 len>=16 卡掉）。
        ("access_token", True),
        ("accessToken", True),        # camelCase 变体
        ("api_key", True),
        ("apiKey", True),
        ("pass", True),
        ("pin", True),
        ("otp", True),
        ("smsCode", True),
        ("verification_code", True),
        ("captcha", True),
        ("auth_code", True),
        ("client_secret", True),
        ("username", False),
        ("page", False),
        # 不能因为引入短同义词就误伤普通字段（substring 匹配的经典坑）
        ("section", False),
        ("companyId", False),
        ("menuIds", False),
        ("compass", False),           # 含 "pass" 但不是凭据
        ("shipping", False),          # 含 "pin" 但不是凭据
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
        # D3：换成**字符分布真实**的 base64 样本（base64(bytes(range(256)))，
        # 恰 344 字符），并像真实表单那样把 + / = 做 URL 编码。
        # 旧的 "A"*344 是单字符重复串——新的形态判定（正确地）不再把它算作
        # base64，继续用它等于把 classifier 削弱回去迁就退化样本。
        cipher_like = base64.b64encode(bytes(range(256))).decode("ascii")
        _, _, meta = redact_payload(f"user_password={quote_plus(cipher_like)}")
        assert meta["$.user_password"]["shape"] == "base64"
        assert meta["$.user_password"]["len"] == 344

    def test_empty_value_not_masked(self):
        red, _, meta = redact_payload("user_password=&username=x")
        assert "username=x" in red
        assert meta == {}

    def test_valueless_control_does_not_disable_redaction(self):
        """D1 回归：真实登录表单普遍带 ``&submit`` / ``&remember`` 这类无值控制项。

        修复前解析器一遇到这种段就判「非表单编码」，`_redact_form` 于是**整串原样返回**
        —— 明文密码被完整写进 capture.jsonl。现在必须照样遮蔽，且键名一个不少。
        """
        red, _, meta = redact_payload("password=Secret1&submit")
        assert "Secret1" not in red
        assert "password=***" in red
        # 结构保留：键名顺序、数量与原文一致（analyzer #23 靠它出参数）。
        assert [k for k, _ in parse_form_urlencoded(red)] == \
               [k for k, _ in parse_form_urlencoded("password=Secret1&submit")]
        assert meta["$.password"]["len"] == len("Secret1")

    @pytest.mark.parametrize("body,secret", [
        ("access_token=short123", "short123"),
        ("apiKey=shortkey1", "shortkey1"),
        ("pass=hunter2", "hunter2"),
        ("pin=1234", "1234"),
        ("otp=654321", "654321"),
        ("smsCode=9999", "9999"),
        ("captcha=4A7B", "4A7B"),
        ("client_secret=abc", "abc"),
    ])
    def test_short_synonym_credentials_masked(self, body, secret):
        """D2（表单路径）：值再短也是凭据——名称像凭据就遮蔽，无 len>=16 门槛。"""
        red, _, _ = redact_payload(body)
        assert secret not in red
        assert red == f"{body.split('=', 1)[0]}=***"   # 键名保留、值全遮


class TestJsonShortCredentials:
    """D2（JSON 路径）：此前 len<16 的 token/同义词值被直接放行。"""

    @pytest.mark.parametrize("key,value", [
        ("access_token", "short123"),
        ("apiKey", "shortkey1"),
        ("pass", "hunter2"),
        ("pin", "1234"),
        ("otp", "654321"),
        ("client_secret", "abc"),
    ])
    def test_masked_regardless_of_value_length(self, key, value):
        red, _, _ = redact_payload(json.dumps({key: value}))
        assert value not in red
        assert json.loads(red)[key] == "***"


class TestHeaderRedaction:
    """D3/D4：Authorization 无 scheme 时整串就是裸 token；其他凭据头此前完全不脱敏。"""

    def test_bare_authorization_token_fully_masked(self):
        # 修复前 token 被当成 scheme 原样保留：'eyJ... ***'
        assert redact_headers({"authorization": "eyJhbGciOiJIUzI1NiJ9.abc.def"}) == \
               {"authorization": "***"}

    @pytest.mark.parametrize("value,expected", [
        ("Bearer eyJhbGciOiJIUzI1NiJ9.x.y", "Bearer ***"),
        ("Basic dXNlcjpwYXNz", "Basic ***"),
    ])
    def test_scheme_kept_value_masked(self, value, expected):
        assert redact_headers({"Authorization": value}) == {"Authorization": expected}

    @pytest.mark.parametrize("name", [
        "X-Auth-Token", "x-api-key", "X-Access-Token", "Api-Key", "X-Client-Secret",
    ])
    def test_credential_headers_masked(self, name):
        assert redact_headers({name: "supersecrettoken"}) == {name: "***"}

    def test_cookie_names_kept_values_masked(self):
        assert redact_headers({"Cookie": "sid=abc123; csrftoken=zzz"}) == \
               {"Cookie": "sid=***; csrftoken=***"}

    def test_plain_headers_untouched(self):
        headers = {"Accept": "application/json", "Content-Type": "text/plain"}
        assert redact_headers(headers) == headers


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
