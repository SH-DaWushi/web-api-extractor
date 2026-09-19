# -*- coding: utf-8 -*-
"""Issue #21：表单编码登录的密文凭据必须被识别。

传统 OA OA 的登录请求：

    POST /api/auth/login/login
    Content-Type: application/x-www-form-urlencoded

    lang=7&username=<351 字符 base64>&user_password=<351 字符 base64>

351 字符 base64 与 RSA-2048 密文特征吻合，但 `crypto_found` 报 false：
`detect_password_encryption()` 只看 URL 查询参数 `encrypt`，而 `detect_crypto()`
对表单编码体 `json.loads` 必失败，退化成「对整串判密文」——整串含 `=`、`&`，
永远判不出来。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from webapi_extractor.bodies import body_fields
from webapi_extractor.crypto_analyzer import detect_crypto


# RSA-2048 密文 base64 后约 344 字符，这里按真实长度构造。
CIPHER = "A" * 344
PLAIN_PW = "P@ssw0rd!"


def _form_body() -> str:
    return (f"lang=7&username={CIPHER}&user_password={CIPHER}"
            f"&captcha=4A7B&loginType=1")


class TestBodyFields:
    def test_parses_form_encoded(self):
        fields = body_fields("a=1&b=2&c=3")
        assert fields == {"a": "1", "b": "2", "c": "3"}

    def test_url_decodes_values(self):
        """密文里的 + / 会被编码成 %2B %2F —— 形态判定必须基于解码后的值。"""
        fields = body_fields("user_password=ab%2Bcd%2Fef")
        assert fields["user_password"] == "ab+cd/ef"

    def test_parses_json(self):
        assert body_fields('{"a": "1", "b": 2}') == {"a": "1"}

    def test_html_is_not_form(self):
        assert body_fields("<html>a=b</html>") == {}

    def test_empty_and_none(self):
        assert body_fields("") == {}
        assert body_fields(None) == {}


def _session(tmp_path: Path, capture_lines: list[dict]) -> Path:
    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)
    (tmp_path / "capture.jsonl").write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in capture_lines),
        encoding="utf-8")
    return tmp_path


def _analysis(url: str) -> dict:
    return {"auth_metadata": {"auth_candidates": [{"request_id": "r1", "url": url}]},
            "endpoints": []}


class TestCryptoDetection:
    def test_form_ciphertext_detected(self, tmp_path):
        url = "https://oa.example.com/api/auth/login/login"
        session = _session(tmp_path, [{
            "type": "request", "requestId": "r1", "url": url,
            "postData": _form_body(),
        }])
        result = detect_crypto(session, _analysis(url))
        assert result["found"] is True
        assert result["crypto_findings"], "表单编码的密文未被识别"
        fields = result["crypto_findings"][0]["encrypted_fields"]
        assert "user_password" in fields
        assert "username" in fields

    def test_plain_form_not_flagged(self, tmp_path):
        """明文表单不应误报——否则 crypto_found 失去意义。"""
        url = "https://oa.example.com/api/auth/login/login"
        session = _session(tmp_path, [{
            "type": "request", "requestId": "r1", "url": url,
            "postData": f"username=alice&user_password={PLAIN_PW}&loginType=1",
        }])
        result = detect_crypto(session, _analysis(url))
        assert result["found"] is False

    def test_json_ciphertext_still_detected(self, tmp_path):
        """原有的 JSON 路径不能因本次修复而失效。"""
        url = "https://oa.example.com/api/login"
        session = _session(tmp_path, [{
            "type": "request", "requestId": "r1", "url": url,
            "postData": json.dumps({"username": "alice", "password": CIPHER}),
        }])
        result = detect_crypto(session, _analysis(url))
        assert result["found"] is True
        assert "password" in result["crypto_findings"][0]["encrypted_fields"]

    def test_shape_meta_sidecar_still_used(self, tmp_path):
        """脱敏边车的形态元数据分支（B-3）保持有效。"""
        url = "https://oa.example.com/api/login"
        session = _session(tmp_path, [{
            "type": "request", "requestId": "r1", "url": url,
            "postData": '{"password": "***"}',
            "redaction_meta": {"$.password": {"len": 344, "shape": "base64"}},
        }])
        result = detect_crypto(session, _analysis(url))
        assert result["found"] is True
