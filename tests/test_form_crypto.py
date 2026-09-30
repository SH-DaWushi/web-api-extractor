# -*- coding: utf-8 -*-
"""Issue #21：表单编码登录的密文凭据必须被识别。

典型 OA 系统的登录请求：

    POST /api/auth/login
    Content-Type: application/x-www-form-urlencoded

    lang=7&username=<base64 密文>&password=<base64 密文>

约 344 字符 base64 与 RSA-2048 密文特征吻合，但 `crypto_found` 报 false：
`detect_password_encryption()` 只看 URL 查询参数 `encrypt`，而 `detect_crypto()`
对表单编码体 `json.loads` 必失败，退化成「对整串判密文」——整串含 `=`、`&`，
永远判不出来。
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import quote_plus

import pytest

from webapi_extractor.bodies import body_fields
from webapi_extractor.crypto_analyzer import _looks_ciphertext, detect_crypto, value_shape


# RSA-2048 密文 base64 后约 344 字符。这里用**字符分布真实**的样本：
# base64(bytes(range(256)))，含大小写字母、数字与 +//，长度恰好 344。
# 旧 fixture 是 "A"*344——单字符重复串，在新的形态判定下（正确地）不再算密文
# （否则等于把 classifier 削弱回去迁就一个退化样本）。见 D3。
CIPHER = base64.b64encode(bytes(range(256))).decode("ascii")
PLAIN_PW = "P@ssw0rd!"


def _form_body() -> str:
    # 真实表单体里密文的 + / = 会被 URL 编码（%2B %2F %3D），
    # 形态判定必须基于解码后的值（见本文件 test_url_decodes_values）。
    encoded = quote_plus(CIPHER)
    return (f"lang=7&username={encoded}&password={encoded}"
            f"&captcha=4A7B&loginType=1")


class TestBodyFields:
    def test_parses_form_encoded(self):
        fields = body_fields("a=1&b=2&c=3")
        assert fields == {"a": "1", "b": "2", "c": "3"}

    def test_url_decodes_values(self):
        """密文里的 + / 会被编码成 %2B %2F —— 形态判定必须基于解码后的值。"""
        fields = body_fields("password=ab%2Bcd%2Fef")
        assert fields["password"] == "ab+cd/ef"

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
        url = "https://oa.example.com/api/auth/login"
        session = _session(tmp_path, [{
            "type": "request", "requestId": "r1", "url": url,
            "postData": _form_body(),
        }])
        result = detect_crypto(session, _analysis(url))
        assert result["found"] is True
        assert result["crypto_findings"], "表单编码的密文未被识别"
        fields = result["crypto_findings"][0]["encrypted_fields"]
        assert "password" in fields
        assert "username" in fields

    def test_plain_form_not_flagged(self, tmp_path):
        """明文表单不应误报——否则 crypto_found 失去意义。"""
        url = "https://oa.example.com/api/auth/login"
        session = _session(tmp_path, [{
            "type": "request", "requestId": "r1", "url": url,
            "postData": f"username=alice&password={PLAIN_PW}&loginType=1",
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

    def test_multiple_candidates_match_multiple_requests(self, tmp_path):
        """索引化后语义不变：每个候选只命中自己的 requestId，命中多个则全部计入。"""
        url = "https://oa.example.com/api/auth/login"
        session = _session(tmp_path, [
            {"type": "response", "requestId": "r1", "url": url, "postData": _form_body()},
            {"type": "request", "requestId": "r1", "url": url, "postData": _form_body()},
            {"type": "request", "requestId": "r2", "url": url, "postData": "username=alice&password=plain"},
        ])
        # 两个候选都指向 r1（同名事件保持文件内顺序）、r2 是明文。
        analysis = {"auth_metadata": {"auth_candidates": [
            {"request_id": "r1", "url": url}, {"request_id": "r1", "url": url},
            {"request_id": "r2", "url": url}]}, "endpoints": []}

        result = detect_crypto(session, analysis)

        # type != "request" 的事件不参与；r1 命中 2 次候选 → 2 条 finding。
        assert len(result["crypto_findings"]) == 2
        assert all("password" in f["encrypted_fields"] for f in result["crypto_findings"])

    def test_capture_file_is_read_once_for_many_candidates(self, tmp_path, monkeypatch):
        """S3：候选再多，capture.jsonl 也只能被读一次。

        旧实现把读文件放在「遍历 auth 候选」的内层循环里，读取次数 == 候选数。
        redaction 会把 ``/api/auth/*`` 整片 URL 算作候选，所以真实抓包里 N 可以
        接近请求总数：5,000 请求 / 5 MB 的 capture → 约 5,000 次读盘（~25 GB I/O），
        表现成 ``analyze_traffic`` 卡死。这里用 50 个候选把差异放大到可断言。
        """
        url = "https://oa.example.com/api/auth/login"
        lines, candidates = [], []
        for i in range(50):
            rid = f"r{i}"
            candidates.append({"request_id": rid, "url": url})
            lines.append({"type": "request", "requestId": rid, "url": url,
                          "postData": _form_body()})
        session = _session(tmp_path, lines)
        capture = session / "capture.jsonl"

        reads: list[int] = []
        real_read_text = Path.read_text

        def counting_read_text(self, *args, **kwargs):
            if self == capture:
                reads.append(1)
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", counting_read_text)

        result = detect_crypto(session, {"auth_metadata": {"auth_candidates": candidates},
                                         "endpoints": []})

        assert len(reads) == 1, (
            f"capture.jsonl 被读了 {len(reads)} 次（== 候选数即旧实现的 O(N) 读盘）")
        assert result["found"] is True
        assert len(result["crypto_findings"]) == 50

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


class TestValueShape:
    """D3：形态分类必须真的有信息量。

    修复前先判 base64 字符集，于是任何纯 ASCII（``password123``）都报 base64，
    hex 分支几乎不可达——"密文判定"因此名存实亡。
    """

    def test_fixture_is_realistic(self):
        assert len(CIPHER) == 344
        assert value_shape(CIPHER) == "base64"

    def test_plain_ascii_is_plain(self):
        assert value_shape("password123") == "plain"
        assert value_shape("alice") == "plain"

    def test_strict_hex_wins_over_base64_charset(self):
        # 全是十六进制字符 → 归 hex，而不是 base64。
        assert value_shape("a" * 344) == "hex"
        assert value_shape("deadbeef" * 16) == "hex"
        assert value_shape(hashlib.sha256(b"seed").hexdigest()) == "hex"

    def test_realistic_ciphertext_is_base64(self):
        assert value_shape(CIPHER) == "base64"

    def test_looks_ciphertext_rejects_degenerate(self):
        assert _looks_ciphertext("a" * 130) is False
        assert _looks_ciphertext("A" * 344) is False
        # 普通的长单词（纯小写），base64 可解码但显然不是密文。
        assert _looks_ciphertext("supercalifragilisticexpialidocious") is False

    def test_looks_ciphertext_accepts_realistic(self):
        assert _looks_ciphertext(CIPHER) is True
        assert _looks_ciphertext(hashlib.sha512(b"seed").hexdigest()) is True

