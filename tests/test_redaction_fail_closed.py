# -*- coding: utf-8 -*-
"""POST 登录体的凭据落盘回归测试（脱敏层 fail-open → fail-closed）。

修复前 ``redact_payload()`` 的顺序是「先 JSON，解析失败就交给表单路径」，
而表单路径对**不像表单编码**的正文是 ``return payload``——原样放行。
于是下面这些 POST 登录体里的明文口令被**完整写进 capture.jsonl**：

* ``{'username':'bob','password':'hunter2'}``（宽松 JSON / JS 对象字面量）
* ``{"password":"hunter2",}``（尾逗号）、``{"password":hunter2}``（值没引号）
* ``multipart/form-data``（浏览器原生表单提交，含文件上传时唯一的选择）
* ``<login><password>…</password></login>``
* 带 BOM 的 JSON、字符串里有裸换行的 JSON

现在的保证（写盘前终检）：**正文里不允许留下没有被遮蔽的凭据名**；
认不出编码又不敢保证干净的体，整条不写（``None``），只留大小与 ``body_dropped``。
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scry_mcp_gen.bodies import (  # noqa: E402
    parse_multipart,
    split_multipart,
)
from scry_mcp_gen.capture import CaptureSession  # noqa: E402
from scry_mcp_gen.redaction import (  # noqa: E402
    mentions_unmasked_secret,
    redact_payload,
)
from scry_mcp_gen.storage import SessionStore  # noqa: E402

PASSWORD = "hunter2"

MULTIPART_LOGIN = (
    "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
    'Content-Disposition: form-data; name="username"\r\n\r\n'
    "bob\r\n"
    "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
    'Content-Disposition: form-data; name="password"\r\n\r\n'
    f"{PASSWORD}\r\n"
    "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
    'Content-Disposition: form-data; name="remember"\r\n\r\n'
    "1\r\n"
    "------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
)


def _redact(payload: str) -> str | None:
    return redact_payload(payload)[0]


class TestBodiesThatUsedToLeak:
    """每一条都是实测会明文落盘的原始体；现在都必须不再含口令。"""

    def test_loose_json_is_dropped_not_written(self):
        """宽松 JSON（单引号）解析不了，但里面有 password，只能整条不写。"""
        assert _redact("{'username':'bob','password':'hunter2'}") is None

    def test_trailing_comma_is_dropped(self):
        assert _redact('{"username":"bob","password":"hunter2",}') is None

    def test_unquoted_value_is_dropped(self):
        assert _redact('{"username":"bob","password":hunter2}') is None

    def test_xml_login_is_dropped(self):
        assert _redact(f"<login><user>bob</user><password>{PASSWORD}</password></login>") is None

    def test_js_object_literal_is_dropped(self):
        assert _redact(f"({{username:'bob',password:'{PASSWORD}'}})") is None

    def test_nested_json_inside_a_multipart_field_is_dropped(self):
        """字段名不敏感、值里再嵌一层 JSON——结构化脱敏看不见里面，终检必须拦住。"""
        body = (
            "--X\r\n"
            'Content-Disposition: form-data; name="payload"\r\n\r\n'
            f'{{"password":"{PASSWORD}"}}\r\n'
            "--X--\r\n"
        )
        assert _redact(body) is None

    def test_bom_json_is_still_redacted(self):
        """带 BOM 的 JSON 此前也会掉进 fail-open；现在按 JSON 正常遮蔽。"""
        red = _redact(f'﻿{{"username":"bob","password":"{PASSWORD}"}}')
        assert red is not None and PASSWORD not in red and '"***"' in red

    def test_json_with_raw_newline_in_string_is_redacted(self):
        red = _redact('{"username":"bob","password":"hu\nter2"}')
        assert red is not None and "ter2" not in red


class TestMultipartIsRedactedInPlace:
    """multipart 是浏览器原生表单提交方式，不能靠「丢弃」了事——要保真地遮。"""

    def test_password_part_is_masked(self):
        red = _redact(MULTIPART_LOGIN)
        assert red is not None
        assert PASSWORD not in red
        assert "***" in red

    def test_everything_but_the_secret_value_is_byte_identical(self):
        """边界、头部、段顺序、其它字段、结尾的 ``--`` 都不许动。"""
        red = _redact(MULTIPART_LOGIN)
        assert red is not None
        assert red == MULTIPART_LOGIN.replace(f"\r\n\r\n{PASSWORD}\r\n", "\r\n\r\n***\r\n")

    def test_non_secret_fields_are_still_readable(self):
        """analyzer 靠字段名生成工具参数，用户名/记住我不能被牵连。"""
        fields = dict(parse_multipart(_redact(MULTIPART_LOGIN)))
        assert fields["username"] == "bob\r\n"
        assert fields["remember"] == "1\r\n"

    def test_no_secret_no_rewrite(self):
        body = (
            "--X\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nhello\r\n--X--\r\n"
        )
        assert _redact(body) == body

    def test_split_multipart_roundtrip(self):
        boundary, parts = split_multipart(MULTIPART_LOGIN)
        assert boundary.join(chunk for _, chunk in parts) == MULTIPART_LOGIN

    def test_none_for_non_multipart(self):
        assert split_multipart("username=bob&password=x") is None
        assert split_multipart(None) is None


class TestStillPreservedVerbatim:
    """没有凭据痕迹的正文照旧原样保留（不因为「看不懂」就一律丢弃）。"""

    def test_plain_text(self):
        assert _redact("just some text") == "just some text"

    def test_html_without_credentials(self):
        assert _redact("<html><body>hello</body></html>") == "<html><body>hello</body></html>"

    def test_none_passthrough(self):
        assert redact_payload(None) == (None, [], {})

    def test_form_and_strict_json_unchanged_behaviour(self):
        assert _redact("username=bob&password=hunter2") == "username=bob&password=***"
        assert _redact('{"username":"bob","password":"hunter2"}') == \
            '{"username":"bob","password":"***"}'


class TestTerminalCheck:
    """写盘前终检：摘掉已遮蔽的形态后，还不许再出现凭据名。"""

    def test_masked_forms_pass(self):
        assert not mentions_unmasked_secret('{"password":"***"}')
        assert not mentions_unmasked_secret("password=***&user=bob")
        assert not mentions_unmasked_secret('name="password"\r\n\r\n***')

    def test_unmasked_forms_fail(self):
        assert mentions_unmasked_secret('{"password":"hunter2"}')
        assert mentions_unmasked_secret("<password>hunter2</password>")
        assert mentions_unmasked_secret('name="password"\r\n\r\nhunter2')

    def test_short_names_only_as_whole_words(self):
        """``compass`` / ``shipping`` 里的 ``pass`` 不算凭据名（否则误伤满屏）。"""
        assert not mentions_unmasked_secret("compass=1&shipping=2")

    def test_conservative_drop_of_a_harmless_mention(self):
        """散文里提了一句 password 也整条丢弃——为了绝不落盘明文，这个误伤是有意的。"""
        assert _redact("note=please reset your password soon") is None


def _run_request(post_data: str | None, tmp_path: Path) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        store = SessionStore(tmp_path)
        session = CaptureSession("s", "https://example.com/", store, 1000, 300)
        session.status = "capturing"
        session.directory.mkdir(parents=True, exist_ok=True)
        await session.on_request({
            "requestId": "r1",
            "request": {
                "url": "https://example.com/api/login",
                "method": "POST",
                "postData": post_data,
            },
        }, None)
        return session.event_queue.get_nowait()
    return asyncio.run(run())


class TestCaptureWritesNoPlaintext:
    """端到端：capture 事件里不能出现口令，丢弃要如实标记。"""

    def test_multipart_login_event_masks_the_password(self, tmp_path):
        record = _run_request(MULTIPART_LOGIN, tmp_path)
        assert PASSWORD not in record["postData"]
        assert record["body_dropped"] is False
        assert record["postData_size"] == len(MULTIPART_LOGIN.encode("utf-8"))
        assert record["auth_candidate"] is True

    def test_unparsable_login_event_drops_the_body(self, tmp_path):
        record = _run_request("{'username':'bob','password':'hunter2'}", tmp_path)
        assert record["postData"] is None
        assert record["body_dropped"] is True      # 「有体但没写」，不是「本来就没有体」
        assert record["postData_size"] == len("{'username':'bob','password':'hunter2'}")

    def test_get_without_body_is_not_marked_dropped(self, tmp_path):
        record = _run_request(None, tmp_path)
        assert record["postData"] is None
        assert record["body_dropped"] is False
