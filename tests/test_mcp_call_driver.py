# -*- coding: utf-8 -*-
"""Issue #17：mcp_call.py 的陈旧会话自动恢复必须真的能触发。

缺陷：post() 里 `r.raise_for_status()` 在解析响应体**之前**就把 HTTP 404
抛成异常，而 404 正是「陈旧会话」的信号——于是 `_is_stale_session` 永远拿不到
它，恢复分支成了死代码。后果是服务每次重启后所有调用都崩，必须手工
`rm .mcp_session`。

mcp_call.py 是仓库根目录的脚本（不在 webapi_extractor 包内），故按路径加载。

另含 R5：**输出编码由工具自己处理对**——管道里是确定的 UTF-8（机器），
真控制台里中文可读（人），两者都不要求用户设 `PYTHONIOENCODING` 或 `chcp`。
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest


DRIVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "mcp_call.py"


@pytest.fixture(scope="module")
def driver():
    spec = importlib.util.spec_from_file_location("mcp_call_driver", DRIVER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        raise httpx.HTTPStatusError("should not be called", request=None, response=None)


class _FakeClient:
    def __init__(self, response: _FakeResponse):
        self.response = response

    def post(self, url, headers=None, json=None):
        return self.response


PAYLOAD = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "list_sessions", "arguments": {}}}


class TestPostDoesNotRaise:
    """核心回归：post() 不得对 HTTP 错误抛异常（否则恢复分支不可达）。"""

    def test_404_returns_status_instead_of_raising(self, driver):
        resp, _ = driver.post(_FakeClient(_FakeResponse(404, "Not Found")), PAYLOAD, "stale-sid")
        assert resp["http_status"] == 404

    def test_500_also_returns_status(self, driver):
        resp, _ = driver.post(_FakeClient(_FakeResponse(500, "boom")), PAYLOAD, "sid")
        assert resp["http_status"] == 500

    def test_fake_response_would_explode_if_raise_for_status_were_called(self, driver):
        """哨兵：_FakeResponse.raise_for_status 会抛——post() 调了就会被测出来。"""
        _FakeClient(_FakeResponse(404, "x"))
        with pytest.raises(httpx.HTTPStatusError):
            _FakeResponse(404, "x").raise_for_status()

    def test_success_still_parses_json(self, driver):
        body = '{"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}'
        resp, sid = driver.post(
            _FakeClient(_FakeResponse(200, body, {"mcp-session-id": "new-sid"})), PAYLOAD, None)
        assert resp["result"] == {"ok": True}
        assert sid == "new-sid"

    def test_sse_body_still_parsed(self, driver):
        body = 'event: message\ndata: {"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}\n\n'
        resp, _ = driver.post(_FakeClient(_FakeResponse(200, body)), PAYLOAD, "sid")
        assert resp["result"] == {"ok": True}


class TestStaleDetection:
    def test_404_is_stale(self, driver):
        assert driver._is_stale_session({"http_status": 404, "http_body": ""}) is True

    def test_500_is_not_stale(self, driver):
        assert driver._is_stale_session({"http_status": 500, "http_body": "boom"}) is False

    def test_500_whose_body_mentions_404_is_not_stale(self, driver):
        """状态码明确时不再靠字符串猜，否则会白重建一次会话。"""
        assert driver._is_stale_session(
            {"http_status": 500, "http_body": "upstream returned 404"}) is False

    def test_protocol_error_code_still_detected(self, driver):
        resp = {"jsonrpc": "2.0", "id": 1,
                "error": {"code": -32001, "message": "Session not found"}}
        assert driver._is_stale_session(resp) is True

    def test_normal_result_is_not_stale(self, driver):
        assert driver._is_stale_session({"result": {"ok": True}}) is False

    def test_non_dict_is_not_stale(self, driver):
        assert driver._is_stale_session(None) is False


# --------------------------------------------------------------------------- #
# S26：mcp_call.py 的输出必须是可解析的 JSON
#
# 实测到的三个根因（Windows 中文环境）：
# 1. print(json.dumps(resp, ensure_ascii=False)) 用**平台默认编码**写 stdout
#    （中文环境是 cp936）→ 结果里的中文变成 cp936 字节，按 UTF-8 读的调用方在
#    第一个中文字节上整体失败：UnicodeDecodeError: byte 0xf6 in position 396；
#    非 cp936 字符（emoji）更会让 print 直接抛 UnicodeEncodeError，stdout 空。
# 2. stderr 上的中文诊断同样是 cp936；调用方 2>&1 合流时它被插到 JSON 前面，
#    整段字节流从此不可解析（实测在 position 0 就崩）。
# 3. 结果提取又脆又静默：只认以 event: 开头的 SSE、只取**第一条** data: 行，
#    其它情况直接 json.loads —— 掺了启动横幅或 SSE 以 data: 开头时抛裸
#    JSONDecodeError，stdout 一个字节都没有，也不给可读诊断。
#
# 夹具一律直接写**字节**（b"ÄãºÃ" 是 GBK 的「你好」），
# 不依赖终端编码。
# --------------------------------------------------------------------------- #
# GBK 的「你好」；作为 UTF-8 解码必然是坏的。
GBK_HELLO = b"\xc4\xe3\xba\xc3"
CLEAN_STDOUT = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "result": {"ok": True, "path": "C:/Users/史霁/x"}},
    ensure_ascii=False).encode("utf-8")


@pytest.fixture(scope="module")
def driver():
    spec = importlib.util.spec_from_file_location("mcp_call_driver_s26", DRIVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# 1. 显式解码：坏字节只损坏自己
# --------------------------------------------------------------------------- #
class TestExplicitDecoding:
    def test_gbk_bytes_do_not_kill_a_utf8_payload(self, driver):
        text = driver.decode_bytes(CLEAN_STDOUT + GBK_HELLO)
        assert "史霁" in text, "干净部分必须完好"
        assert "result" in text

    def test_decoding_is_explicit_not_platform_default(self, driver):
        """绝不能用平台默认编码：同样的字节在任何机器上结果必须一致。"""
        assert driver.decode_bytes(GBK_HELLO).encode("utf-8", "replace") != GBK_HELLO
        assert driver.decode_bytes(GBK_HELLO) == GBK_HELLO.decode("utf-8", "replace")

    def test_str_input_is_passed_through(self, driver):
        assert driver.decode_bytes("已经 是文本") == "已经 是文本"


# --------------------------------------------------------------------------- #
# 2. 流分离：stderr 只用于诊断，绝不进结果
# --------------------------------------------------------------------------- #
class TestStderrNeverPollutesResult:
    def test_clean_stdout_with_gbk_stderr_still_yields_the_result(self, driver):
        """夹具：stdout 干净（UTF-8）+ stderr 是 GBK 字节 → 结果照样取得到。"""
        result = driver.parse_payload(CLEAN_STDOUT, where="stdout")
        diagnostic = driver.decode_bytes(GBK_HELLO)          # stderr 只用来诊断
        assert result["result"]["ok"] is True
        assert result["result"]["path"].endswith("史霁/x")
        assert "result" not in diagnostic, "诊断不能被当成结果"

    def test_diagnostic_of_gbk_stderr_is_readable_and_bounded(self, driver):
        """GBK 的 stderr 要能给出**可读**诊断，而不是抛异常或原样吐回坏字节。"""
        message = driver.truncate(driver.decode_bytes(GBK_HELLO + b"!" * 5000))
        assert message                                   # 非空、可读
        assert len(message) < 600, "诊断必须先截断，不能把整段原始输出吐出来"

    def test_result_goes_to_stdout_and_diagnostic_to_stderr(self, driver, capsys):
        driver.emit_result({"result": {"ok": True}})
        driver.diagnose("诊断（只该出现在 stderr）")
        captured = capsys.readouterr()
        assert json.loads(captured.out) == {"result": {"ok": True}}, \
            "stdout 里必须只有结果，且是干净 JSON"
        assert "诊断" in captured.err
        assert "诊断" not in captured.out


# --------------------------------------------------------------------------- #
# 3. 容错提取
# --------------------------------------------------------------------------- #
class TestTolerantExtraction:
    def test_plain_json(self, driver):
        assert driver.extract_result('{"result": {"ok": true}}')["result"] == {"ok": True}

    def test_sse_with_event_line(self, driver):
        body = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n'
        assert driver.extract_result(body)["result"] == {"ok": True}

    def test_sse_with_crlf(self, driver):
        body = 'event: message\r\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\r\n\r\n'
        assert driver.extract_result(body)["result"] == {"ok": True}

    def test_sse_starting_with_a_data_line(self, driver):
        """SSE 直接以 ``data:`` 开头（没有 ``event:`` 行）此前**完全不被识别**。"""
        body = 'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n'
        assert driver.extract_result(body)["result"] == {"ok": True}

    def test_sse_with_a_notification_before_the_reply(self, driver):
        """一条流里先来通知、应答在后面：此前取**第一条** data 行 → 永远拿不到结果。"""
        body = ('event: message\n'
                'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
                'event: message\n'
                'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n')
        assert driver.extract_result(body)["result"] == {"ok": True}

    def test_banner_prefix_before_the_json(self, driver):
        """夹具：stdout 前面掺了启动横幅（FastMCP 那种）→ 仍要取到结果。"""
        banner = ("\n\n+---------------------------+\n|        FastMCP 4.0.10     |\n"
                  "+---------------------------+\nServer: Web API Extractor\n")
        body = banner + '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'
        assert driver.extract_result(body)["result"] == {"ok": True}

    def test_banner_and_chinese_survive(self, driver):
        body = ("启动横幅: FastMCP 4.0.10\n"
                '{"jsonrpc":"2.0","id":1,"result":{"path":"C:/Users/史霁/x"}}')
        assert driver.extract_result(body)["result"]["path"].endswith("史霁/x")

    def test_empty_payload_is_none(self, driver):
        assert driver.parse_payload(b"") is None

    def test_decode_is_lenient_so_gbk_bytes_still_leave_a_usable_result(self, driver):
        """体里某个字符串字段混了坏字节时，其余部分仍要能解析出来（不整段报废）。"""
        body = (b'{"jsonrpc":"2.0","id":1,"result":{"ok":true,"note":"'
                + GBK_HELLO + b'"}}')
        result = driver.parse_payload(body)
        assert result["result"]["ok"] is True
        assert "�" in result["result"]["note"], "坏字节只该损坏它自己那一小段"


# --------------------------------------------------------------------------- #
# 4. 真的没有 JSON：明确报错、可读、不吞
# --------------------------------------------------------------------------- #
class TestNoJsonAtAll:
    def test_raises_with_a_readable_diagnostic(self, driver):
        with pytest.raises(driver.ResultParseError) as excinfo:
            driver.extract_result("<html><body>502 Bad Gateway</body></html>")
        message = str(excinfo.value)
        assert "502 Bad Gateway" in message
        assert "JSON" in message

    def test_gbk_only_body_raises_instead_of_silently_returning_nothing(self, driver):
        with pytest.raises(driver.ResultParseError):
            driver.parse_payload(GBK_HELLO * 10)

    def test_diagnostic_is_truncated_not_a_full_dump(self, driver):
        """分析摘要动辄几 MB：报错里绝不能整段吐出来。"""
        huge = "x" * 200_000
        with pytest.raises(driver.ResultParseError) as excinfo:
            driver.extract_result(huge + "<not json>")
        message = str(excinfo.value)
        assert len(message) < 2000, f"诊断没有截断，长度 {len(message)}"
        assert "已截断" in message
        assert "x" * 5000 not in message

    def test_truncate_keeps_both_ends(self, driver):
        text = "HEAD" + "m" * 10_000 + "TAIL"
        result = driver.truncate(text, limit=100)
        assert result.startswith("HEAD") and result.endswith("TAIL")
        assert len(result) < 200


# --------------------------------------------------------------------------- #
# 5. 端到端（子进程 + 真实 HTTP 服务）：这是 cp936 那条根因的回归
# --------------------------------------------------------------------------- #
class _FakeMcpServer:
    """最小 streamable-HTTP 服务：只认识 initialize / tools/call。

    另外把**中文写进 stderr**（模拟 FastMCP 启动横幅那类噪音），证明它进不了结果。
    """

    def __init__(self) -> None:
        self.sessions: set[str] = set()
        self.banner_printed = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                sid = self.headers.get("Mcp-Session-Id")
                if not outer.banner_printed:
                    # 服务端把横幅写进 stderr（真实场景里这就是 cp936 的来源）。
                    sys.stderr.write("FastMCP 启动横幅：监听中…\n")
                    outer.banner_printed = True
                if sid and sid not in outer.sessions:
                    self._reply(404, b"session not found", "text/plain")
                    return
                method = payload.get("method")
                if method == "initialize":
                    new_sid = "sid-1234"
                    outer.sessions.add(new_sid)
                    body = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {
                        "protocolVersion": "2025-03-26",
                        "serverInfo": {"name": "fake", "version": "0"}}})
                    self._reply(200, _sse(body), "text/event-stream",
                                {"mcp-session-id": new_sid})
                    return
                if method == "notifications/initialized":
                    self._reply(202, b"", "text/plain")
                    return
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                    "content": [{"type": "text", "text": json.dumps(
                        {"path": "C:/Users/史霁/数据", "emoji": "🖥", "ok": True},
                        ensure_ascii=False)}]}}, ensure_ascii=False)
                self._reply(200, _sse(body), "text/event-stream")

            def _reply(self, status, body: bytes, ctype: str, extra=None):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for key, value in (extra or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        def _sse(body: str) -> bytes:
            return f"event: message\r\ndata: {body}\r\n\r\n".encode("utf-8")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def _run_driver(port: int, cache: pathlib.Path, *, mode: str = "capture") -> subprocess.CompletedProcess:
    """在子进程里跑真实的 mcp_call.main()（stdout 被重定向 → 触发 cp936 那条路径）。

    ``mode``: capture = stdout/stderr 分开抓；merged = 调用方 ``2>&1`` 合流。
    """
    child = (
        "import importlib.util, pathlib, sys\n"
        f"spec = importlib.util.spec_from_file_location('drv', r'{DRIVER_PATH}')\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        f"module.BASE = 'http://127.0.0.1:{port}/mcp'\n"
        f"module.CACHE = pathlib.Path(r'{cache}')\n"
        "sys.argv = ['mcp_call.py', 'list_sessions', '{}']\n"
        "module.main()\n")
    kwargs = {"stdout": subprocess.PIPE, "cwd": str(DRIVER_PATH.parent)}
    if mode == "merged":
        kwargs["stderr"] = subprocess.STDOUT
    else:
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run([sys.executable, "-c", child], **kwargs)


class TestEndToEndSubprocess:
    def test_stdout_is_strict_utf8_json_even_with_chinese_and_emoji(self, tmp_path):
        """核心回归：stdout 必须是**严格 UTF-8**，UTF-8 消费者能直接 json.loads。

        修复前：cp936 字节 → UnicodeDecodeError（中文）；emoji 更会让 print 直接
        抛 UnicodeEncodeError，stdout 一个字节都没有。
        """
        with _FakeMcpServer() as server:
            cache = tmp_path / ".mcp_session"
            proc = _run_driver(server.port, cache)
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        text = proc.stdout.decode("utf-8")               # 严格解码，不容错
        parsed = json.loads(text)
        inner = json.loads(parsed["result"]["content"][0]["text"])
        assert inner["ok"] is True
        assert inner["path"].endswith("史霁/数据")
        assert inner["emoji"] == "🖥", "非 cp936 字符不能把整次调用打死"
        # 服务端的横幅只走 stderr，绝不进结果。
        assert "启动横幅" not in text

    def test_stale_session_diagnostic_does_not_break_a_merged_stream(self, tmp_path):
        """调用方 ``2>&1`` 合流时也要能取出结果（此前 cp936 诊断字节在 position 0 就崩）。"""
        with _FakeMcpServer() as server:
            cache = tmp_path / ".mcp_session"
            cache.write_text("stale-session-id", encoding="utf-8")
            proc = _run_driver(server.port, cache, mode="merged")
        assert proc.returncode == 0
        merged = proc.stdout.decode("utf-8")             # 严格 UTF-8：诊断也是 UTF-8
        assert "会话已失效" in merged, "诊断本身要可读"
        # 整段字节流里能定位到 JSON 对象 → 调用方不会被诊断噎死。
        spec = importlib.util.spec_from_file_location("drv_merge", DRIVER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.extract_result(merged)["result"]["content"]

    def test_missing_json_reports_readably_and_does_not_swallow(self, tmp_path):
        """服务返回非 JSON（HTML 错误页）时：非零退出 + 可读诊断 + stdout 干净。"""
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                body = b"<html><body>502 Bad Gateway</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            proc = _run_driver(server.server_address[1], tmp_path / ".mcp_session")
        finally:
            server.shutdown()
            server.server_close()

        assert proc.returncode != 0, "解析失败必须非零退出，不能假装成功"
        assert proc.stdout == b"", "失败时 stdout 不能留下像结果的东西"
        err = proc.stderr.decode("utf-8", "replace")
        assert "502 Bad Gateway" in err
        assert "Traceback" not in err, "要给人看的诊断，不是裸 traceback"


# --------------------------------------------------------------------------- #
# R5：输出编码由**工具自己**处理对
#
# 两条契约必须同时成立（用户不设任何环境变量、不改控制台代码页）：
#   1. 非 TTY（管道 / 重定向 / 文件）：stdout 是**确定的 UTF-8 字节**，调用方
#      `bytes.decode("utf-8")` 严格解码必须成功（夹具一律直接写字节）；
#   2. TTY（真控制台）：屏幕上是中文，不是「浣犲ソ」。
#
# 第 2 条只靠单测测不出来——「屏幕上是什么」得真的去问控制台。下面的
# ``CONSOLE_HARNESS`` 会 AllocConsole() 建一个**真控制台**，把它的 CONOUT$ 句柄当
# 子进程的 stdout 起一个**真的 mcp_call 输出路径**，再用 ReadConsoleOutputCharacterW
# 把屏幕缓冲区里的字符读回来。实测矩阵（Windows 11 / CPython 3.13）：
#
#   Python 控制台流        输出代码页   写 UTF-8 字节
#   现代（PEP 528）          936         中文正确
#   现代（PEP 528）          65001       中文正确
#   旧式（legacy stdio）     936         **乱码**（用户报的那个现象）
#   旧式（legacy stdio）     65001       中文正确
#
# 所以修法是：真控制台上把输出代码页切成 UTF-8（退出时还原），字节照旧写 UTF-8。
# --------------------------------------------------------------------------- #
class TestEncodingHardeningDecisions:
    """``harden_stream_encoding`` 的分支：非 TTY 只认字节，真控制台改输出代码页。"""

    def test_absent_stream(self, driver):
        assert driver.harden_stream_encoding(None) == "absent"

    def test_non_console_stream_keeps_utf8_bytes(self, driver):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp936")
        assert driver.harden_stream_encoding(stream) == "bytes-utf8",             "非 TTY 不得改变字节编码：写出去的必须一直是 UTF-8 字节"
        assert stream.encoding == "utf-8", "文本层也别再产出 cp936 字节（best-effort）"

    def test_real_console_sets_the_utf8_code_page(self, driver, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(driver, "_console_handle", lambda stream: 1234)
        monkeypatch.setattr(driver, "_get_console_output_cp", lambda: 936)
        monkeypatch.setattr(driver, "_set_console_output_cp",
                            lambda cp: calls.append(cp) or True)
        monkeypatch.setattr(driver, "_ORIGINAL_CONSOLE_CP", None)
        monkeypatch.setattr(driver, "_RESTORE_REGISTERED", True)

        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp936")
        assert driver.harden_stream_encoding(stream) == "console-utf8"
        assert calls == [driver.CONSOLE_CODE_PAGE_UTF8],             "真控制台上必须把输出代码页切成 UTF-8，否则中文就是乱码"

    def test_code_page_is_never_claimed_when_it_cannot_be_set(self, driver, monkeypatch):
        monkeypatch.setattr(driver, "_console_handle", lambda stream: 1234)
        monkeypatch.setattr(driver, "_get_console_output_cp", lambda: 936)
        monkeypatch.setattr(driver, "_set_console_output_cp", lambda cp: False)
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp936")
        assert driver.harden_stream_encoding(stream) == "bytes-utf8",             "改不了代码页就不能声称自己把控制台处理好了"

    def test_utf8_code_page_is_left_alone(self, driver, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(driver, "_console_handle", lambda stream: 1234)
        monkeypatch.setattr(driver, "_get_console_output_cp",
                            lambda: driver.CONSOLE_CODE_PAGE_UTF8)
        monkeypatch.setattr(driver, "_set_console_output_cp",
                            lambda cp: calls.append(cp) or True)
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp936")
        assert driver.harden_stream_encoding(stream) == "console-utf8"
        assert calls == [], "已经是 UTF-8 就别再动控制台"

    def test_importing_the_module_already_hardened_both_streams(self, driver):
        """导入即处理：调用方不必记得先调什么，输出编码天然是对的。"""
        assert len(driver.OUTPUT_ENCODING_NOTES) == 2
        assert all(note in {"bytes-utf8", "console-utf8", "absent"}
                   for note in driver.OUTPUT_ENCODING_NOTES)


class TestNonTtyOutputIsStrictUtf8:
    """① 管道/重定向：机器读到的必须是**能严格解码的 UTF-8**。"""

    def test_pipe_stdout_decodes_strictly_as_utf8(self, tmp_path):
        child = (
            "import importlib.util, sys;"
            f"spec = importlib.util.spec_from_file_location('drv', r'{DRIVER_PATH}');"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
            "sys.stderr.write('notes=' + repr(m.OUTPUT_ENCODING_NOTES));"
            "m.emit_result({'result': {'path': 'C:/Users/\u53f2\u9701/\u6570\u636e'}})"
        )
        proc = subprocess.run([sys.executable, "-c", child], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, cwd=str(DRIVER_PATH.parent))
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        text = proc.stdout.decode("utf-8")          # 严格解码，不容错
        assert json.loads(text)["result"]["path"].endswith("史霁/数据")
        err = proc.stderr.decode("utf-8", "replace")
        assert err.count("bytes-utf8") == 2,             f"非 TTY 下两个流都该走「字节 UTF-8」这条路：{err}"


CONSOLE_HARNESS = r'''
# 由 tests/test_mcp_call_driver.py 内嵌、写到临时目录后运行。
# 用法：python console_harness.py <driver.py> <workdir> [legacy|modern]
# 它 AllocConsole() 建真控制台 → 用 CONOUT$ 当子进程 stdout 跑 mcp_call 的输出路径
# → ReadConsoleOutputCharacterW 读回**屏幕上的字符** → 以 ASCII 转义打印。
# 自身只打印 ASCII，所以测试断言与任何终端编码无关。
# -*- coding: utf-8 -*-
"""真控制台渲染验证工具（简化版，供测试内嵌使用）。

用法：python console_harness.py <driver.py> <workdir>
在**新建的真控制台**上跑一条 mcp_call 输出路径，然后把屏幕缓冲区里的字符以
ASCII 转义打出来（调用方据此断言「人眼看到的是什么」）。

只打印 ASCII，自身编码能力不参与任何断言。
"""
import ctypes
import ctypes.wintypes as wt
import msvcrt
import os
import subprocess
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, wt.HANDLE]

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
SHARE = 0x1 | 0x2
OPEN_EXISTING = 3
ROWS, COLS = 8, 110

# 子进程：导入 mcp_call 并输出一段含中文的结果。路径用 \u 转义写，命令行保持纯 ASCII。
CHILD = (
    "import importlib.util;"
    "spec=importlib.util.spec_from_file_location('drv', r'{driver}');"
    "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
    "m.emit_result({{'result':{{'path':'C:/Users/\\u53f2\\u9701/\\u6570\\u636e',"
    "'ok':True}}}})"
)


class COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


def read_screen(handle):
    buf = ctypes.create_unicode_buffer(ROWS * COLS)
    read = wt.DWORD(0)
    if not k32.ReadConsoleOutputCharacterW(handle, buf, ROWS * COLS, COORD(0, 0),
                                          ctypes.byref(read)):
        return f"<read failed {ctypes.get_last_error()}>"
    text = buf[:read.value]
    return "".join(text[i * COLS:(i + 1) * COLS].rstrip() + "\n" for i in range(ROWS))


def main():
    driver, workdir = sys.argv[1], sys.argv[2]
    legacy = (sys.argv[3] if len(sys.argv) > 3 else "legacy")
    k32.FreeConsole()
    if not k32.AllocConsole():
        print("NO_CONSOLE")
        return
    # 别在用户桌面上闪一个控制台窗口出来（缓冲区照样渲染，读回不受影响）。
    ctypes.windll.user32.ShowWindow(k32.GetConsoleWindow(), 0)
    handle = k32.CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE, SHARE,
                             None, OPEN_EXISTING, 0, None)
    if handle in (-1, 0, None):
        print("NO_CONSOLE")
        return
    print(f"CP_BEFORE={k32.GetConsoleOutputCP()}")
    fd = msvcrt.open_osfhandle(handle, os.O_RDWR)
    env = dict(os.environ)
    env["PYTHONUTF8"] = "0"
    env["PYTHONIOENCODING"] = ""
    env["PYTHONLEGACYWINDOWSSTDIO"] = "1" if legacy == "legacy" else "0"
    proc = subprocess.Popen([sys.executable, "-c", CHILD.format(driver=driver)],
                            stdout=fd, stderr=fd, env=env, cwd=workdir)
    code = proc.wait(timeout=90)
    screen = read_screen(handle)
    print(f"CHILD_EXIT={code} MODE={legacy}")
    print("SCREEN=" + screen.encode("unicode_escape").decode("ascii"))
    print(f"CP_AFTER={k32.GetConsoleOutputCP()}")


if __name__ == "__main__":
    main()
'''


@pytest.mark.skipif(sys.platform != "win32", reason="输出代码页只存在于 Windows 控制台")
class TestRealConsoleRendering:
    """② 真控制台：屏幕上必须是中文（用户报的乱码就在这里）。"""

    def _screen(self, tmp_path, mode: str) -> tuple[str, int, int]:
        harness = tmp_path / "console_harness.py"
        harness.write_text(CONSOLE_HARNESS, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(harness), str(DRIVER_PATH), str(tmp_path), mode],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        out = proc.stdout.decode("ascii", "replace")
        assert "NO_CONSOLE" not in out, f"本机建不出控制台，这条测不了：{out}"
        err = proc.stderr.decode("utf-8", "replace")
        assert "SCREEN=" in out, f"渲染工具没给出屏幕内容：{out}\n{err}"
        escaped = out.split("SCREEN=", 1)[1].splitlines()[0]
        screen = escaped.encode("ascii").decode("unicode_escape")
        cp_before = int(out.split("CP_BEFORE=", 1)[1].splitlines()[0])
        cp_after = int(out.split("CP_AFTER=", 1)[1].splitlines()[0])
        return screen, cp_before, cp_after

    def test_legacy_stdio_console_shows_chinese(self, tmp_path):
        """旧式控制台流（``PYTHONLEGACYWINDOWSSTDIO=1``）：改动前这里就是乱码。"""
        screen, _before, _after = self._screen(tmp_path, "legacy")
        assert "史霁/数据" in screen, f"控制台上中文没显示对：{screen!r}"

    def test_modern_console_shows_chinese(self, tmp_path):
        screen, _before, _after = self._screen(tmp_path, "modern")
        assert "史霁/数据" in screen, f"控制台上中文没显示对：{screen!r}"

    def test_the_users_console_code_page_is_restored(self, tmp_path):
        """改代码页只为这一次输出：退出时还原，不留副作用给用户的控制台。"""
        _screen, before, after = self._screen(tmp_path, "legacy")
        assert after == before, f"进程退出后代码页没还原：{before} -> {after}"
