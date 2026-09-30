# -*- coding: utf-8 -*-
"""Minimal streamable-HTTP MCP client driver for scry-mcp-gen.

Usage:
    python mcp_call.py <tool_name> [json_arguments]
    python mcp_call.py <tool_name> @args.json     # read arguments from a JSON file
    python mcp_call.py <tool_name> -              # read arguments from stdin

The @file / stdin forms avoid Windows shell quoting issues entirely and are the
recommended way to pass arguments containing Windows paths.

Prints the tool result as JSON. Reuses a session id cached in .mcp_session.

## 输出契约（S26：结果必须是可解析的 JSON）

**结果只走 stdout，一律 UTF-8；诊断只走 stderr，绝不出现在结果里。**

修复前这里是 cp936 的坑：``print(json.dumps(...))`` 用平台默认编码写 stdout，
而 Windows 中文环境默认 cp936——于是结果里的中文（用户名路径、提示语、URL）全都
变成 cp936 字节，按 UTF-8 读的调用方在第一个中文字节上就整体失败：

    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf6 in position 396

而 stderr 上的中文诊断（cp936）在调用方 ``2>&1`` 合流时会**插到 JSON 前面**，
整段字节流从此不可解析。现在两边都显式 UTF-8，且解析失败会给出带截断片段的
明确报错，而不是裸 traceback / 静默吞掉。

## 输出编码（R5：机器读得到、人眼看得到，**都不需要用户做任何设置**）

只把字节改成 UTF-8 还不够：管道里机器读得对，但**人**在 Windows 控制台里看到的是
控制台按**输出代码页**解释这些字节的结果。中文 Windows 默认 936，于是 UTF-8 字节在
屏幕上变成「浣犲ソ」式乱码（真机复现见 ``harden_stream_encoding`` 的矩阵）。而让用户
去设 ``PYTHONIOENCODING`` / ``chcp 65001`` 对这不是一回事——本工具**自己**把这件事
做掉，分两种情形：

* **非 TTY**（管道 / 重定向 / 文件）：只写 **UTF-8 字节**（``sys.stdout.buffer``），
  读它的程序拿到的编码是确定的；
* **TTY**（真控制台）：把控制台**输出代码页**切成 UTF-8（65001），并在退出时还原，
  这样「写 UTF-8 字节」在屏幕上也是中文。判据是句柄支持 ``ConsoleMode``，不是
  ``isatty()``（NUL 之类的字符设备 isatty 也为真，但那不是屏幕）。
"""
import atexit
import json
import os
import pathlib
import sys

import httpx

BASE = "http://127.0.0.1:8422/mcp"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
CACHE = pathlib.Path(__file__).resolve().parent / ".mcp_session"

# 结果与诊断的**显式**编码：不依赖平台默认（Windows 中文环境是 cp936）。
STREAM_ENCODING = "utf-8"
# 控制台输出代码页的 UTF-8 取值。设成它之后，控制台会按 UTF-8 解释我们写出的字节。
CONSOLE_CODE_PAGE_UTF8 = 65001
# 诊断里附带的原始片段上限。分析摘要动辄几 MB，整段吐出来既没用又淹没报错。
SNIPPET_LIMIT = 400
# 在整段文本里暴力定位 JSON 对象时，最多尝试多少个 `{` 起点。
_MAX_JSON_STARTS = 200

_MISS = object()

# --------------------------------------------------------------------------- #
# 输出编码：机器读到的必须是**确定的 UTF-8**，人在 Windows 控制台里看中文也不能乱码
# --------------------------------------------------------------------------- #
# 控制台输出代码页的还原（只在真的改过时注册一次）。
_ORIGINAL_CONSOLE_CP: int | None = None
_RESTORE_REGISTERED = False
# 每个流最后采取的做法，供诊断/测试直接看（"console-utf8" / "bytes-utf8" / "absent"）。
OUTPUT_ENCODING_NOTES: list[str] = []
# 控制台探测失败的原因（探测成功或压根不在 Windows 时为 None）。**不静默**：
# 「在真控制台上却探测不到控制台」是会直接把输出写成乱码的那类故障，必须留痕。
CONSOLE_DETECTION_ERROR: str | None = None


class ResultParseError(RuntimeError):
    """响应里定位不到 JSON 对象。message 里自带**已截断**的原始片段，可直接读。"""


def _console_handle(stream) -> int | None:
    """``stream`` 背后的 Windows **真控制台**句柄；不是控制台时返回 ``None``。

    为什么不用 ``isatty()`` 一项判定：``isatty()`` 对 NUL 之类的字符设备同样为真，
    而这里要的是「屏幕」——真正的判据是句柄支持 ``GetConsoleMode``。

    探测失败的原因留在 ``CONSOLE_DETECTION_ERROR`` 里（不静默）：这里以前栽过一次，
    `import ctypes` **不会**自动带进 `ctypes.wintypes` 子模块，于是 `ctypes.wintypes.DWORD`
    抛 AttributeError、被宽 except 吞掉，表现为「在真控制台上却探测不到控制台」，
    结果就是把中文写成了乱码而毫无线索（真机复现：同一个进程里先 `import
    ctypes.wintypes` 就正常，不导入就乱码）。
    """
    global CONSOLE_DETECTION_ERROR
    if os.name != "nt" or stream is None:
        return None
    try:
        import msvcrt
        handle = msvcrt.get_osfhandle(stream.fileno())
    except Exception as exc:                               # 没有 fileno / 句柄无效
        CONSOLE_DETECTION_ERROR = f"get_osfhandle: {type(exc).__name__}: {exc}"
        return None
    try:
        import ctypes
        import ctypes.wintypes          # 必须显式导入：ctypes 不会自动带入子模块
        mode = ctypes.wintypes.DWORD()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return handle
        CONSOLE_DETECTION_ERROR = "GetConsoleMode 返回假：该句柄不是控制台"
    except Exception as exc:                               # noqa: BLE001
        CONSOLE_DETECTION_ERROR = f"GetConsoleMode: {type(exc).__name__}: {exc}"
    return None


def _get_console_output_cp() -> int | None:
    """当前控制台输出代码页；拿不到（没有控制台）时返回 ``None``。"""
    try:
        import ctypes
        value = int(ctypes.windll.kernel32.GetConsoleOutputCP())
        return value or None
    except Exception:                                      # noqa: BLE001
        return None


def _set_console_output_cp(code_page: int) -> bool:
    """设置控制台输出代码页；成功返回 True。失败**不抛**（降级为「字节路径」）。"""
    try:
        import ctypes
        return bool(ctypes.windll.kernel32.SetConsoleOutputCP(int(code_page)))
    except Exception:                                      # noqa: BLE001
        return False


def _restore_console_code_page() -> None:
    """进程退出时把输出代码页还原：不动用户控制台的既有状态。"""
    global _ORIGINAL_CONSOLE_CP
    if _ORIGINAL_CONSOLE_CP is not None:
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(int(_ORIGINAL_CONSOLE_CP))
        except Exception:                                  # noqa: BLE001
            pass
        _ORIGINAL_CONSOLE_CP = None


def _reconfigure_text_layer(stream) -> None:
    """把文本层也钉成 UTF-8（best-effort）。

    我们自己的结果/诊断**不走**文本层（一律写字节），钉它是为了别的东西（例如
    Python 自己打的 traceback）万一写进来时，不会又变成 cp936 字节插进 UTF-8 流里。
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    try:
        reconfigure(encoding=STREAM_ENCODING, errors="replace")
    except Exception:                                      # noqa: BLE001 — 老流/假流
        pass


def harden_stream_encoding(stream) -> str:
    """把**一个输出流**的编码处理对；返回采取的做法（便于诊断与测试）。

    两条契约同时成立，缺一不可：

    * **非 TTY**（管道 / 重定向 / 文件）：我们只写 **UTF-8 字节**，读它的程序拿到的
      编码是确定的 —— 这正是上一次故障的教训（退回平台默认编码 ⇒ cp936 字节 ⇒
      按 UTF-8 读的调用方在第一个中文字节上整段失败）；
    * **TTY**（真控制台）：屏幕上是什么字，由控制台按**输出代码页**解释我们写出的
      字节决定。把输出代码页切成 UTF-8（65001）之后，现代 Python（PEP 528：控制台流
      本来就把字节按 UTF-8 解释）与旧式路径**都**能正确显示中文；进程退出时还原。

    真机实测矩阵（Windows 11 / CPython 3.13，读回控制台屏幕缓冲区里的字符）：

    ===================  ==========  =================
    Python 控制台流       输出代码页   写 UTF-8 字节的结果
    ===================  ==========  =================
    现代（PEP 528）        936         正确
    现代（PEP 528）        65001       正确
    旧式（legacy stdio）   936         **乱码**
    旧式（legacy stdio）   65001       正确
    ===================  ==========  =================

    「旧式」= ``PYTHONLEGACYWINDOWSSTDIO=1``，或任何把控制台包成普通文件流的包装层。
    乱码对应用户报的那个现象（cp936 控制台里肉眼看中文是乱码），而设置代码页是
    **唯一**能同时喂饱现代与旧式两条路径的动作。
    """
    if stream is None:
        return "absent"
    handle = _console_handle(stream)
    if handle is None:
        _reconfigure_text_layer(stream)
        return "bytes-utf8"
    global _ORIGINAL_CONSOLE_CP, _RESTORE_REGISTERED
    _reconfigure_text_layer(stream)
    current = _get_console_output_cp()
    if current == CONSOLE_CODE_PAGE_UTF8:
        return "console-utf8"                              # 已经是 UTF-8 就别动用户的控制台
    if not _set_console_output_cp(CONSOLE_CODE_PAGE_UTF8):
        return "bytes-utf8"                                # 改不了就别声称做了
    # 记下原值以便**退出时还原**；读不到原值时（罕见）不写还原逻辑，宁可少一次还原，
    # 也不要把用户控制台设成我们猜出来的代码页。
    if current is not None and _ORIGINAL_CONSOLE_CP is None:
        _ORIGINAL_CONSOLE_CP = current
    if not _RESTORE_REGISTERED:
        atexit.register(_restore_console_code_page)
        _RESTORE_REGISTERED = True
    return "console-utf8"


def harden_output_encoding() -> list[str]:
    """把 stdout / stderr 的编码一次性处理对；返回每个流采取的做法。

    幂等：重复调用不会重复改代码页，也不会重复注册还原逻辑。导入本模块即调用一次
    （在任何输出之前），所以无论从哪条路径进来，输出的编码都已经是对的了。
    """
    notes = [harden_stream_encoding(sys.stdout), harden_stream_encoding(sys.stderr)]
    OUTPUT_ENCODING_NOTES[:] = notes
    return notes


def decode_bytes(raw, encoding: str = STREAM_ENCODING) -> str:
    """显式解码：坏字节只损坏自己（errors="replace"），不毁掉整段结果。

    **不要**用 ``bytes.decode()`` 的默认参数，也不要依赖 ``response.text`` 的
    自动探测——那正是「同一份输出在不同机器上表现不同」的来源。
    """
    if isinstance(raw, str):
        return raw
    return bytes(raw).decode(encoding, "replace")


def truncate(text: str, limit: int = SNIPPET_LIMIT) -> str:
    """长度截断：超限时保留头尾，中间标注被截掉多少字符。"""
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return f"{text[:head]}…(已截断 {len(text) - limit} 字符)…{text[-tail:]}"


def _sse_payloads(text: str) -> list[str]:
    """SSE 里所有 ``data:`` 行的载荷（FastMCP 用 CRLF，按行切即可）。

    注意**不能只看第一条** ``data:``：一条流里可能先来一个通知，我们的应答在后面。
    """
    payloads = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("data:"):
            payloads.append(stripped[5:].strip())
    return payloads


def _try_json(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return _MISS


def _pick(values: list, prefer: str) -> object:
    """优先返回带 result/error 的 JSON-RPC 应答；都没有时按 prefer 兜底。"""
    for value in values:
        if isinstance(value, dict) and ("result" in value or "error" in value):
            return value
    if not values:
        return _MISS
    return values[0] if prefer == "first" else values[-1]


def _raw_object_scan(text: str):
    """文本里掺了非 JSON 前缀时的兜底：从每个 ``{`` 起尝试 raw_decode。"""
    decoder = json.JSONDecoder()
    candidates: list = []
    for index, char in enumerate(text):
        if char != "{":
            continue
        if len(candidates) >= _MAX_JSON_STARTS:
            break
        try:
            value, _ = decoder.raw_decode(text[index:])
        except ValueError:
            continue
        candidates.append(value)
        if isinstance(value, dict) and ("result" in value or "error" in value):
            break
    return candidates


def extract_result(text: str, *, where: str = "响应体"):
    """从回应文本里**容错**地取回 JSON-RPC 对象。

    顺序：
      1. 整段就是 JSON（``application/json`` 回应的正常路径）；
      2. SSE：逐条 ``data:`` 载荷尝试，优先带 result/error 的那条；
      3. 前面掺了启动横幅/日志等非 JSON 前缀：逐个 ``{`` 起点做 raw_decode。

    三者都定位不到 → ``ResultParseError``，信息里带**截断后**的原始片段与常见原因。
    **绝不**静默返回空值：调用方拿到异常就能立刻知道「这次输出不能当结果用」。
    """
    direct = _try_json(text)
    if direct is not _MISS:
        return direct
    payloads = [_try_json(payload) for payload in _sse_payloads(text)]
    payloads = [value for value in payloads if value is not _MISS]
    if payloads:
        picked = _pick(payloads, prefer="last")
        if picked is not _MISS:
            return picked
    scanned = _raw_object_scan(text)
    picked = _pick(scanned, prefer="first")
    if picked is not _MISS:
        return picked
    raise ResultParseError(_diagnose_text(text, where=where))


def _diagnose_text(text: str, *, where: str = "响应体") -> str:
    snippet = repr(truncate(text))
    return (
        f"无法从{where}里定位 JSON 对象（共 {len(text)} 字符）。\n"
        f"原始片段（已截断）：{snippet}\n"
        "常见原因：① 输出里掺了启动横幅/日志等非 JSON 前缀；"
        "② 服务返回的是 HTML 或纯文本错误页；"
        "③ 结果被别的输出混了进来（诊断必须走 stderr，不能与 stdout 合流）。"
    )


def _emit(text: str, stream) -> None:
    """按 UTF-8 写一个流（结果给 stdout，诊断给 stderr）。

    有 ``.buffer`` 就写**字节**（绕开任何平台默认编码）；没有（例如测试里替换过的
    假 stdout）就退回 ``write``。

    「人在控制台里看不看得懂」不靠这里改编码，而靠 ``harden_output_encoding()``
    把控制台的**输出代码页**摆成 UTF-8 —— 见 ``harden_stream_encoding`` 的真机矩阵。
    """
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        try:
            buffer.write(text.encode(STREAM_ENCODING))
            buffer.flush()
            return
        except (AttributeError, OSError, ValueError):
            pass
    stream.write(text)


def emit_result(payload) -> None:
    """把结果写到 stdout：**只有**这一条路径写 stdout，且一定是 UTF-8。"""
    _emit(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", sys.stdout)


def diagnose(message: str) -> None:
    """把诊断写到 stderr：从不写 stdout，于是结果永远不会被诊断污染。"""
    _emit(message.rstrip("\n") + "\n", sys.stderr)


def parse_payload(raw, *, where: str = "HTTP 响应体"):
    """字节流 → JSON-RPC 对象。解析不了就抛 ``ResultParseError``（带片段）。"""
    text = decode_bytes(raw)
    if not text.strip():
        return None
    return extract_result(text, where=where)


def load_args(raw: str) -> dict:
    """Parse tool arguments from a literal JSON string, '@file' or '-' (stdin)."""
    raw = raw.strip()
    if raw == "-":
        raw = sys.stdin.read()
    elif raw.startswith("@"):
        raw = pathlib.Path(raw[1:]).read_text(encoding="utf-8")
    return json.loads(raw) if raw else {}


def post(client: httpx.Client, payload: dict, sid: str | None):
    h = dict(HEADERS)
    if sid:
        h["Mcp-Session-Id"] = sid
    r = client.post(BASE, headers=h, json=payload)
    new_sid = r.headers.get("mcp-session-id")
    # 用**字节**自己解码（显式 utf-8 + replace）：不依赖 response.text 的自动探测，
    # 于是「服务端把中文按另一种编码吐出来」也最多只损坏那几个字，不会毁掉整段。
    content = getattr(r, "content", None)
    if isinstance(content, (bytes, bytearray)):
        out = decode_bytes(bytes(content))
    else:                                    # 兼容测试里的假响应（只有 .text）
        out = getattr(r, "text", "") or ""
    # 不要在这里 raise_for_status()：陈旧会话会得到 HTTP 404，而 404 正是
    # _is_stale_session 要识别的恢复信号——先抛异常会让恢复分支永远执行不到
    # （issue #17）。把状态码原样带回，由调用方判定。
    if r.status_code >= 400:
        return {"http_status": r.status_code, "http_body": out[:500]}, new_sid
    if not out.strip():
        return None, new_sid
    # 结果提取是**容错**的：JSON / SSE / 前面掺了横幅都能取到；取不到就抛
    # ResultParseError（带截断片段），由 main() 转成可读诊断 + 非零退出码。
    return extract_result(out, where="HTTP 响应体"), new_sid


def main():
    try:
        _run()
    except ResultParseError as exc:
        # 解析失败**明确报错**：可读诊断走 stderr，退出码非零，stdout 保持干净
        # （调用方拿不到半分「看起来像结果」的东西）。
        diagnose(f"mcp_call.py: 工具结果不可解析。\n{exc}")
        raise SystemExit(3)
    except (httpx.HTTPError, OSError) as exc:
        # 网络/连接类失败也给可读信息，而不是裸 traceback（旧行为是 traceback）。
        diagnose(f"mcp_call.py: 无法访问 {BASE}（{type(exc).__name__}: {exc}）。"
                 "服务是否已用 start_server.py 启动？")
        raise SystemExit(4)


def _run():
    tool = sys.argv[1]
    args = load_args(sys.argv[2]) if len(sys.argv) > 2 else {}
    sid = CACHE.read_text(encoding="utf-8").strip() if CACHE.exists() else None

    def initialize(client):
        resp, new_sid = post(client, {
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "driver", "version": "0"}},
        }, None)
        if not new_sid:
            diagnose("mcp_call.py: 服务没有返回会话 id：\n"
                     + truncate(json.dumps(resp, ensure_ascii=False)))
            raise SystemExit(2)
        CACHE.write_text(new_sid, encoding="utf-8")
        post(client, {"jsonrpc": "2.0", "method": "notifications/initialized"}, new_sid)
        return new_sid

    # trust_env=False：本客户端只连 127.0.0.1 回环地址，不该走任何代理——
    # 这比「清洗 NO_PROXY」更彻底。若放任 trust_env=True，httpx 会在**构造
    # 阶段**解析环境代理变量，遇到 NO_PROXY 含方括号 IPv6 字面量（Cherry
    # Studio 默认写入的 `...,::1,...,[::1]`）会直接抛
    # InvalidURL: Invalid port: ':1]'，客户端根本没建起来——即使请求压根不经过代理。
    with httpx.Client(timeout=300, trust_env=False) as client:
        if not sid:
            sid = initialize(client)
        resp, _ = post(client, {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }, sid)
        # E-2: cached session id goes stale after a server restart; the server
        # then answers 404. Detect, re-initialize once, retry automatically.
        # 该恢复分支此前是死代码——post() 的 raise_for_status() 会把 404 提前
        # 抛成异常（issue #17）。
        if _is_stale_session(resp):
            diagnose("缓存的 MCP 会话已失效（服务可能重启过），重新初始化并重试...")
            try:
                CACHE.unlink()
            except OSError:
                pass
            sid = initialize(client)
            resp, _ = post(client, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            }, sid)
        elif isinstance(resp, dict) and resp.get("http_status"):
            # 非「会话失效」的 HTTP 错误：保持原先硬失败的语义，但给出可读信息
            # 而非裸 traceback。
            diagnose(f"mcp_call.py: HTTP {resp['http_status']} from {BASE}\n"
                     f"{resp.get('http_body', '')}")
            raise SystemExit(5)
        emit_result(resp)


def _is_stale_session(resp) -> bool:
    """陈旧会话的判据：服务端对未知 Mcp-Session-Id 答 404。

    post() 对 HTTP >= 400 返回 ``{"http_status": N, "http_body": ...}``，
    故这里先认该形态；其余分支兼容 JSON-RPC 协议错误形态。
    """
    if not isinstance(resp, dict):
        return False
    if resp.get("http_status") == 404:
        return True
    if "http_status" in resp:
        # 明确的 HTTP 错误：已由状态码判定，不再靠字符串猜（否则 500 响应体里
        # 恰好出现 "404" 就会被误判成会话失效，白白重建一次会话）。
        return False
    err = resp.get("error")
    if isinstance(err, dict) and (err.get("code") == -32001 or "404" in str(err.get("message", ""))):
        return True
    return "result" not in resp and "404" in str(resp)


# 导入即把输出编码摆正：无论调用方从哪条路径进来（main()、直接 emit_result、
# 还是被当成库用），都不会再出现「机器读到 cp936」或「控制台看中文是乱码」。
# 幂等，且只在本进程真的挂在控制台上时才动控制台状态。
harden_output_encoding()


if __name__ == "__main__":
    main()
