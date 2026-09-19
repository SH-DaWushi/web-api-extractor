# -*- coding: utf-8 -*-
"""代理环境变量清洗：httpx 无法解析 NO_PROXY 里的方括号 IPv6 字面量。

现象：环境里 NO_PROXY 含 `[::1]`（Cherry Studio 默认写入的形态）时，
**任何** 用默认 trust_env=True 的 httpx 客户端都在构造阶段崩溃：

    httpx.InvalidURL: Invalid port: ':1]'

要点：
  * 崩溃发生在**构造**阶段，与请求是否经过代理无关；
  * 裸 `::1` 无害，`[::1]` 才有毒；
  * 回环客户端用 trust_env=False 更彻底（见 mcp_call.py），
    访问外部站点的客户端用本模块清洗（保留代理能力）。

注意：_sanitize_no_proxy 在 generator 的 **_SERVER_TEMPLATE 模板字符串**内
（生成的 server 是独立部署单元，不依赖本包），故与 _load_dotenv 一样，
测试直接从模板文本抽取该段执行。
"""
from __future__ import annotations

import os
import sys

import httpx
import pytest

from webapi_extractor.generator import _SERVER_TEMPLATE
from webapi_extractor.proxy_env import sanitize_no_proxy


# Cherry Studio 实际写入的形态：裸 ::1 与方括号 [::1] 同时存在。
CHERRY_NO_PROXY = "localhost,127.0.0.1,::1,windows10.corp.example,[::1]"
POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows 环境变量名大小写不敏感，NO_PROXY 与 no_proxy 是同一个变量",
)


@pytest.fixture
def broken_no_proxy(monkeypatch):
    """复现缺陷环境：NO_PROXY 含方括号 IPv6。

    注意不要在 fixture 里删 `no_proxy`：Windows 下它与 `NO_PROXY` 是同一个
    变量，`delenv("no_proxy")` 会把刚设好的值一并删掉，导致用例静默失效。
    """
    monkeypatch.setenv("NO_PROXY", CHERRY_NO_PROXY)
    return CHERRY_NO_PROXY


class TestSanitize:
    def test_strips_brackets(self, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "[::1]")
        assert sanitize_no_proxy() is True
        assert os.environ["NO_PROXY"] == "::1"

    def test_preserves_other_entries(self, broken_no_proxy):
        sanitize_no_proxy()
        entries = os.environ["NO_PROXY"].split(",")
        assert "localhost" in entries
        assert "127.0.0.1" in entries
        assert "windows10.corp.example" in entries
        assert "[::1]" not in entries
        assert "::1" in entries

    def test_no_brackets_is_noop(self, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,::1")
        assert sanitize_no_proxy() is False
        assert os.environ["NO_PROXY"] == "localhost,127.0.0.1,::1"

    def test_idempotent(self, broken_no_proxy):
        assert sanitize_no_proxy() is True
        assert sanitize_no_proxy() is False   # 第二次已无方括号

    @POSIX_ONLY
    def test_lowercase_var_too(self, monkeypatch):
        monkeypatch.setenv("no_proxy", "[::1],localhost")
        assert sanitize_no_proxy() is True
        assert os.environ["no_proxy"] == "::1,localhost"

    def test_empty_and_missing_are_safe(self, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "")
        assert sanitize_no_proxy() is False


class TestHttpxConstructionRegression:
    """核心回归：修复后客户端必须能构造出来。

    这几个用例锁定了 httpx 当前的行为；若未来 httpx 自行修好方括号解析，
    `test_bracketed_ipv6_breaks_client` 会失败——那是「可以撤掉清洗」的信号，
    而非本测试写错。
    """

    def test_bracketed_ipv6_breaks_client(self, broken_no_proxy):
        with pytest.raises(httpx.InvalidURL):
            httpx.Client()

    def test_sanitize_makes_client_constructible(self, broken_no_proxy):
        sanitize_no_proxy()
        client = httpx.Client(timeout=5)
        client.close()

    async def test_async_client_also_recovers(self, broken_no_proxy):
        sanitize_no_proxy()
        client = httpx.AsyncClient(timeout=5)
        await client.aclose()

    def test_trust_env_false_immune_to_broken_no_proxy(self, broken_no_proxy):
        """回环客户端不读环境代理，即使 NO_PROXY 仍然是坏的也能构造。"""
        client = httpx.Client(timeout=5, trust_env=False)
        client.close()


def _extract_sanitize_src() -> str:
    """从模板抽出 _sanitize_no_proxy 定义 + 其模块级调用。

    锚点用行首的模块级调用 `\\n_sanitize_no_proxy()`：裸 `_sanitize_no_proxy()`
    也会匹配 `def _sanitize_no_proxy() -> None:` 那一行，导致截断在函数体内。
    结尾必须**包含调用本身**（用 +1 只到行首会把调用切掉，exec 后不生效）。
    """
    src = _SERVER_TEMPLATE
    start = src.index("def _sanitize_no_proxy")
    call = "\n_sanitize_no_proxy()"
    end = src.index(call + "\n", start) + len(call)
    return "import os\n" + src[start:end]


class TestTemplateInlined:
    """生成的 server.py 必须自带同一修复（独立部署单元，不依赖本包）。"""

    def test_template_contains_helper(self):
        assert "_sanitize_no_proxy" in _SERVER_TEMPLATE

    def test_template_calls_it_at_module_level(self):
        assert "\n_sanitize_no_proxy()\n" in _SERVER_TEMPLATE

    def test_template_calls_before_client_creation(self):
        """调用必须早于任何 httpx 客户端构造点。"""
        assert (_SERVER_TEMPLATE.index("_sanitize_no_proxy()")
                < _SERVER_TEMPLATE.index("httpx.AsyncClient"))

    def test_extracted_template_code_works(self, broken_no_proxy):
        ns: dict = {}
        exec(compile(_extract_sanitize_src(), "<tpl>", "exec"), ns)
        assert "[" not in os.environ["NO_PROXY"]
        httpx.Client(timeout=5).close()
