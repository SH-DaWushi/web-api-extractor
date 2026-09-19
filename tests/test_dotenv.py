# -*- coding: utf-8 -*-
"""Issue #7：生成的 server.py 模板中 _load_dotenv 应正确剥离引号。

密钥常含 base64 的 '=' 补位，运维按 dotenv 惯例写
    SITE_TOKEN="abc=def"
时若不剥引号会把引号带进环境变量，鉴权失败且错误信息不指向根因。

注意：_load_dotenv 位于 generator 的 **_SERVER_TEMPLATE 模板字符串**内，
不是模块级函数，因此测试直接从模板文本中抽取该段执行。
"""
from __future__ import annotations

import os
import re

import pytest

from webapi_extractor.generator import _SERVER_TEMPLATE


def _extract_load_dotenv_src(here: str) -> str:
    """从模板中抽出 _unquote_env_value + _load_dotenv 的实现。

    锚点须精确：模板里 `_load_dotenv()` 也出现在 `def _load_dotenv() -> None:`
    这一行，用裸 `_load_dotenv()` 定位会截断在参数注解中间导致语法错误。
    这里用行首的模块级调用 `\n_load_dotenv()\n` 作为结束锚点。
    """
    src = _SERVER_TEMPLATE
    start = src.index("def _unquote_env_value")
    end = src.index("\n_load_dotenv()\n", start) + 1   # 保留到调用的行首
    snippet = src[start:end]
    preamble = f"import os\nfrom pathlib import Path\n_HERE = Path(r'{here}')\n"
    return preamble + snippet


class TestTemplateHasUnquote:
    def test_template_contains_helper(self):
        assert "_unquote_env_value" in _SERVER_TEMPLATE

    def test_load_dotenv_uses_helper(self):
        # 确保 _load_dotenv 真的调用了剥离逻辑，而非取回原始值
        assert "_unquote_env_value(v)" in _SERVER_TEMPLATE


class TestUnquoteBehaviour:
    """行为验证：抽模板代码执行，断言环境变量取值。"""

    @pytest.fixture
    def env_setup(self, tmp_path):
        ns: dict = {}
        exec(compile(_extract_load_dotenv_src(str(tmp_path)), "<tpl>", "exec"), ns)
        return ns, tmp_path

    def _run(self, ns, tmp_path, content: str, keys: list[str]) -> None:
        (tmp_path / ".env").write_text(content, encoding="utf-8")
        for k in keys:
            os.environ.pop(k, None)
        ns["_load_dotenv"]()

    def test_quoted_base64_token(self, env_setup):
        ns, tmp = env_setup
        keys = ["PREFIX_TOKEN"]
        self._run(ns, tmp, 'PREFIX_TOKEN="aGVsbG8+d29ybGQvPQ=="\n', keys)
        # 引号被剥离，base64 的 '=' 与 '+' '/' 完整保留
        assert os.environ["PREFIX_TOKEN"] == "aGVsbG8+d29ybGQvPQ=="

    def test_single_quoted(self, env_setup):
        ns, tmp = env_setup
        self._run(ns, tmp, "PREFIX_TOKEN='abc=def'\n", ["PREFIX_TOKEN"])
        assert os.environ["PREFIX_TOKEN"] == "abc=def"

    def test_plain_value_unchanged(self, env_setup):
        ns, tmp = env_setup
        self._run(ns, tmp, "PREFIX_TIMEOUT=30\n", ["PREFIX_TIMEOUT"])
        assert os.environ["PREFIX_TIMEOUT"] == "30"

    def test_inline_comment_stripped(self, env_setup):
        ns, tmp = env_setup
        self._run(ns, tmp, "PREFIX_ACCOUNT=user@example.com  # 账号\n", ["PREFIX_ACCOUNT"])
        assert os.environ["PREFIX_ACCOUNT"] == "user@example.com"

    def test_hash_inside_quotes_preserved(self, env_setup):
        ns, tmp = env_setup
        self._run(ns, tmp, 'PREFIX_TOKEN="val#ue"\n', ["PREFIX_TOKEN"])
        assert os.environ["PREFIX_TOKEN"] == "val#ue"

    def test_hash_without_space_is_part_of_value(self, env_setup):
        # '#' 前无空格时不视为注释，避免误伤含 # 的密钥
        ns, tmp = env_setup
        self._run(ns, tmp, "PREFIX_TOKEN=pass#word\n", ["PREFIX_TOKEN"])
        assert os.environ["PREFIX_TOKEN"] == "pass#word"

    def test_does_not_override_existing_env(self, env_setup):
        """setdefault 语义：已存在的环境变量优先。"""
        ns, tmp = env_setup
        os.environ["PREFIX_TOKEN"] = "from-env"
        (tmp / ".env").write_text('PREFIX_TOKEN="from-file"\n', encoding="utf-8")
        ns["_load_dotenv"]()
        assert os.environ["PREFIX_TOKEN"] == "from-env"
        os.environ.pop("PREFIX_TOKEN", None)

    def test_blank_lines_and_comments_skipped(self, env_setup):
        ns, tmp = env_setup
        keys = ["PREFIX_A", "PREFIX_B"]
        self._run(ns, tmp, "\n# 注释行\nPREFIX_A=1\n\nPREFIX_B=2\n", keys)
        assert os.environ["PREFIX_A"] == "1"
        assert os.environ["PREFIX_B"] == "2"
