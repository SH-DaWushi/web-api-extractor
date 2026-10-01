# -*- coding: utf-8 -*-
"""商店版必须自足，且不得带任何指向开源版的线索。

商店版与开源版是**两个相互独立发行的版本**，分开的意义就在于让拿到商店包的人
搜不到开源版。而公开库的 README / 技术参考 / 授权文本里天然写着仓库地址、打包清单、
目录树，以及「另有开源版、它的条款是 X、想跑测试请用它」—— 这些东西一旦随商店包
发出去，隔离就失效了。

所以商店版**不是**「开源版裁掉几个开发文件」，而是**一份独立文档集**：

- 代码（`scry_mcp_gen/`）两边**逐字节相同**（这是硬要求，代码不分叉）；
- `README.md` / `README.en.md` 由 `README-STORE*.md` 顶替；
- `LICENSE` 由 `LICENSE-STORE` 顶替；
- `docs/reference.md` **两版共享**（`SKILL.md`、`runbook/` 与代码文档字符串都引用它，
  后两者不能按版本分叉），因此它自己也不得出现仓库线索 —— 打包清单与目录树搬去了
  `PACKAGING.md`，那份不在 `INCLUDE` 里，天然只属于仓库。

本文件只断言**事实关系**：真打一个商店包，逐文件扫线索、并比对两版代码一致性。
不锁文案措辞 —— 改写 README 的行文不该让测试变红。
"""
from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# 硬线索：任何文件（含代码）都不得出现。指向仓库、指向开源版、或暴露构建方式。
HARD_LEAKS = (
    "github.com",
    "SH-DaWushi",
    "shdawushi",
    "web-api-extractor",     # 旧库名，也是公开库的仓库名
    "LICENSE-STORE",         # 商店包内它叫 LICENSE；这个名字只在仓库侧成立
    "package-agent",         # 打包脚本名（不在包里，提到它就等于承认有构建流程）
    "open-source",
    "开源",
    "Releases",              # 公开库的发包渠道
)

# 泛指"仓库"的词：代码注释里出现是历史措辞（代码必须与开源版逐字节相同，不能改），
# 但**散文**里出现就说明这段文字是从仓库视角写的，不该发给商店用户。
PROSE_ONLY_LEAKS = ("仓库", "repository", "Repository")

CODE_PREFIX = "scry_mcp_gen/"


def _load_module():
    """文件名带连字符，import 语句用不了，用 spec 直接加载。"""
    spec = importlib.util.spec_from_file_location("package_agent", ROOT / "package-agent.py")
    assert spec and spec.loader, "加载 package-agent.py 失败"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


package_agent = _load_module()


@pytest.fixture(scope="module")
def store_zip(tmp_path_factory) -> Path:
    dest = tmp_path_factory.mktemp("store") / "store.zip"
    package_agent.build_zip(dest, manifest=package_agent.STORE_INCLUDE,
                            rename=package_agent.STORE_RENAME)
    return dest


@pytest.fixture(scope="module")
def oss_zip(tmp_path_factory) -> Path:
    dest = tmp_path_factory.mktemp("oss") / "oss.zip"
    package_agent.build_zip(dest)
    return dest


def _texts(dest: Path) -> dict[str, str]:
    """读出包里每个成员的可解码文本；解不开的（二进制）跳过。"""
    out: dict[str, str] = {}
    with zipfile.ZipFile(dest) as zf:
        for name in zf.namelist():
            raw = zf.read(name)
            try:
                out[name] = raw.decode("utf-8")
            except UnicodeDecodeError:      # pragma: no cover - 当前包内全是文本
                continue
    return out


class TestStorePackageCarriesNoOpenSourceHints:
    def test_package_is_not_empty(self, store_zip):
        """守卫非空转：扫一份空包永远"干净"。"""
        texts = _texts(store_zip)
        assert len(texts) > 30, f"商店包只有 {len(texts)} 个成员，扫描结论不可信"
        assert "scry_mcp_gen/server.py" in texts

    def test_no_hard_leak_in_any_file(self, store_zip):
        texts = _texts(store_zip)
        hits = [(name, token)
                for name, text in texts.items()
                for token in HARD_LEAKS if token in text]
        assert not hits, f"商店包里出现了指向开源版的线索：{hits}"

    def test_no_repo_wording_in_prose(self, store_zip):
        """散文（非代码）里不得出现"仓库"口径 —— 那是从仓库视角写的文字。"""
        texts = _texts(store_zip)
        prose = {n: t for n, t in texts.items() if not n.startswith(CODE_PREFIX)}
        hits = [(name, token)
                for name, text in prose.items()
                for token in PROSE_ONLY_LEAKS if token in text]
        assert not hits, f"商店包的散文里出现了仓库口径：{hits}"

    def test_reference_is_shipped(self, store_zip):
        """技术参考必须随包 —— SKILL.md、runbook/ 与代码都在引用它。

        它若缺席，那些引用全部悬空：Agent 会照手册去找一份不存在的文件。
        """
        texts = _texts(store_zip)
        assert "docs/reference.md" in texts
        assert "docs/reference.en.md" in texts

    @pytest.mark.parametrize("name", ["SKILL.md", "runbook/00-environment.md",
                                      "runbook/99-troubleshooting.md"])
    def test_agent_facing_docs_present(self, store_zip, name):
        assert name in _texts(store_zip)


class TestStorePackageUsesStoreDocuments:
    """商店包只能有一份 README、一份授权，且必须是商店版那几份。"""

    def test_readmes_come_from_the_store_sources(self, store_zip):
        with zipfile.ZipFile(store_zip) as zf:
            assert zf.read("README.md") == (ROOT / "README-STORE.md").read_bytes()
            assert zf.read("README.en.md") == (ROOT / "README-STORE.en.md").read_bytes()
            assert "README-STORE.md" not in zf.namelist(), "必须改名落包，不能原名出现"

    def test_license_comes_from_the_store_source(self, store_zip):
        with zipfile.ZipFile(store_zip) as zf:
            inside = zf.read("LICENSE")
        assert inside == (ROOT / "LICENSE-STORE").read_bytes()
        assert inside != (ROOT / "LICENSE").read_bytes(), \
            "商店包带的是仓库的非商业 LICENSE，等于把开源条款发给了商店用户"

    def test_store_license_does_not_mention_another_edition(self):
        """授权文本是最后一道防线：它自己不得描述开源版。

        首次发布时它有一整条「与开源版的关系」，逐条说明开源版在公共仓库、
        是非商用条款、且不放弃其限制 —— 等于把商店用户直接指向免费版本。
        """
        text = (ROOT / "LICENSE-STORE").read_text(encoding="utf-8")
        for token in HARD_LEAKS:
            assert token not in text, f"LICENSE-STORE 里出现了 {token!r}"
        for token in PROSE_ONLY_LEAKS:
            assert token not in text, f"LICENSE-STORE 里出现了 {token!r}"


class TestCodeIsIdenticalAcrossEditions:
    """代码不分叉：`scry_mcp_gen/` 两边逐字节相同。

    文档可以各写各的（那是本次隔离的目的），但**代码必须一致** —— 否则修一个
    版本会漏掉另一个，而使用者分不出自己手上的是哪一支。
    """

    def test_every_code_member_matches(self, store_zip, oss_zip):
        with zipfile.ZipFile(store_zip) as sz, zipfile.ZipFile(oss_zip) as oz:
            store_code = {n: sz.read(n) for n in sz.namelist() if n.startswith(CODE_PREFIX)}
            oss_code = {n: oz.read(n) for n in oz.namelist() if n.startswith(CODE_PREFIX)}
        assert store_code, "商店包里没有代码，比对本身失效"
        assert set(store_code) == set(oss_code), (
            f"两版代码文件集合不同：仅商店 {sorted(set(store_code) - set(oss_code))}，"
            f"仅开源 {sorted(set(oss_code) - set(store_code))}")
        differing = sorted(n for n in store_code if store_code[n] != oss_code[n])
        assert not differing, f"两版代码内容不同（{len(differing)} 个）：{differing}"

    def test_tool_count_is_the_same(self, store_zip, oss_zip):
        """工具数不变式（21）在商店包里同样成立。"""
        import re
        with zipfile.ZipFile(store_zip) as sz:
            server = sz.read(f"{CODE_PREFIX}server.py").decode("utf-8")
        assert len(re.findall(r"@mcp\.tool\(\)", server)) == 21
