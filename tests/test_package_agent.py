# -*- coding: utf-8 -*-
"""打包脚本必须只产出自足的技能导入包。

背景（都是真发生过的）：

- `$include` 曾漏掉 runbook/00 让 Agent 使用的 bootstrap / start_server.py / mcp_call.py，
  打出的 zip 导入后按手册走会直接找不到脚本；
- zip 曾把仓库根当成默认输出并误提交进仓库（.gitignore 里至今留着这条注释）；
- 现在有 .ps1 与 .py 两份清单，只改一边就会让「用哪份打」决定包里有什么。

因此这里只断言**清单关系**（两份一致、必含项在、运行产物不在），不断言 zip 字节，
也不锁打印文案 —— 改实现方式不该让测试变红。
"""
from __future__ import annotations

import importlib.util
import re
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PS1 = ROOT / "package-agent.ps1"


def _load_module():
    """文件名带连字符，import 语句用不了，用 spec 直接加载。"""
    spec = importlib.util.spec_from_file_location("package_agent", ROOT / "package-agent.py")
    assert spec and spec.loader, "加载 package-agent.py 失败"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


package_agent = _load_module()


def _ps1_include() -> list[str]:
    block = re.search(r"\$include\s*=\s*@\((.*?)\)", PS1.read_text(encoding="utf-8"), re.S)
    assert block, "package-agent.ps1 里找不到 $include 清单（改结构要同步改这里）"
    return re.findall(r'"([^"]+)"', block.group(1))


@pytest.fixture()
def built(tmp_path):
    """打一次真包，返回 (zip 路径, 条目名列表)。"""
    dest = tmp_path / "nested" / "pkg.zip"   # 嵌套目录顺带验证 dest.parent 会自动建
    names = package_agent.build_zip(dest)
    return dest, names


class TestManifestsAgree:
    def test_py_and_ps1_include_match(self):
        """两份脚本都要对使用者分发，清单只改一边 = 用哪份打结果不同。"""
        assert list(package_agent.INCLUDE) == _ps1_include()

    def test_zip_entries_sorted(self, built):
        """条目顺序稳定，才能比对两次打包 / 两份脚本的产物。"""
        _, names = built
        assert names == sorted(names)


class TestPackageIsSelfSufficient:
    @pytest.mark.parametrize("required", [
        "SKILL.md",                  # 技能导入要求它在包根
        "docs/reference.md",
        "runbook/00-environment.md",
        "bootstrap.py",
        "start_server.py",           # runbook 与 SKILL.md 硬规则都要求用它起服务
        "mcp_call.py",
        "run_http.py",
        "install-agent.ps1",
        "webapi_extractor/server.py",
    ])
    def test_required_member_present(self, built, required):
        _, names = built
        assert required in names

    def test_skill_md_is_at_package_root(self, built):
        """套一层目录的话技能导入认不出 —— 解压后 SKILL.md 必须在根上。"""
        _, names = built
        assert "SKILL.md" in names
        assert not any(n.startswith("web-api-extractor/") for n in names)

    def test_every_runbook_module_packaged(self, built):
        _, names = built
        expected = {f"runbook/{p.name}" for p in (ROOT / "runbook").glob("*.md")}
        assert expected <= set(names)


class TestRuntimeArtifactsExcluded:
    def test_no_cache_or_venv_entries(self, built):
        _, names = built
        for name in names:
            parts = name.split("/")
            assert not any(p in {"__pycache__", ".venv", ".git",
                                 ".pytest_cache", ".mypy_cache"} for p in parts), name
            assert not any(p.endswith(".egg-info") for p in parts), name
            assert Path(name).suffix not in {".pyc", ".pyo"}, name

    def test_cache_dir_present_on_disk_is_skipped(self, tmp_path, monkeypatch):
        """不靠「碰巧仓库里没有缓存」，而是真的给一份带产物的树。"""
        monkeypatch.setattr(package_agent, "INCLUDE", ("pkg", "SKILL.md"))
        (tmp_path / "pkg" / "__pycache__").mkdir(parents=True)
        (tmp_path / "pkg" / "__pycache__" / "mod.cpython-310.pyc").write_bytes(b"x")
        (tmp_path / "pkg" / "demo.egg-info").mkdir()
        (tmp_path / "pkg" / "demo.egg-info" / "PKG-INFO").write_text("nope", encoding="utf-8")
        (tmp_path / "pkg" / "keep.py").write_text("ok", encoding="utf-8")
        (tmp_path / "SKILL.md").write_text("s", encoding="utf-8")

        names = package_agent.build_zip(tmp_path / "out.zip", root=tmp_path)

        assert names == ["SKILL.md", "pkg/keep.py"]


class TestFailureModes:
    def test_missing_manifest_item_raises(self, tmp_path, monkeypatch):
        """缺文件必须在打包时炸掉，而不是产出一个少脚本的 zip。"""
        monkeypatch.setattr(package_agent, "INCLUDE", ("SKILL.md", "not_here.py"))
        (tmp_path / "SKILL.md").write_text("s", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            package_agent.build_zip(tmp_path / "out.zip", root=tmp_path)

    def test_existing_zip_is_replaced_not_appended(self, built):
        dest, names = built          # built 已打过一次；再打一遍不应翻倍
        again = package_agent.build_zip(dest)
        assert again == names
        with zipfile.ZipFile(dest) as zf:
            assert sorted(zf.namelist()) == names

    def test_default_output_stays_gitignored(self):
        """默认输出落在仓库根，历史上正是这样误提交过一次 zip。"""
        assert "*.zip" in (ROOT / ".gitignore").read_text(encoding="utf-8")
