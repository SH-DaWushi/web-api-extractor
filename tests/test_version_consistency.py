# -*- coding: utf-8 -*-
"""版本号三处必须一致：`pyproject.toml` / `__version__` / 最新 git tag。

版本号此前重复写在两个文件里（`pyproject.toml` 与 `webapi_extractor/__init__.py`），
彼此没有任何联动 —— 发布时只改一处就会静默漂移。而 git 标签是**公开且难以收回**的：
打错了要删标签重打，release URL 还会留下痕迹。

所以这里断言的是三者的**相等关系**，不锁具体数字 —— 改版本号不会让测试变红，
只有「改了一处、漏了另一处」才会。
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_VERSION_LINE = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)
_DUNDER_LINE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)
_PEP440 = re.compile(r"\d+\.\d+\.\d+(?:[.\-+][A-Za-z0-9.]+)?")


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = re.search(r"^\[project\]\s*$(.*?)(?=^\[)", text, re.S | re.M)
    assert block, "pyproject.toml 里找不到 [project] 段"
    found = _VERSION_LINE.search(block.group(1))
    assert found, "pyproject.toml 的 [project] 段里没有 version"
    return found.group(1)


def _dunder_version() -> str:
    text = (ROOT / "webapi_extractor" / "__init__.py").read_text(encoding="utf-8")
    found = _DUNDER_LINE.search(text)
    assert found, "webapi_extractor/__init__.py 里没有 __version__"
    return found.group(1)


def _latest_tag() -> str | None:
    """版本号最高的 `v*` 标签；拿不到（无 git / 浅克隆 / 尚无标签）时返回 None。

    用「所有标签里最高的那个」而不是 `git describe`（只找 HEAD 可达的标签）：
    打错位置的标签同样该被发现。
    """
    try:
        result = subprocess.run(
            ["git", "tag", "--list", "v*", "--sort=-v:refname"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return names[0] if names else None


class TestVersionIsConsistent:
    def test_pyproject_matches_dunder(self):
        assert _pyproject_version() == _dunder_version(), (
            f"pyproject.toml 写的是 {_pyproject_version()}，"
            f"而 __version__ 是 {_dunder_version()} —— 只改了一处"
        )

    def test_matches_latest_git_tag(self):
        tag = _latest_tag()
        if tag is None:
            pytest.skip("拿不到 git 标签（无 git / 浅克隆 / 尚无标签）")
        assert tag.lstrip("v") == _pyproject_version(), (
            f"最新标签 {tag} 与代码版本 {_pyproject_version()} 不一致 —— "
            "打标签前先改版本号，或标签打到了错的提交上"
        )

    def test_version_looks_releasable(self):
        assert _PEP440.fullmatch(_pyproject_version()), \
            f"{_pyproject_version()} 不像一个合法的发布版本号"
