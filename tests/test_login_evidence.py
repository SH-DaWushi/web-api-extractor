# -*- coding: utf-8 -*-
"""Issue #20：登录证据不能只看「有没有会话类 Cookie」。

修复前 `_login_evidence()` 只要目标域上存在名字含 token/session/sid/auth 的
Cookie 就算已登录。而登录页**自己就会设**这类 Cookie：

    JSESSIONID / PHPSESSID / ASP.NET_SessionId / SERVERID

于是页面刚加载就被判 completed，约 6 秒后 `record.browser.close()` 关掉浏览器，
用户根本来不及登录。

修法：首次导航后拍 Cookie 基线快照，只有**相对基线新增或值变化**的凭据
Cookie 才算登录证据。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from webapi_extractor.auth import LoginManager, LoginSession, _cookie_baseline

OA_HOST = "oa.example.com"
LOGIN_URL = f"https://{OA_HOST}/login"
HOME_URL = f"https://{OA_HOST}/home"


class _FakeContext:
    def __init__(self, cookies):
        self._cookies = cookies

    async def cookies(self):
        return self._cookies


class _FakePage:
    def __init__(self, url):
        self.url = url


def _cookie(name, value, domain=OA_HOST):
    return {"name": name, "value": value, "domain": domain, "path": "/"}


def _record(cookies, baseline=None):
    """构造一个已拍过基线的登录会话。"""
    rec = LoginSession("login_test", LOGIN_URL, 300, Path("."))
    rec.context = _FakeContext(cookies)
    rec.baseline_cookies = _cookie_baseline(cookies if baseline is None else baseline)
    return rec


@pytest.fixture
def manager():
    return LoginManager(Path("."))


# 典型 Java / PHP 登录页在**登录前**就会落下的 Cookie
PRE_AUTH = [
    _cookie("JSESSIONID", "BBB222"),
    _cookie("PHPSESSID", "AAA111"),
    _cookie("SERVERID", "node-1"),
    _cookie("csrftoken", "csrf-1"),
    _cookie("_ga", "GA1.2.3"),
]


class TestPreAuthCookiesDoNotCount:
    async def test_unchanged_session_cookies_are_not_evidence(self, manager):
        """核心回归：登录页自设的会话 Cookie 不再冒充登录证据。"""
        rec = _record(PRE_AUTH)
        assert await manager._login_evidence(rec, _FakePage(LOGIN_URL), OA_HOST) is False

    async def test_page_title_irrelevant_when_cookies_unchanged(self, manager):
        rec = _record(PRE_AUTH)
        assert await manager._login_evidence(rec, _FakePage(HOME_URL), OA_HOST) is False


class TestRealLoginIsDetected:
    async def test_new_credential_cookie_counts(self, manager):
        """用户登录后服务端下发新 token → 应判定为已登录。"""
        after = PRE_AUTH + [_cookie("loginToken", "tok-123")]
        rec = _record(after, baseline=PRE_AUTH)
        assert await manager._login_evidence(rec, _FakePage(HOME_URL), OA_HOST) is True

    async def test_rotated_session_id_counts(self, manager):
        """会话固定防护会轮换 session id —— 值变化也应判为已登录。"""
        after = [_cookie("JSESSIONID", "ROTATED-999")] + PRE_AUTH[1:]
        rec = _record(after, baseline=PRE_AUTH)
        assert await manager._login_evidence(rec, _FakePage(HOME_URL), OA_HOST) is True

    async def test_off_site_cookie_ignored(self, manager):
        """第三方域的凭据类 Cookie 不算（须落在目标站）。"""
        after = [_cookie("authToken", "x", domain="idp.other.com")]
        rec = _record(after, baseline=[])
        assert await manager._login_evidence(rec, _FakePage(HOME_URL), OA_HOST) is False

    async def test_evidence_requires_being_on_target_site(self, manager):
        """已拿到新 Cookie 但当前仍在第三方 IdP 页 → 还不算完成。"""
        after = PRE_AUTH + [_cookie("loginToken", "tok-1")]
        rec = _record(after, baseline=PRE_AUTH)
        assert await manager._login_evidence(rec, _FakePage("https://idp.other.com/sso"), OA_HOST) is False


class TestBaselineEdgeCases:
    async def test_empty_baseline_falls_back_to_old_behaviour(self, manager):
        """尚未拍到基线时不得误伤正常流程（退回旧判定）。"""
        rec = LoginSession("login_test", LOGIN_URL, 300, Path("."))
        rec.context = _FakeContext(PRE_AUTH)
        rec.baseline_cookies = {}
        assert await manager._login_evidence(rec, _FakePage(HOME_URL), OA_HOST) is True

    def test_baseline_keys_include_domain_and_path(self):
        cookies = [_cookie("JSESSIONID", "v", domain="a.example.com"),
                   _cookie("JSESSIONID", "v2", domain="b.example.com")]
        base = _cookie_baseline(cookies)
        assert len(base) == 2, "同名不同域的 Cookie 不能互相覆盖"
