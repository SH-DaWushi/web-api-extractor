# -*- coding: utf-8 -*-
"""Issue #9：可注册域解析与 Cookie 域匹配。

修复前用「取末两段」当站点区域，对 `crm.example.com.cn` 会得到公共后缀
`com.cn`，导致任一 `.com.cn` 下的第三方域都被误判为目标站。
"""
from __future__ import annotations

import pytest

from webapi_extractor.domain import domain_matches, registrable_domain, same_site


class TestRegistrableDomain:
    @pytest.mark.parametrize("host,expected", [
        # 核心修复：ccTLD 二级后缀必须取三段
        ("crm.example.com.cn", "example.com.cn"),
        ("idp.example.com.cn", "example.com.cn"),
        ("a.b.c.example.com.cn", "example.com.cn"),
        ("deep.sub.example.co.uk", "example.co.uk"),
        ("x.y.z.example.co.jp", "example.co.jp"),
        ("site.example.com.au", "example.com.au"),
        ("foo.example.co.kr", "example.co.kr"),
        # 普通域名取两段
        ("www.example.com", "example.com"),
        ("api.example.org", "example.org"),
        ("example.com", "example.com"),
        # 边界
        ("localhost", "localhost"),
        ("192.168.1.1", "192.168.1.1"),
        ("", ""),
        # 大小写与前导点
        ("WWW.Example.COM", "example.com"),
        ("crm.example.com.cn.", "example.com.cn"),
        # 多段公共后缀
        ("user.github.io", "user.github.io"),
        ("myapp.azurewebsites.net", "myapp.azurewebsites.net"),
    ])
    def test_registrable(self, host, expected):
        assert registrable_domain(host) == expected

    def test_never_returns_public_suffix(self):
        """可注册域绝不能是公共后缀本身。"""
        for host in ("crm.example.com.cn", "a.example.co.uk", "b.example.com.au"):
            result = registrable_domain(host)
            assert result not in ("com.cn", "co.uk", "com.au")
            assert "." in result


class TestDomainMatches:
    """RFC6265 域匹配。"""

    def test_exact_host_only(self):
        assert domain_matches("crm.example.com", "crm.example.com")

    def test_host_only_is_not_subdomain_match(self):
        # 无前导点 = host-only，不应匹配子域
        assert not domain_matches("example.com", "crm.example.com")

    def test_leading_dot_matches_subdomains(self):
        assert domain_matches(".example.com", "crm.example.com")
        assert domain_matches(".example.com", "a.b.example.com")
        assert domain_matches(".example.com", "example.com")

    def test_rejects_non_matching(self):
        assert not domain_matches(".example.com", "evil.com")
        # 关键：后缀相似但非子域
        assert not domain_matches(".example.com", "notexample.com")

    def test_case_insensitive(self):
        assert domain_matches(".Example.COM", "CRM.example.com")

    def test_empty(self):
        assert not domain_matches("", "example.com")
        assert not domain_matches(".example.com", "")


class TestSameSite:
    def test_same_registrable_domain(self):
        assert same_site(".example.com.cn", "crm.example.com.cn")
        assert same_site("idp.example.com.cn", "crm.example.com.cn")
        assert same_site(".example.com", "crm.example.com")

    def test_different_organization_rejected(self):
        """核心修复：同为 .com.cn 但不同组织的域必须排除。

        修复前 `"com.cn" in "evil.com.cn"` 为 True，会被误判为目标站。
        """
        assert not same_site("evil.com.cn", "crm.example.com.cn")
        assert not same_site("attacker.co.uk", "shop.example.co.uk")
        assert not same_site("other.com", "example.com")

    def test_subdomain_is_same_site(self):
        assert same_site("a.b.example.com", "example.com")
        assert same_site("example.com", "a.b.example.com")

    def test_empty(self):
        assert not same_site("", "example.com")
        assert not same_site(".example.com", "")
