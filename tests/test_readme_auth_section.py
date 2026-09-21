# -*- coding: utf-8 -*-
"""README「鉴权说明」必须如实反映 Cookie 鉴权。

纯 Cookie 鉴权站点的 registry 里 `hosts[host].scheme` 为 **None**（凭据走
`cookie_names` + 运行时 `.env` 的 `<PREFIX>_COOKIE_<HOST>`），而端点
`auth_required` 为 true。若 README 直接按 `scheme or '无（公开接口）'` 渲染，
就会把**需要登录态**的站点写成公开接口 —— 实测某 OA 系统的**全部端点**都是如此，
`.env.example` 写着要填 Cookie，README 却说「无（公开接口）」，
两份文档互相矛盾，未来对接方会据此漏配 Cookie 而全部 401。
"""
from __future__ import annotations

from webapi_extractor.generator import render_server

COOKIE_HOST = "oa.example.com"


def _registry(hosts: dict, auth_required: bool = True) -> dict:
    return {
        "site_name": "portal",
        "registry_version": 1,
        "hosts": hosts,
        "endpoints": [{
            "tool_name": "get_api_system_status",
            "method": "GET",
            "host": COOKIE_HOST,
            "path": "/api/system/status",
            "auth_required": auth_required,
            "status": "active",
        }],
    }


def _readme(registry: dict) -> str:
    return render_server(registry)["README.md"]


class TestCookieOnlyHost:
    """scheme 为空但配了凭据 Cookie —— 是 Cookie 鉴权，不是公开接口。"""

    HOSTS = {COOKIE_HOST: {"scheme": None,
                           "cookie_names": ["SERVERID", "JSESSIONID", "loginToken"]}}

    def test_not_reported_as_public(self):
        readme = _readme(_registry(self.HOSTS))
        assert "无（公开接口）" not in readme

    def test_reported_as_cookie(self):
        readme = _readme(_registry(self.HOSTS))
        assert f"- `{COOKIE_HOST}`：Cookie（" in readme

    def test_lists_observed_cookie_names(self):
        """只列凭据类 Cookie：`SERVERID` 不含凭据特征，被 is_credential_cookie 过滤。"""
        readme = _readme(_registry(self.HOSTS))
        assert "JSESSIONID" in readme and "loginToken" in readme

    def test_points_at_cookie_env_var(self):
        """要给出可操作配置项，而不是只描述现象（具体键名见 .env.example）。"""
        readme = _readme(_registry(self.HOSTS))
        assert "PORTAL_COOKIE_" in readme
        assert "auth_states/" in readme

    def test_no_bogus_token_line(self):
        """纯 Cookie 站点不应让人去填 token（.env.example 里根本没这项）。"""
        readme = _readme(_registry(self.HOSTS))
        assert "`PORTAL_TOKEN`" not in readme


class TestTrulyPublicHost:
    def test_still_reported_as_public(self):
        hosts = {COOKIE_HOST: {"scheme": None, "cookie_names": []}}
        readme = _readme(_registry(hosts, auth_required=False))
        assert "无（公开接口）" in readme
        assert "`PORTAL_TOKEN`" in readme


class TestAuthRequiredWithoutSchemeOrCookie:
    def test_flags_for_manual_review(self):
        """既无 scheme 又无 Cookie 却要求鉴权：不能谎称公开，要提示人工核对。"""
        hosts = {COOKIE_HOST: {"scheme": None, "cookie_names": []}}
        readme = _readme(_registry(hosts, auth_required=True))
        assert "无（公开接口）" not in readme
        assert "需要鉴权" in readme


class TestBearerHost:
    def test_bearer_keeps_token_line(self):
        hosts = {"api.example.com": {"scheme": "Bearer", "cookie_names": []}}
        registry = _registry(hosts)
        registry["endpoints"][0]["host"] = "api.example.com"
        readme = _readme(registry)
        assert "- `api.example.com`：Bearer" in readme
        assert "`PORTAL_TOKEN`" in readme
