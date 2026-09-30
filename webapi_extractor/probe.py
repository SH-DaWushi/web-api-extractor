# -*- coding: utf-8 -*-
"""Best-effort browser-based authentication mode probing.

Designed for heavy SPA sites: uses ``domcontentloaded`` instead of ``networkidle``
(SPA pages rarely go idle within any timeout) and probes for *login entry points*
(password inputs, login links, OAuth/SSO markers), not just a password form on
the landing page.
"""
from __future__ import annotations

import os
from urllib.parse import urljoin

DEFAULT_TIMEOUT_MS = 15000
LOGIN_LINK_TEXTS = ("login", "log in", "sign in", "signin", "登录", "登陆", "登入")
LOGIN_HREF_MARKERS = ("login", "signin", "sign-in", "passport", "sso", "oauth", "account")

# TLS / 证书类失败在 Playwright 异常文本里的特征。内网设备自签名证书是常态：goto 抛出的
# ``net::ERR_CERT_AUTHORITY_INVALID`` / ``ERR_SSL_*`` / ``ssl handshake failed`` 若不被识别，
# 就会被降级成「page load timed out」——报错方向完全指向「页面慢 / 网络差」，实测把排障引偏
# 了一整轮（隔离变量后才看出是证书：放开校验即 ``title='NetScaler Login'``）。命中即给出 TLS
# 结论与处置建议；认不出就**不**声称是 TLS（宁可不猜，也不误导）。
TLS_ERROR_MARKERS = (
    "err_cert", "cert_authority_invalid", "certificate", "self-signed", "self signed",
    "err_ssl", "ssl_error", "ssl handshake", "ssl: ", "handshake failed",
    "tls handshake", "unable to verify", "cert_verify",
)


def _probe_timeout_ms() -> int:
    try:
        return int(os.environ.get("WEB_API_EXTRACTOR_PROBE_TIMEOUT", DEFAULT_TIMEOUT_MS))
    except ValueError:
        return DEFAULT_TIMEOUT_MS


def _classify_load_failure(exc: BaseException) -> tuple[bool, str]:
    """把页面加载失败分类成 (是否 TLS/证书相关, 给人看的处置建议)。

    只在异常文本命中 :data:`TLS_ERROR_MARKERS` 时才认作 TLS —— 认不出就按普通加载失败
    （超时/网络）给建议，绝不硬把超时说成证书问题。
    """
    text = f"{type(exc).__name__}: {exc}".lower()
    if any(marker in text for marker in TLS_ERROR_MARKERS):
        return True, (
            "page load was blocked by a TLS/certificate error "
            "(a self-signed certificate on an internal device is common). "
            "This is not a slow page or a network problem: the browser has to accept the "
            "certificate — use open_browser_login so the user can accept/trust it and log in "
            "interactively. 页面加载被 TLS/证书校验挡住（内网设备自签名证书是常态），"
            "不是页面慢或网络问题：需改用 open_browser_login，"
            "由用户在真实浏览器里接受证书后交互式登录。"
        )
    return False, (
        "the page did not finish loading within the timeout "
        "(the page itself may be slow, or the network is restricted/proxied). Retry with a "
        "larger WEB_API_EXTRACTOR_PROBE_TIMEOUT, or log in interactively via "
        "open_browser_login if the site needs authentication. "
        "页面在超时时间内未完成加载（可能页面慢、网络受限或被代理拦截）；"
        "可调大 WEB_API_EXTRACTOR_PROBE_TIMEOUT 后重试，"
        "或直接改用 open_browser_login 交互式登录。"
    )


async def probe_login(url: str) -> dict:
    """Inspect a rendered page and return a deliberately conservative suggestion."""
    result = {
        "url": url,
        "auth_mode": "none",
        "login_url": None,
        "form_fields": [],
        "indicators": {
            "has_captcha": False,
            "has_mfa": False,
            "has_oauth_redirect": False,
            "has_sso": False,
            "has_login_entry": False,
        },
        "confidence": 0.3,
        # 失败分类：tls_error 为 True 时 hint 指向证书处置，reason 也不再读作「超时」。
        # 认不出原因时保持 False + 空 hint，不声称 TLS。
        "tls_error": False,
        "hint": "",
    }
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        result["reason"] = "playwright is not installed"
        return result

    browser = None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            # 内网设备自签名证书是常态。不放开校验时 goto 抛 net::ERR_CERT_AUTHORITY_INVALID，
            # 而探测会把它降级成「page load timed out; confidence reduced」+ auth_mode=none ——
            # 报错完全不指向 TLS，隔离变量才能看出是证书（实测：放开后 title='NetScaler Login'）。
            page = await browser.new_page(ignore_https_errors=True)
            try:
                # domcontentloaded: networkidle almost never fires on heavy SPAs.
                await page.goto(url, wait_until="domcontentloaded", timeout=_probe_timeout_ms())
                # Give the SPA a moment to render its shell, then settle best-effort.
                try:
                    await page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass
            except Exception as exc:
                # 不再把所有加载失败一律写成「超时」：先分类，再决定 reason/hint。
                tls_error, hint = _classify_load_failure(exc)
                result["tls_error"] = tls_error
                result["hint"] = hint
                result["reason"] = ("page load failed: TLS/certificate error"
                                    if tls_error
                                    else "page load timed out; confidence reduced")
            password = page.locator('input[type="password"]')
            indicators = result["indicators"]
            try:
                if await password.count():
                    # 1) Direct password field on the landing page.
                    fields = await page.locator("input").evaluate_all(
                        "els => els.map(el => el.name || el.type).filter(Boolean)"
                    )
                    result["form_fields"] = fields
                    forms = page.locator("form")
                    action = await forms.first.get_attribute("action") if await forms.count() else None
                    result["login_url"] = urljoin(url, action or url)
                    result["auth_mode"] = "interactive"
                else:
                    # 2) SPA login entry: login link/button leading to a login route
                    #    or OAuth popup — no password field on the landing page.
                    hrefs = await page.locator("a[href]").evaluate_all(
                        "els => els.map(el => el.getAttribute('href')).filter(Boolean)"
                    )
                    login_hrefs = [h for h in hrefs if any(m in str(h).lower() for m in LOGIN_HREF_MARKERS)]
                    if login_hrefs:
                        result["login_url"] = urljoin(url, login_hrefs[0])
                        result["auth_mode"] = "interactive"
                        indicators["has_login_entry"] = True
                    else:
                        texts = await page.locator("a, button").all_inner_texts()
                        if any(any(t.lower() == text or t.lower().startswith(text) for text in LOGIN_LINK_TEXTS) for t in texts):
                            result["auth_mode"] = "interactive"
                            indicators["has_login_entry"] = True
                text = (await page.locator("body").inner_text()).lower()
                links = " ".join(await page.locator("a").all_inner_texts()).lower()
                combined = f"{text} {links}"
                indicators["has_captcha"] = any(term in combined for term in ("captcha", "recaptcha", "hcaptcha", "极验"))
                indicators["has_mfa"] = any(term in combined for term in ("mfa", "two-factor", "verification code", "验证码"))
                indicators["has_oauth_redirect"] = any(term in combined for term in ("oauth", "authorize"))
                indicators["has_sso"] = any(term in combined for term in ("sso", "saml", "cas"))
                if result["auth_mode"] == "interactive":
                    result["confidence"] = 0.75 if any(indicators.values()) else 0.6
                else:
                    # No password field and no login entry found → probably public.
                    result["confidence"] = 0.5
            except Exception:
                result["reason"] = "dom inspection failed; confidence reduced"
    except Exception as exc:
        result["reason"] = f"probe failed: {type(exc).__name__}"
        result["confidence"] = 0.3
    finally:
        # 浏览器必须**无条件**关闭：locator / evaluate / new_page 任一抛出异常都会跳到上面的
        # 处理器，而 close() 原先只在 try 末尾执行，于是一次异常就漏掉一个 Chromium 进程
        # （连续探测累积成僵尸进程）。这里放进 finally，且不让关闭自身的失败覆盖原始报错。
        if browser is not None:
            try:
                await browser.close()
            except Exception:
                pass
    return result
