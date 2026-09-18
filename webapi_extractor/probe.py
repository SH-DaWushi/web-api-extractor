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


def _probe_timeout_ms() -> int:
    try:
        return int(os.environ.get("WEB_API_EXTRACTOR_PROBE_TIMEOUT", DEFAULT_TIMEOUT_MS))
    except ValueError:
        return DEFAULT_TIMEOUT_MS


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
    }
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        result["reason"] = "playwright is not installed"
        return result

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            try:
                # domcontentloaded: networkidle almost never fires on heavy SPAs.
                await page.goto(url, wait_until="domcontentloaded", timeout=_probe_timeout_ms())
                # Give the SPA a moment to render its shell, then settle best-effort.
                try:
                    await page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass
            except Exception:
                result["reason"] = "page load timed out; confidence reduced"
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
            await browser.close()
    except Exception as exc:
        result["reason"] = f"probe failed: {type(exc).__name__}"
        result["confidence"] = 0.3
    return result
