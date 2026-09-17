"""Best-effort browser-based authentication mode probing."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse


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
                await page.goto(url, wait_until="networkidle", timeout=8000)
            except Exception:
                result["reason"] = "page load timed out; confidence reduced"
            password = page.locator('input[type="password"]')
            if await password.count():
                fields = await page.locator("input").evaluate_all(
                    "els => els.map(el => el.name || el.type).filter(Boolean)"
                )
                result["form_fields"] = fields
                forms = page.locator("form")
                action = await forms.first.get_attribute("action") if await forms.count() else None
                result["login_url"] = urljoin(url, action or url)
                text = (await page.locator("body").inner_text()).lower()
                links = " ".join(await page.locator("a").all_inner_texts()).lower()
                combined = f"{text} {links}"
                indicators = result["indicators"]
                indicators["has_captcha"] = any(term in combined for term in ("captcha", "recaptcha", "hcaptcha", "极验"))
                indicators["has_mfa"] = any(term in combined for term in ("mfa", "two-factor", "verification code", "验证码"))
                indicators["has_oauth_redirect"] = any(term in combined for term in ("oauth", "authorize"))
                indicators["has_sso"] = any(term in combined for term in ("sso", "saml", "cas"))
                same_origin = urlparse(result["login_url"]).netloc == urlparse(url).netloc
                risky = any(indicators.values())
                result["auth_mode"] = "interactive" if risky or not same_origin else "form"
                result["confidence"] = 0.6 if result["auth_mode"] == "form" else 0.9
            await browser.close()
    except Exception as exc:
        result["reason"] = f"probe failed: {type(exc).__name__}"
        result["confidence"] = 0.3
    return result