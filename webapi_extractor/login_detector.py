"""Heuristic login success detection for browser-based auth flows."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def detect_login_success(
    request_urls: Sequence[str] | None = None,
    observed_headers: Mapping[str, Any] | None = None,
    storage_state: Mapping[str, Any] | None = None,
    session_storage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a conservative completion verdict for interactive login flows.

    The detector is intentionally heuristic: it does not claim success on page-content
    alone, but it does recognize the common evidence of a completed auth session such as
    auth headers, session cookies, or a redirect to an authenticated landing page.
    """
    urls = [str(url) for url in (request_urls or [])]
    headers = dict(observed_headers or {})
    storage = dict(storage_state or {})
    session = dict(session_storage or {})

    lower_url_text = " ".join(url.lower() for url in urls)
    has_auth_header = any(
        name.lower() in {"authorization", "x-auth-token"}
        and str(headers.get(name, "")).strip() not in {"", "Bearer auto-detected"}
        for name in headers
    )
    cookie_value = "" if not storage.get("cookies") else str(storage["cookies"])
    session_values = " ".join(str(value).lower() for value in session.values())
    tokenish = any(key.lower().find("token") >= 0 or key.lower().find("session") >= 0 for key in session)
    has_session_cookie = "session" in cookie_value.lower() or "token" in cookie_value.lower() or "sid=" in cookie_value.lower()
    auth_redirect = any(marker in lower_url_text for marker in ("/dashboard", "/home", "/profile", "/account", "/callback", "/oauth"))

    evidence: list[str] = []
    if has_auth_header:
        evidence.append("authorization header observed")
    if has_session_cookie:
        evidence.append("session cookie observed")
    if tokenish:
        evidence.append("sessionStorage token observed")

    # Conservative verdict: a URL redirect alone never proves login (the login
    # page itself often matches /account|/oauth). Credential evidence required.
    completed = bool(has_auth_header or has_session_cookie or tokenish)
    return {
        "status": "completed" if completed else "waiting",
        "auth_ready": completed,
        "evidence": evidence,
        "details": {
            "request_urls": urls,
            "auth_header_seen": has_auth_header,
            "session_cookie_seen": has_session_cookie,
            "token_in_session_storage": tokenish,
            "authenticated_redirect_seen": auth_redirect,
        },
    }
