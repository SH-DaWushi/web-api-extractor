"""Conservative detection of encrypted login payloads and JS crypto hints."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any


CRYPTO_HINTS = re.compile(r"CryptoJS|JSEncrypt|sm2|sm4|encrypt|RSA|AES", re.I)


def _looks_ciphertext(value: str) -> bool:
    if len(value) < 32:
        return False
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
        try:
            decoded = base64.b64decode(value + "===", validate=False)
            return len(decoded) >= 16
        except Exception:
            return False
    return bool(re.fullmatch(r"[0-9a-f]{32,}", value, re.I))


def detect_crypto(session_dir: Path, analysis: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for candidate in analysis.get("auth_metadata", {}).get("auth_candidates", []):
        request_id = candidate.get("request_id")
        for line in (session_dir / "capture.jsonl").read_text(encoding="utf-8").splitlines() if (session_dir / "capture.jsonl").exists() else []:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("requestId") != request_id or event.get("type") != "request":
                continue
            body = event.get("postData")
            try:
                parsed = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed = body
            encrypted_fields = [key for key, value in parsed.items() if isinstance(value, str) and _looks_ciphertext(value)] if isinstance(parsed, dict) else []
            if encrypted_fields or isinstance(parsed, str) and _looks_ciphertext(parsed):
                findings.append({"endpoint": event.get("url"), "encrypted_fields": encrypted_fields, "ciphertext": True})
    scripts = list((session_dir / "scripts").glob("*.js")) if (session_dir / "scripts").exists() else []
    hints = [str(path.relative_to(session_dir)) for path in scripts if CRYPTO_HINTS.search(path.read_text(encoding="utf-8", errors="ignore"))]
    return {"found": bool(findings), "strategy": "L1_native" if findings and hints else "L0_manual" if findings else "none", "crypto_findings": findings, "script_hints": hints, "scripts_unavailable": bool(findings and not scripts)}