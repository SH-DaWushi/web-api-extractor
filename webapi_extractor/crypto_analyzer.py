"""Conservative detection of encrypted login payloads and JS crypto hints."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any


CRYPTO_HINTS = re.compile(r"CryptoJS|JSEncrypt|sm2|sm4|encrypt|RSA|AES", re.I)
# B-2: URL 查询参数里的加密信号——不是密文，但明确指出「密码需加密传输」。
ENCRYPTION_QUERY_KEYS = ("encrypt", "sign", "signature", "enc_type", "encrypt_type")
# JS 源码里的 PEM 公钥（换行可能是真实换行或字面 \n 转义）。
PEM_RE = re.compile(
    r"-----BEGIN PUBLIC KEY-----(?:\\n|\s)*(?P<body>[A-Za-z0-9+/=\\n\s]+?)(?:\\n|\s)*-----END PUBLIC KEY-----")


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


def value_shape(value: str) -> str:
    """B-3 配套：值的形态分类，供脱敏边车与密文判定共用。"""
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
        try:
            base64.b64decode(value + "===", validate=False)
            return "base64"
        except Exception:
            pass
    if re.fullmatch(r"[0-9a-f]+", value, re.I):
        return "hex"
    return "plain"


def normalize_pem(raw: str) -> str:
    """把 JS 源码里的 PEM 还原成标准格式（源码换行可能是真实换行或字面 \\n）。"""
    body = raw.replace("\\n", "").replace("\r", "").replace("\n", "").strip()
    body = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----"


def find_public_key(session_dir: Path | None) -> str | None:
    """在抓包的前端脚本里搜索 PEM 公钥块。"""
    scripts_dir = Path(session_dir) / "scripts" if session_dir else None
    if not scripts_dir or not scripts_dir.is_dir():
        return None
    for js in sorted(scripts_dir.glob("*")):
        try:
            text = js.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = PEM_RE.search(text)
        if m:
            return normalize_pem(m.group("body"))
    return None


def detect_password_encryption(session_dir: Path | None, login: dict[str, Any]) -> dict[str, Any] | None:
    """B-2：判断登录接口是否有前端加密。

    判据（按可靠性）：登录接口带 `encrypt` 类查询参数（版本号）→
    从前端 JS 提取 PEM 公钥（当前识别 RSA-OAEP/SHA-256 策略）。
    """
    query = login.get("query_params") or {}
    version = query.get("encrypt")
    if not version:
        return None
    public_key = find_public_key(session_dir)
    return {"scheme": "rsa-oaep-sha256", "version": str(version), "public_key": public_key}


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
            # B-3 边车：优先用脱敏时保留的形态元数据（len/shape）判定密文。
            shape_meta = event.get("redaction_meta") or {}
            for path, meta in shape_meta.items():
                if isinstance(meta, dict) and meta.get("shape") in ("base64", "hex") and meta.get("len", 0) >= 128:
                    findings.append({"endpoint": event.get("url"), "redacted_field": path,
                                     "shape": meta.get("shape"), "len": meta.get("len"), "ciphertext": True})
            try:
                parsed = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed = body
            encrypted_fields = [key for key, value in parsed.items() if isinstance(value, str) and _looks_ciphertext(value)] if isinstance(parsed, dict) else []
            if encrypted_fields or isinstance(parsed, str) and _looks_ciphertext(parsed):
                findings.append({"endpoint": event.get("url"), "encrypted_fields": encrypted_fields, "ciphertext": True})
    # B-2：URL 查询参数加密信号（如 encrypt=2）。
    query_signal = []
    for ep in analysis.get("endpoints", []):
        for key in (ep.get("query_params") or {}):
            if key.lower() in ENCRYPTION_QUERY_KEYS:
                query_signal.append({"endpoint": f"{ep['method']} {ep['host']}{ep['path']}", "param": key})
                break
    scripts = list((session_dir / "scripts").glob("*.js")) if (session_dir / "scripts").exists() else []
    hints = [str(path.relative_to(session_dir)) for path in scripts if CRYPTO_HINTS.search(path.read_text(encoding="utf-8", errors="ignore"))]
    found = bool(findings or query_signal)
    return {"found": found,
            "strategy": "L1_native" if (findings or query_signal) and hints else "L0_manual" if found else "none",
            "crypto_findings": findings, "query_encryption_signals": query_signal,
            "script_hints": hints, "scripts_unavailable": bool(found and not scripts)}