from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from fastapi import Request


class CSRFContext(str, Enum):
    PRE_AUTH = "pre_auth"
    SESSION_BOUND = "session_bound"
    DUAL_MODE = "dual_mode"
    LOGOUT = "logout"


def _sign_payload(payload: dict[str, Any], signing_key: bytes) -> str:
    json_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    payload_b64 = base64.urlsafe_b64encode(json_bytes).decode("utf-8").rstrip("=")
    sig = hmac.new(signing_key, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    return f"{payload_b64}.{sig_b64}"


def _verify_and_decode(token: str, signing_key: bytes) -> dict[str, Any] | None:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts

        rem = len(sig_b64) % 4
        sig_padded = sig_b64 + ("=" * (4 - rem) if rem else "")
        actual_sig = base64.urlsafe_b64decode(sig_padded.encode("utf-8"))

        expected_sig = hmac.new(
            signing_key, payload_b64.encode("utf-8"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        p_rem = len(payload_b64) % 4
        p_padded = payload_b64 + ("=" * (4 - p_rem) if p_rem else "")
        data = json.loads(
            base64.urlsafe_b64decode(p_padded.encode("utf-8")).decode("utf-8")
        )
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


def create_pre_auth_csrf_token(signing_key: bytes, max_age_seconds: int = 3600) -> str:
    """Generate a signed pre-authentication CSRF token."""
    payload = {
        "type": "pre_auth",
        "sid": None,
        "exp": int(time.time()) + max_age_seconds,
        "nonce": secrets.token_hex(8),
    }
    return _sign_payload(payload, signing_key)


def create_session_csrf_token(
    session_id: str, signing_key: bytes, max_age_seconds: int = 86400 * 14
) -> str:
    """Generate a signed CSRF token bound to an authenticated session."""
    payload = {
        "type": "session",
        "sid": session_id,
        "exp": int(time.time()) + max_age_seconds,
        "nonce": secrets.token_hex(8),
    }
    return _sign_payload(payload, signing_key)


def validate_csrf_token(
    cookie_token: str | None,
    header_token: str | None,
    current_session_id: str | None,
    signing_key: bytes,
    expected_context: CSRFContext = CSRFContext.DUAL_MODE,
) -> bool:
    """Validate double-submit CSRF tokens and enforce strict route context."""
    if not cookie_token or not header_token:
        return False

    if not hmac.compare_digest(cookie_token.encode("utf-8"), header_token.encode("utf-8")):
        return False

    payload = _verify_and_decode(cookie_token, signing_key)
    if not payload:
        return False

    token_type = payload.get("type")
    token_sid = payload.get("sid")

    if expected_context == CSRFContext.PRE_AUTH:
        return token_type == "pre_auth" and token_sid is None

    if expected_context == CSRFContext.SESSION_BOUND:
        return (
            token_type == "session"
            and current_session_id is not None
            and token_sid == current_session_id
        )

    if expected_context == CSRFContext.DUAL_MODE:
        if current_session_id is not None:
            return token_type == "session" and token_sid == current_session_id
        else:
            return token_type == "pre_auth" and token_sid is None

    if expected_context == CSRFContext.LOGOUT:
        if current_session_id is not None:
            return token_type == "session" and token_sid == current_session_id
        else:
            return token_type == "pre_auth" and token_sid is None

    return False


def validate_origin_header(
    request: Request, allowed_origins: list[str] | None = None
) -> bool:
    """Validate request Origin or Referer against server base_url and allowed_origins."""
    origin = request.headers.get("origin")
    if not origin:
        referer = request.headers.get("referer")
        if referer:
            try:
                parsed_ref = urlparse(referer)
                if parsed_ref.scheme and parsed_ref.netloc:
                    origin = f"{parsed_ref.scheme}://{parsed_ref.netloc}".lower()
            except Exception:
                origin = None

    # Fail closed if both Origin and Referer are absent on mutating requests
    if not origin:
        return False

    origin_norm = origin.strip().lower().rstrip("/")

    # Construct server expected origin from request
    server_base = str(request.base_url).strip().lower().rstrip("/")
    try:
        parsed_base = urlparse(server_base)
        server_origin = f"{parsed_base.scheme}://{parsed_base.netloc}".lower().rstrip(
            "/"
        )
    except Exception:
        server_origin = server_base

    trusted = {server_origin}
    if allowed_origins:
        for ao in allowed_origins:
            ao_norm = ao.strip().lower().rstrip("/")
            try:
                parsed_ao = urlparse(ao_norm)
                if parsed_ao.scheme and parsed_ao.netloc:
                    trusted.add(
                        f"{parsed_ao.scheme}://{parsed_ao.netloc}".lower().rstrip("/")
                    )
                else:
                    trusted.add(ao_norm)
            except Exception:
                trusted.add(ao_norm)

    return origin_norm in trusted
