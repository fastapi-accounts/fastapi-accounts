import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Sequence
from typing import Any

WEAK_SECRET_PLACEHOLDERS = {
    "change-me-in-production-0123456789",
    "secret",
    "12345678901234567890123456789012",
    "abcdefghijklmnopqrstuvwxyz123456",
    "your-secret-key-here-must-be-32-bytes",
}


def derive_key(secret: str, domain: bytes) -> bytes:
    """Derive domain-separated cryptographic key using HMAC-SHA256."""
    return hmac.new(secret.encode("utf-8"), domain, hashlib.sha256).digest()


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure random URL-safe token representing 256+ bits of entropy."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Hash a token using SHA-256 for secure database lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TimedTokenSigner:
    """Generates and verifies cryptographically signed tokens with expiration and secret rotation."""

    def __init__(
        self,
        secret_keys: str | Sequence[str],
        domain: bytes = b"fastapi-accounts-auth-token",
    ):
        if isinstance(secret_keys, str):
            keys = [secret_keys]
        else:
            keys = list(secret_keys)

        if not keys:
            raise ValueError("TimedTokenSigner requires at least one secret key.")

        for k in keys:
            if not isinstance(k, str) or len(k) < 32:
                raise ValueError(
                    "Each secret key must be a non-empty string of at least 32 characters."
                )
            if k.lower() in WEAK_SECRET_PLACEHOLDERS:
                raise ValueError(
                    f"Insecure placeholder secret key '{k[:16]}...' is rejected. "
                    "Generate a cryptographically secure key with `secrets.token_urlsafe(32)`."
                )

        self._keys = keys
        self._domain = domain
        self._derived_keys = [derive_key(k, domain) for k in keys]
        self._raw_keys = [k.encode("utf-8") for k in keys]

    def create_token(
        self, payload: dict[str, Any], max_age_seconds: int = 86400
    ) -> str:
        """Create a timed signed token containing payload data using primary key (keys[0])."""
        data = {
            **payload,
            "exp": int(time.time()) + max_age_seconds,
            "nonce": secrets.token_hex(8),
        }
        json_bytes = json.dumps(data, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        payload_b64 = base64.urlsafe_b64encode(json_bytes).decode("utf-8").rstrip("=")

        primary_derived_key = self._derived_keys[0]
        signature = hmac.new(
            primary_derived_key, payload_b64.encode("utf-8"), hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

        return f"{payload_b64}.{sig_b64}"

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """Verify the signature across all active keys and check expiration. Returns payload or None."""
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None

            payload_b64, sig_b64 = parts

            rem = len(sig_b64) % 4
            sig_padded = sig_b64 + ("=" * (4 - rem) if rem else "")
            actual_sig = base64.urlsafe_b64decode(sig_padded.encode("utf-8"))

            payload_bytes = payload_b64.encode("utf-8")

            # Try derived keys first (for current/rotated keys)
            matched = False
            for d_key in self._derived_keys:
                expected_sig = hmac.new(d_key, payload_bytes, hashlib.sha256).digest()
                if hmac.compare_digest(expected_sig, actual_sig):
                    matched = True
                    break

            # Fallback to raw keys for legacy token compatibility
            if not matched:
                for r_key in self._raw_keys:
                    expected_sig = hmac.new(
                        r_key, payload_bytes, hashlib.sha256
                    ).digest()
                    if hmac.compare_digest(expected_sig, actual_sig):
                        matched = True
                        break

            if not matched:
                return None

            # Decode payload
            payload_rem = len(payload_b64) % 4
            payload_padded = payload_b64 + (
                "=" * (4 - payload_rem) if payload_rem else ""
            )
            data = json.loads(
                base64.urlsafe_b64decode(payload_padded.encode("utf-8")).decode("utf-8")
            )

            # Check expiration
            if data.get("exp", 0) < time.time():
                return None

            return data
        except (
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            return None
