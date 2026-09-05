import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Optional


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure random URL-safe token."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Hash a token using SHA-256 for secure database lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TimedTokenSigner:
    """Generates and verifies cryptographically signed tokens with expiration."""

    def __init__(self, secret_key: str):
        self._secret = secret_key.encode("utf-8")

    def create_token(self, payload: dict[str, Any], max_age_seconds: int = 86400) -> str:
        """Create a timed signed token containing payload data."""
        data = {
            **payload,
            "exp": int(time.time()) + max_age_seconds,
            "nonce": secrets.token_hex(8),
        }
        json_bytes = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(json_bytes).decode("utf-8").rstrip("=")
        
        signature = hmac.new(self._secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
        
        return f"{payload_b64}.{sig_b64}"

    def verify_token(self, token: str) -> Optional[dict[str, Any]]:
        """Verify the signature and expiration of a timed token. Returns payload or None."""
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            
            payload_b64, sig_b64 = parts
            
            # Recompute signature
            expected_sig = hmac.new(self._secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
            
            # Add padding back for base64 decoding
            rem = len(sig_b64) % 4
            sig_padded = sig_b64 + ("=" * (4 - rem) if rem else "")
            actual_sig = base64.urlsafe_b64decode(sig_padded.encode("utf-8"))
            
            if not hmac.compare_digest(expected_sig, actual_sig):
                return None
            
            # Decode payload
            payload_rem = len(payload_b64) % 4
            payload_padded = payload_b64 + ("=" * (4 - payload_rem) if payload_rem else "")
            data = json.loads(base64.urlsafe_b64decode(payload_padded.encode("utf-8")).decode("utf-8"))
            
            # Check expiration
            if data.get("exp", 0) < time.time():
                return None
            
            return data
        except Exception:
            return None
