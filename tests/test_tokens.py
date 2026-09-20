import pytest

from fastapi_accounts.security.tokens import (
    TimedTokenSigner,
    generate_secure_token,
    hash_token,
)

KEY_A = "primary-secret-key-at-least-32-chars-long-001"
KEY_B = "secondary-rotated-key-at-least-32-chars-002"
KEY_C = "third-secret-key-at-least-32-characters-003"


def test_secure_token_and_hash():
    token = generate_secure_token(32)
    assert len(token) > 30

    h1 = hash_token(token)
    h2 = hash_token(token)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex length


def test_timed_token_signer_valid():
    signer = TimedTokenSigner(KEY_A)
    token = signer.create_token(
        {"email": "test@example.com", "action": "verify_email"}, max_age_seconds=60
    )

    payload = signer.verify_token(token)
    assert payload is not None
    assert payload["email"] == "test@example.com"
    assert payload["action"] == "verify_email"


def test_timed_token_signer_tampered():
    signer = TimedTokenSigner(KEY_A)
    token = signer.create_token({"email": "test@example.com"})

    tampered = token[:-4] + "abcd"
    assert signer.verify_token(tampered) is None


def test_timed_token_signer_expired():
    signer = TimedTokenSigner(KEY_A)
    token = signer.create_token({"email": "test@example.com"}, max_age_seconds=-1)
    assert signer.verify_token(token) is None


def test_secret_key_validation_and_placeholder_rejection():
    # Short key rejected
    with pytest.raises(ValueError, match="at least 32 characters"):
        TimedTokenSigner("short")

    # Known placeholders rejected
    placeholders = [
        "change-me-in-production-0123456789",
        "dev-secret-key-must-be-at-least-32-chars-long-change-in-prod-1234567890",
        "secret-key-must-be-at-least-32-chars-long-for-tests-1234567890",
        "temporary-secret-key-do-not-use-in-production-0123456789",
    ]
    for p in placeholders:
        with pytest.raises(ValueError, match="Insecure placeholder"):
            TimedTokenSigner(p)


def test_timed_token_signer_key_kind_and_legacy_raw_fallback():
    import base64
    import hashlib
    import hmac
    import json
    import time

    from fastapi_accounts.security.tokens import KeyKind

    signer = TimedTokenSigner(KEY_A)

    # 1. Normal derived key token
    token = signer.create_token(
        {"email": "test@example.com", "action": "verify_email", "token_v": 2}
    )
    payload, kind = signer.verify_token_with_kind(token)
    assert payload is not None
    assert kind == KeyKind.DERIVED
    assert payload["token_v"] == 2

    # 2. Legacy raw key token with token_v = 1
    def _make_raw_token(p: dict) -> str:
        data = {**p, "exp": int(time.time()) + 3600}
        jb = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
        pb64 = base64.urlsafe_b64encode(jb).decode("utf-8").rstrip("=")
        sig = hmac.new(
            KEY_A.encode("utf-8"), pb64.encode("utf-8"), hashlib.sha256
        ).digest()
        sb64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
        return f"{pb64}.{sb64}"

    legacy_token = _make_raw_token({"email": "legacy@example.com", "token_v": 1})
    payload_legacy, kind_legacy = signer.verify_token_with_kind(legacy_token)
    assert payload_legacy is not None
    assert kind_legacy == KeyKind.RAW_FALLBACK
    assert payload_legacy["email"] == "legacy@example.com"

    # 3. Raw key token attempting token_v = 2 must be rejected!
    spoofed_token = _make_raw_token({"email": "spoof@example.com", "token_v": 2})
    payload_spoofed, kind_spoofed = signer.verify_token_with_kind(spoofed_token)
    assert payload_spoofed is None
    assert kind_spoofed is None


def test_secret_key_rotation():
    # 1. Sign token with Key A
    signer_a = TimedTokenSigner([KEY_A])
    token_from_a = signer_a.create_token({"user_id": "u1", "action": "test"})

    # 2. Key rotation: Key B is now primary, Key A is secondary
    signer_b_and_a = TimedTokenSigner([KEY_B, KEY_A])
    # Token from A still verifies with rotated signer
    payload_a = signer_b_and_a.verify_token(token_from_a)
    assert payload_a is not None
    assert payload_a["user_id"] == "u1"

    # New token created with rotated signer is signed by Key B
    token_from_b = signer_b_and_a.create_token({"user_id": "u2", "action": "test"})
    # Signer with only Key A CANNOT verify token created with Key B
    assert signer_a.verify_token(token_from_b) is None

    # 3. Old Key A removed completely
    signer_b_only = TimedTokenSigner([KEY_B])
    # Token from A now fails verification
    assert signer_b_only.verify_token(token_from_a) is None
    # Token from B succeeds
    assert signer_b_only.verify_token(token_from_b) is not None
