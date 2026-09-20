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

    # Known placeholder rejected
    with pytest.raises(ValueError, match="Insecure placeholder"):
        TimedTokenSigner("change-me-in-production-0123456789")


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
