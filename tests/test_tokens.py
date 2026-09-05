import time

from fastapi_accounts.security.tokens import TimedTokenSigner, generate_secure_token, hash_token


def test_secure_token_and_hash():
    token = generate_secure_token(32)
    assert len(token) > 30

    h1 = hash_token(token)
    h2 = hash_token(token)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex length


def test_timed_token_signer_valid():
    signer = TimedTokenSigner("secret-12345")
    token = signer.create_token({"email": "test@example.com", "action": "verify_email"}, max_age_seconds=60)

    payload = signer.verify_token(token)
    assert payload is not None
    assert payload["email"] == "test@example.com"
    assert payload["action"] == "verify_email"


def test_timed_token_signer_tampered():
    signer = TimedTokenSigner("secret-12345")
    token = signer.create_token({"email": "test@example.com"})

    # Tamper with token
    tampered = token[:-4] + "abcd"
    assert signer.verify_token(tampered) is None


def test_timed_token_signer_expired():
    signer = TimedTokenSigner("secret-12345")
    # Expired token (0 seconds)
    token = signer.create_token({"email": "test@example.com"}, max_age_seconds=-1)

    assert signer.verify_token(token) is None
