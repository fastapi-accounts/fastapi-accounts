from fastapi_accounts.security.password import hash_password, verify_password


def test_password_hashing_and_verification():
    plain = "SuperSecretPassword123!"
    hashed = hash_password(plain)

    # Hash should not equal plaintext
    assert hashed != plain
    assert "argon2" in hashed

    # Valid password verification
    assert verify_password(plain, hashed) is True

    # Invalid password verification
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


def test_unique_salts():
    plain = "SamePasswordEverywhere!"
    hash1 = hash_password(plain)
    hash2 = hash_password(plain)

    # Hashes must differ due to unique salts
    assert hash1 != hash2
    assert verify_password(plain, hash1) is True
    assert verify_password(plain, hash2) is True
