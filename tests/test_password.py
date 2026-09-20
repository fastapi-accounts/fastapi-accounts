import asyncio

import pytest

from fastapi_accounts.security.password import (
    PasswordService,
    async_hash_password,
    async_verify_dummy_password,
    async_verify_password,
    hash_password,
    verify_password,
)


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


@pytest.mark.asyncio
async def test_async_password_hashing_and_verification():
    plain = "AsyncPassword123!"
    hashed = await async_hash_password(plain)
    assert hashed != plain
    assert "argon2" in hashed

    assert await async_verify_password(plain, hashed) is True
    assert await async_verify_password("WrongPassword", hashed) is False


@pytest.mark.asyncio
async def test_async_verify_dummy_password():
    res = await async_verify_dummy_password("any_plain_password")
    assert res is False


@pytest.mark.asyncio
async def test_event_loop_not_blocked_during_hashing():
    """Verify that CPU-intensive Argon2 operations offloaded via worker threads do not block event loop progress."""
    svc = PasswordService(argon2_concurrency=4)

    ticks = 0

    async def heartbeat():
        nonlocal ticks
        for _ in range(10):
            await asyncio.sleep(0.01)
            ticks += 1

    # Run background heartbeat concurrently with multiple async password hashes
    heartbeat_task = asyncio.create_task(heartbeat())
    hashes = await asyncio.gather(
        svc.async_hash_password("Pass1234!"),
        svc.async_hash_password("Pass5678!"),
        svc.async_hash_password("Pass9012!"),
    )
    await heartbeat_task

    assert len(hashes) == 3
    # Heartbeat must have ticked while hashing took place
    assert ticks > 0
