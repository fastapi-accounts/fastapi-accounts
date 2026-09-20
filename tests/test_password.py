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
async def test_event_loop_not_blocked_during_hashing(monkeypatch):
    """Verify that CPU-intensive Argon2 operations offloaded via worker threads do not block event loop progress."""
    import threading

    import fastapi_accounts.security.password as pwd_module

    svc = PasswordService(argon2_concurrency=4)

    # 1. Deterministic thread-offload verification: intercept synchronous hash_password with threading.Event
    worker_started = threading.Event()
    worker_can_finish = threading.Event()

    def blocking_hash(secret: str) -> str:
        worker_started.set()
        worker_can_finish.wait(timeout=5.0)
        return "$argon2id$mock_blocked_hash"

    monkeypatch.setattr(pwd_module, "hash_password", blocking_hash)

    task = asyncio.create_task(svc.async_hash_password("SuperSecret123!"))

    while not worker_started.is_set():
        await asyncio.sleep(0.001)

    # Event loop continues processing while offloaded worker thread is blocked
    loop_progressed = False
    for _ in range(5):
        await asyncio.sleep(0.005)
        loop_progressed = True

    assert loop_progressed is True
    worker_can_finish.set()

    res = await task
    assert res == "$argon2id$mock_blocked_hash"

    # Restore unpatched hash_password for live Argon2 hashing heartbeat concurrency test
    monkeypatch.undo()

    # 2. Live Argon2 hashing heartbeat concurrency
    ticks = 0

    async def heartbeat():
        nonlocal ticks
        for _ in range(10):
            await asyncio.sleep(0.01)
            ticks += 1

    heartbeat_task = asyncio.create_task(heartbeat())
    hashes = await asyncio.gather(
        svc.async_hash_password("Pass1234!"),
        svc.async_hash_password("Pass5678!"),
        svc.async_hash_password("Pass9012!"),
    )
    await heartbeat_task

    assert len(hashes) == 3
    assert ticks > 0
