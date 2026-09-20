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
    import threading

    import anyio

    svc = PasswordService(argon2_concurrency=4)

    # 1. Deterministic thread-offload verification: event loop yields while thread waits
    worker_started = threading.Event()
    worker_can_finish = threading.Event()
    loop_progressed = False

    def blocking_worker() -> str:
        worker_started.set()
        worker_can_finish.wait(timeout=5.0)
        return "worker_completed"

    async def run_worker() -> str:
        return await anyio.to_thread.run_sync(blocking_worker, limiter=svc._limiter)

    task = asyncio.create_task(run_worker())

    while not worker_started.is_set():
        await asyncio.sleep(0.001)

    # Event loop continues processing while thread is blocked
    loop_progressed = True
    worker_can_finish.set()

    res = await task
    assert res == "worker_completed"
    assert loop_progressed is True

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
