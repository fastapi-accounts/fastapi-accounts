import asyncio
import os

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.migrations import get_alembic_config

POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")


@pytest.mark.skipif(
    not POSTGRES_URL,
    reason="TEST_POSTGRES_URL not set (runs in CI with PostgreSQL container)",
)
@pytest.mark.asyncio
async def test_postgres_migration_and_cas_concurrency():
    """Verify PostgreSQL migrations to head with zero drift and physical concurrent CAS updates."""
    # Convert asyncpg url to synchronous psycopg v3 driver for Alembic
    sync_pg_url = (
        POSTGRES_URL.replace("postgresql+asyncpg://", "postgresql+psycopg://")
        if "+asyncpg" in POSTGRES_URL
        else POSTGRES_URL.replace("postgresql://", "postgresql+psycopg://")
    )

    alembic_cfg = get_alembic_config(sync_pg_url)
    command.upgrade(alembic_cfg, "head")
    command.check(alembic_cfg)

    # Test physical concurrent CAS with separate async connections
    engine = create_async_engine(POSTGRES_URL, echo=False)
    session_maker = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )
    adapter = SQLAlchemyAdapter(session_maker=session_maker, engine=engine)

    async with session_maker() as session:
        user, _ = await adapter.create_user_with_password(
            session=session,
            email="pg_concurrency@example.com",
            hashed_password="$argon2id$mockpgpass",
            is_verified=True,
        )
        await session.commit()
        user_id = user.id

    # Two separate worker connections performing CAS update with expected_cred_v=1
    async def worker_cas(new_hash: str) -> tuple[bool, str | None]:
        async with session_maker() as s:
            ok = await adapter.atomic_reset_password(
                session=s,
                user_id=user_id,
                expected_cred_v=1,
                new_hashed_password=new_hash,
            )
            if ok:
                await s.commit()
            else:
                await s.rollback()
            return ok, new_hash if ok else None

    results = await asyncio.gather(
        worker_cas("$argon2id$win1"),
        worker_cas("$argon2id$win2"),
    )

    # Exactly one must succeed on real Postgres
    successes = [r for r in results if r[0] is True]
    failures = [r for r in results if r[0] is False]
    assert len(successes) == 1
    assert len(failures) == 1
    winner_hash = successes[0][1]

    # Verify persisted state from a separate 3rd session
    async with session_maker() as s:
        cred = await adapter.get_password_credential(s, user_id)
        assert cred is not None
        assert cred.credential_version == 2
        assert cred.hashed_password == winner_hash

    # ---------------------------------------------------------
    # Deterministic PostgreSQL Multi-Connection Concurrency Tests
    # ---------------------------------------------------------

    # Ordering 1: Session issuance acquires lock first, Reset waits on row lock
    async with session_maker() as s_init:
        user1, _ = await adapter.create_user_with_password(
            session=s_init,
            email="pg_lock_order1@example.com",
            hashed_password="$argon2id$initpass1",
            is_verified=True,
        )
        await s_init.commit()
        user1_id = user1.id

    barrier_sess_locked = asyncio.Event()
    barrier_reset_started = asyncio.Event()

    async def worker_sess_creation() -> tuple[bool, str]:
        raw_tok = "pg_raw_tok_ordering_1"
        async with session_maker() as s1:
            try:
                # 1. Acquire row lock on credentials for expected_credential_version=1
                cred_lock = (
                    (
                        await s1.execute(
                            sa.select(adapter.credential_model)
                            .where(
                                adapter.credential_model.user_id == user1_id,
                                adapter.credential_model.credential_version == 1,
                            )
                            .with_for_update()
                        )
                    )
                    .scalars()
                    .first()
                )
                assert cred_lock is not None
                barrier_sess_locked.set()

                # Wait until reset worker has entered and is waiting
                await asyncio.wait_for(barrier_reset_started.wait(), timeout=5.0)
                await asyncio.sleep(
                    0.1
                )  # Brief pause to ensure reset UPDATE is queued on row lock

                # Complete session insertion and commit
                sess_rec = await adapter.create_session(
                    session=s1,
                    user_id=user1_id,
                    raw_token=raw_tok,
                    expected_credential_version=1,
                )
                await s1.commit()
                assert sess_rec.credential_version == 1
                return True, raw_tok
            except Exception:
                await s1.rollback()
                raise

    async def worker_reset_password() -> bool:
        async with session_maker() as s2:
            try:
                await asyncio.wait_for(barrier_sess_locked.wait(), timeout=5.0)
                barrier_reset_started.set()
                # atomic_reset_password will block until worker_sess_creation commits and releases row lock
                ok = await asyncio.wait_for(
                    adapter.atomic_reset_password(
                        session=s2,
                        user_id=user1_id,
                        expected_cred_v=1,
                        new_hashed_password="$argon2id$newpass1",
                    ),
                    timeout=5.0,
                )
                if ok:
                    await s2.commit()
                else:
                    await s2.rollback()
                return ok
            except Exception:
                await s2.rollback()
                raise

    sess_res, reset_ok = await asyncio.gather(
        worker_sess_creation(),
        worker_reset_password(),
    )
    assert sess_res[0] is True
    assert reset_ok is True
    issued_tok1 = sess_res[1]

    # Verify post-reset authorization: issued session was bound to version 1, but credential is now version 2
    async with session_maker() as s_check:
        cred = await adapter.get_password_credential(s_check, user1_id)
        assert cred is not None
        assert cred.credential_version == 2
        auth_res = await adapter.get_session_and_user(s_check, issued_tok1)
        # MUST fail authentication (401 invalidation)
        assert auth_res is None

    # Ordering 2: Reset acquires lock and commits first, Session creation observes version mismatch
    async with session_maker() as s_init:
        user2, _ = await adapter.create_user_with_password(
            session=s_init,
            email="pg_lock_order2@example.com",
            hashed_password="$argon2id$initpass2",
            is_verified=True,
        )
        await s_init.commit()
        user2_id = user2.id

    # Reset advances credential_version from 1 to 2 first
    async with session_maker() as s_reset:
        ok2 = await adapter.atomic_reset_password(
            session=s_reset,
            user_id=user2_id,
            expected_cred_v=1,
            new_hashed_password="$argon2id$newpass2",
        )
        assert ok2 is True
        await s_reset.commit()

    # Session creation attempted with stale expected_credential_version=1 MUST raise ValueError
    async with session_maker() as s_sess:
        with pytest.raises(
            ValueError, match="Credential version mismatch during session creation"
        ):
            await adapter.create_session(
                session=s_sess,
                user_id=user2_id,
                raw_token="pg_stale_token_attempt",
                expected_credential_version=1,
            )

    # Verify no session was created and authentication returns None
    async with session_maker() as s_check:
        auth_res2 = await adapter.get_session_and_user(
            s_check, "pg_stale_token_attempt"
        )
        assert auth_res2 is None

    # Verify complete downgrade to base and re-upgrade to head
    command.downgrade(alembic_cfg, "base")
    command.upgrade(alembic_cfg, "head")
    command.check(alembic_cfg)

    await engine.dispose()
