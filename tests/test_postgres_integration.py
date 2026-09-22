import asyncio
import os

import pytest
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

    # Test concurrent session creation and password reset on Postgres
    async with session_maker() as s:
        # Create session bound to version 2
        sess_rec, raw_tok = await adapter.create_session(
            session=s,
            user_id=user_id,
            expected_credential_version=2,
        )
        await s.commit()
        assert sess_rec.credential_version == 2

    # Verify session authenticates
    async with session_maker() as s:
        auth_res = await adapter.get_session_and_user(s, raw_tok)
        assert auth_res is not None

    # Reset password to version 3
    async with session_maker() as s:
        ok = await adapter.atomic_reset_password(
            session=s,
            user_id=user_id,
            expected_cred_v=2,
            new_hashed_password="$argon2id$v3",
        )
        assert ok is True
        await s.commit()

    # Old session bound to version 2 must immediately fail authentication
    async with session_maker() as s:
        auth_res = await adapter.get_session_and_user(s, raw_tok)
        assert auth_res is None

    # Verify complete downgrade to base and re-upgrade to head
    command.downgrade(alembic_cfg, "base")
    command.upgrade(alembic_cfg, "head")
    command.check(alembic_cfg)

    await engine.dispose()
