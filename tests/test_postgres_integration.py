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
    # Convert async url to sync for Alembic if needed
    sync_pg_url = POSTGRES_URL.replace("+asyncpg", "")

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
    async def worker_cas(new_hash: str):
        async with session_maker() as s:
            return await adapter.atomic_reset_password(
                session=s,
                user_id=user_id,
                expected_cred_v=1,
                new_hashed_password=new_hash,
            )

    results = await asyncio.gather(
        worker_cas("$argon2id$win1"),
        worker_cas("$argon2id$win2"),
    )

    # Exactly one must succeed on real Postgres
    assert results.count(True) == 1
    assert results.count(False) == 1

    await engine.dispose()
