import asyncio
import contextlib
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.migrations import (
    get_alembic_config,
    inspect_legacy_schema,
)
from fastapi_accounts.migrations.legacy import SchemaState
from fastapi_accounts.models.default import Base
from fastapi_accounts.security.tokens import hash_token

POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")


async def wait_for_lock_block(
    observer_session: AsyncSession,
    waiter_pid: int,
    blocker_pid: int,
    timeout: float = 5.0,
) -> bool:
    """Observe that waiter_pid is physically blocked by blocker_pid via pg_stat_activity and pg_blocking_pids."""
    start = asyncio.get_event_loop().time()
    while asyncio.get_event_loop().time() - start < timeout:
        res = await observer_session.execute(
            sa.text(
                "SELECT pid, wait_event_type, pg_blocking_pids(pid) "
                "FROM pg_stat_activity "
                "WHERE pid = :waiter_pid"
            ),
            {"waiter_pid": waiter_pid},
        )
        row = res.first()
        if row:
            wait_event_type = row[1]
            blocking_pids = row[2] or []
            if wait_event_type == "Lock" and blocker_pid in blocking_pids:
                return True
        await asyncio.sleep(0.02)
    raise TimeoutError(
        f"Waiter PID {waiter_pid} was not observed blocked by PID {blocker_pid} within {timeout}s"
    )


@pytest.mark.skipif(
    not POSTGRES_URL,
    reason="TEST_POSTGRES_URL not set (runs in CI with PostgreSQL container)",
)
@pytest.mark.asyncio
async def test_postgres_native_uuid_and_schema_inspection():
    """Verify PostgreSQL reflection and schema inspector on native UUID types (managed and unmanaged)."""
    sync_pg_url = (
        POSTGRES_URL.replace("postgresql+asyncpg://", "postgresql+psycopg://")
        if "+asyncpg" in POSTGRES_URL
        else POSTGRES_URL.replace("postgresql://", "postgresql+psycopg://")
    )
    sync_engine = sa.create_engine(sync_pg_url)
    try:

        def clone_metadata() -> sa.MetaData:
            m = sa.MetaData()
            for table in Base.metadata.sorted_tables:
                table.to_metadata(m)
            return m

        # 1. Valid managed 0005 schema inspection on real PostgreSQL
        alembic_cfg = get_alembic_config(sync_pg_url)
        command.upgrade(alembic_cfg, "head")
        with sync_engine.connect() as conn:
            res = inspect_legacy_schema(conn)
            assert res.state == SchemaState.ALEMBIC_MANAGED

        # 2. Positive controls on unmanaged and managed clean cloned metadata (preserving FKs/indexes)
        with sync_engine.begin() as conn:
            conn.execute(sa.text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
        meta_clean = clone_metadata()
        meta_clean.create_all(sync_engine)
        with sync_engine.connect() as conn:
            res_clean_unmanaged = inspect_legacy_schema(conn)
            assert res_clean_unmanaged.state == SchemaState.UNVERSIONED_CURRENT, (
                f"Expected UNVERSIONED_CURRENT for clean cloned metadata, got {res_clean_unmanaged.state}"
            )

        with sync_engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY);"
                )
            )
            conn.execute(
                sa.text(
                    "INSERT INTO alembic_version (version_num) VALUES ('0005_add_session_cred_version');"
                )
            )
        with sync_engine.connect() as conn:
            res_clean_managed = inspect_legacy_schema(conn)
            assert res_clean_managed.state == SchemaState.ALEMBIC_MANAGED, (
                f"Expected ALEMBIC_MANAGED for clean managed cloned metadata, got {res_clean_managed.state}"
            )

        # 3. Test invalid non-ID native UUID columns on PostgreSQL tables in both unmanaged and managed modes
        invalid_columns = [
            ("email_addresses", "email"),
            ("password_credentials", "hashed_password"),
            ("sessions", "id"),
            ("sessions", "ip_address"),
            ("sessions", "user_agent"),
        ]
        for table_name, col_name in invalid_columns:
            # Mode A: Unmanaged schema with invalid native UUID on non-ID column
            with sync_engine.begin() as conn:
                conn.execute(
                    sa.text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
                )

            meta = clone_metadata()
            meta.tables[table_name].c[col_name].type = postgresql.UUID()
            meta.create_all(sync_engine)

            with sync_engine.connect() as conn:
                res = inspect_legacy_schema(conn)
                assert res.state == SchemaState.UNKNOWN, (
                    f"Expected UNKNOWN for unmanaged {table_name}.{col_name} UUID on PG, got {res.state}"
                )

            # Mode B: Managed 0005 schema with invalid native UUID on non-ID column
            with sync_engine.begin() as conn:
                conn.execute(
                    sa.text(
                        "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY);"
                    )
                )
                conn.execute(
                    sa.text(
                        "INSERT INTO alembic_version (version_num) VALUES ('0005_add_session_cred_version');"
                    )
                )

            with sync_engine.connect() as conn:
                res = inspect_legacy_schema(conn)
                assert res.state == SchemaState.UNKNOWN, (
                    f"Expected UNKNOWN for managed {table_name}.{col_name} UUID on PG, got {res.state}"
                )

        # Clean schema and upgrade back to head
        with sync_engine.begin() as conn:
            conn.execute(sa.text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)
    finally:
        sync_engine.dispose()


@pytest.mark.skipif(
    not POSTGRES_URL,
    reason="TEST_POSTGRES_URL not set (runs in CI with PostgreSQL container)",
)
@pytest.mark.asyncio
async def test_postgres_migration_and_cas_concurrency():
    """Verify PostgreSQL migrations, populated 0004->0005 backfill, CAS concurrency, and 3-connection lock orderings."""
    sync_pg_url = (
        POSTGRES_URL.replace("postgresql+asyncpg://", "postgresql+psycopg://")
        if "+asyncpg" in POSTGRES_URL
        else POSTGRES_URL.replace("postgresql://", "postgresql+psycopg://")
    )

    alembic_cfg = get_alembic_config(sync_pg_url)

    # 1. Upgrade populated 0004 -> 0005 on PostgreSQL
    command.downgrade(alembic_cfg, "base")
    command.upgrade(alembic_cfg, "0004_add_credential_version")

    sync_engine = sa.create_engine(sync_pg_url)
    try:
        user_pop1 = uuid.uuid4()
        user_pop2 = uuid.uuid4()
        now_utc = datetime.now(timezone.utc)
        with sync_engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, is_active, is_superuser, created_at, updated_at) "
                    "VALUES (:u1, true, false, :now, :now), (:u2, true, false, :now, :now)"
                ),
                {"u1": user_pop1, "u2": user_pop2, "now": now_utc},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO password_credentials (id, user_id, hashed_password, credential_version, password_updated_at, created_at, updated_at) "
                    "VALUES (:cid, :u1, 'pg_hash', 3, :now, :now, :now)"
                ),
                {"cid": uuid.uuid4(), "u1": user_pop1, "now": now_utc},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO sessions (id, user_id, created_at, expires_at) "
                    "VALUES ('pg_sess1', :u1, :now, :now), ('pg_sess2', :u2, :now, :now)"
                ),
                {"u1": user_pop1, "u2": user_pop2, "now": now_utc},
            )

        # Upgrade to head (0005) on PostgreSQL
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)

        with sync_engine.connect() as conn:
            v1 = conn.execute(
                sa.text("SELECT credential_version FROM sessions WHERE id = 'pg_sess1'")
            ).scalar()
            v2 = conn.execute(
                sa.text("SELECT credential_version FROM sessions WHERE id = 'pg_sess2'")
            ).scalar()
            assert v1 == 3
            assert v2 == 1
    finally:
        sync_engine.dispose()

    # 2. Test physical concurrent CAS with separate async connections
    engine: AsyncEngine = create_async_engine(POSTGRES_URL, echo=False)
    try:
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
        # Deterministic 3-Connection PostgreSQL Concurrency Tests
        # ---------------------------------------------------------

        # Ordering 1: Session issuance acquires lock first via adapter, Reset waits on row lock
        async with session_maker() as s_init:
            user1, _ = await adapter.create_user_with_password(
                session=s_init,
                email="pg_lock_order1@example.com",
                hashed_password="$argon2id$initpass1",
                is_verified=True,
            )
            await s_init.commit()
            user1_id = user1.id

        barrier_issuance_ready = asyncio.Event()
        raw_tok1 = "pg_raw_tok_ordering_1"
        tok1_id = hash_token(raw_tok1)

        async with (
            session_maker() as s_issuance,
            session_maker() as s_reset,
            session_maker() as s_observer,
        ):
            pid_issuance = (
                await s_issuance.execute(sa.text("SELECT pg_backend_pid()"))
            ).scalar()
            pid_reset = (
                await s_reset.execute(sa.text("SELECT pg_backend_pid()"))
            ).scalar()
            assert pid_issuance is not None and pid_reset is not None

            reset_task: asyncio.Task[bool] | None = None
            try:
                # Worker 1 calls adapter.create_session (which acquires row lock on password_credentials)
                sess_rec = await adapter.create_session(
                    session=s_issuance,
                    user_id=user1_id,
                    raw_token=raw_tok1,
                    expected_credential_version=1,
                )
                assert sess_rec.credential_version == 1
                barrier_issuance_ready.set()

                # Worker 2 starts adapter.atomic_reset_password concurrently (which blocks on Worker 1's lock)
                async def run_reset_worker() -> bool:
                    return await adapter.atomic_reset_password(
                        session=s_reset,
                        user_id=user1_id,
                        expected_cred_v=1,
                        new_hashed_password="$argon2id$newpass1",
                    )

                reset_task = asyncio.create_task(run_reset_worker())

                # Observer confirms Worker 2 is physically blocked by Worker 1 in PostgreSQL
                await wait_for_lock_block(
                    observer_session=s_observer,
                    waiter_pid=pid_reset,
                    blocker_pid=pid_issuance,
                    timeout=5.0,
                )

                # Worker 1 commits session
                await s_issuance.commit()

                # Worker 2 unblocks, completes atomic_reset_password, and commits
                reset_ok = await asyncio.wait_for(reset_task, timeout=5.0)
                assert reset_ok is True
                await s_reset.commit()

                # Post-reset verification:
                # 1. Physical revocation: user's session was deleted by atomic_reset_password
                res_count = (
                    await s_observer.execute(
                        sa.text("SELECT count(*) FROM sessions WHERE id = :tid"),
                        {"tid": tok1_id},
                    )
                ).scalar()
                assert res_count == 0

                # 2. Credential generation bumped to 2
                cred1 = await adapter.get_password_credential(s_observer, user1_id)
                assert cred1 is not None
                assert cred1.credential_version == 2

                # 3. Authorization rejected
                auth_res = await adapter.get_session_and_user(s_observer, raw_tok1)
                assert auth_res is None
            finally:
                if reset_task is not None:
                    if not reset_task.done():
                        reset_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await reset_task

        # Ordering 2: Reset acquires lock first via adapter, Session creation waits on row lock
        async with session_maker() as s_init:
            user2, _ = await adapter.create_user_with_password(
                session=s_init,
                email="pg_lock_order2@example.com",
                hashed_password="$argon2id$initpass2",
                is_verified=True,
            )
            await s_init.commit()
            user2_id = user2.id

        raw_tok2 = "pg_raw_tok_ordering_2"
        tok2_id = hash_token(raw_tok2)
        barrier_reset_ready = asyncio.Event()

        async with (
            session_maker() as s_issuance,
            session_maker() as s_reset,
            session_maker() as s_observer,
        ):
            pid_issuance = (
                await s_issuance.execute(sa.text("SELECT pg_backend_pid()"))
            ).scalar()
            pid_reset = (
                await s_reset.execute(sa.text("SELECT pg_backend_pid()"))
            ).scalar()
            assert pid_issuance is not None and pid_reset is not None

            issuance_task: asyncio.Task[Any] | None = None
            try:
                # Worker 2 calls adapter.atomic_reset_password (holds row exclusive lock on password_credentials)
                reset_ok2 = await adapter.atomic_reset_password(
                    session=s_reset,
                    user_id=user2_id,
                    expected_cred_v=1,
                    new_hashed_password="$argon2id$newpass2",
                )
                assert reset_ok2 is True
                barrier_reset_ready.set()

                # Worker 1 attempts adapter.create_session with expected_credential_version=1 (blocks on Worker 2's lock)
                async def run_issuance_worker() -> Any:
                    return await adapter.create_session(
                        session=s_issuance,
                        user_id=user2_id,
                        raw_token=raw_tok2,
                        expected_credential_version=1,
                    )

                issuance_task = asyncio.create_task(run_issuance_worker())

                # Observer confirms Worker 1 is physically blocked by Worker 2 in PostgreSQL
                await wait_for_lock_block(
                    observer_session=s_observer,
                    waiter_pid=pid_issuance,
                    blocker_pid=pid_reset,
                    timeout=5.0,
                )

                # Worker 2 commits (advancing version to 2)
                await s_reset.commit()

                # Worker 1 unblocks, observes version mismatch (version is now 2), and raises ValueError
                with pytest.raises(
                    ValueError,
                    match="Credential version mismatch during session creation",
                ):
                    await asyncio.wait_for(issuance_task, timeout=5.0)

                await s_issuance.rollback()

                # Post-reset verification:
                # 1. No session was inserted
                res_count2 = (
                    await s_observer.execute(
                        sa.text("SELECT count(*) FROM sessions WHERE id = :tid"),
                        {"tid": tok2_id},
                    )
                ).scalar()
                assert res_count2 == 0

                # 2. Credential generation bumped to 2
                cred2 = await adapter.get_password_credential(s_observer, user2_id)
                assert cred2 is not None
                assert cred2.credential_version == 2

                # 3. Authorization rejected
                auth_res2 = await adapter.get_session_and_user(s_observer, raw_tok2)
                assert auth_res2 is None
            finally:
                if issuance_task is not None:
                    if not issuance_task.done():
                        issuance_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await issuance_task

        # Verify complete downgrade to base and re-upgrade to head
        command.downgrade(alembic_cfg, "base")
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)
    finally:
        await engine.dispose()
