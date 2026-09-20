import os
import tempfile
import uuid
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.migrations import (
    get_alembic_config,
    inspect_legacy_schema,
)
from fastapi_accounts.models.default import Base


@pytest.mark.asyncio
async def test_migration_fresh_database():
    """Test initializing a completely fresh database with alembic upgrade head and assert 0 drift."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "fresh_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        async_db_url = f"sqlite+aiosqlite:///{db_path}"

        # 1. Run Alembic upgrade head on an empty database using package config helper
        alembic_cfg = get_alembic_config(sync_db_url)
        command.upgrade(alembic_cfg, "head")

        # 2. Assert zero schema drift
        command.check(alembic_cfg)

        # 3. Verify tables and operations work cleanly with SQLAlchemyAdapter
        adapter = SQLAlchemyAdapter(database_url=async_db_url)
        async with adapter.session_maker() as session:
            _user, _email_rec = await adapter.create_user_with_password(
                session=session,
                email="fresh@example.com",
                password="FreshPassword123!",
                is_verified=True,
            )
            await session.commit()

        async with adapter.session_maker() as session:
            queried = await adapter.get_user_by_email(session, "fresh@example.com")
            assert queried is not None
            assert queried.primary_email == "fresh@example.com"
            assert queried.password_credential is not None
            assert queried.password_credential.password_updated_at is not None

        await adapter.engine.dispose()


@pytest.mark.asyncio
async def test_migration_upgrade_from_legacy_a2_schema():
    """Test upgrade from authentic v0.1.0a2 create_all() schema (including existing indexes) to head."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_a2_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        async_db_url = f"sqlite+aiosqlite:///{db_path}"

        sync_engine = create_engine(sync_db_url)

        # 1. Create authentic v0.1.0a2 schema (as created by v0.1.0a2 adapter.create_all())
        meta_a2 = sa.MetaData()
        users_t = sa.Table(
            "users",
            meta_a2,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
            ),
            sa.Column(
                "is_superuser", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        emails_t = sa.Table(
            "email_addresses",
            meta_a2,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("email", sa.String(320), nullable=False, unique=True, index=True),
            sa.Column(
                "is_verified", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "is_primary", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        creds_t = sa.Table(
            "password_credentials",
            meta_a2,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
                unique=True,
                index=True,
            ),
            sa.Column("hashed_password", sa.String(1024), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        sa.Table(
            "sessions",
            meta_a2,
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "expires_at", sa.DateTime(timezone=True), nullable=False, index=True
            ),
            sa.Column("ip_address", sa.String(45), nullable=True),
            sa.Column("user_agent", sa.String(512), nullable=True),
        )

        meta_a2.create_all(sync_engine)

        user_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        with sync_engine.connect() as conn:
            # Insert legacy user record
            conn.execute(
                users_t.insert().values(
                    id=user_id,
                    is_active=True,
                    is_superuser=False,
                    created_at=now,
                    updated_at=now,
                )
            )
            conn.execute(
                emails_t.insert().values(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    email="legacy_a2@example.com",
                    is_verified=True,
                    is_primary=True,
                    created_at=now,
                )
            )
            conn.execute(
                creds_t.insert().values(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    hashed_password="$argon2id$mockhash",
                    created_at=now,
                    updated_at=now,
                )
            )
            conn.commit()

            # Verify schema inspector identifies v0.1.0a2
            classification = inspect_legacy_schema(conn)
            assert classification == "v0.1.0a2"

        # 2. Before migration: querying with current model raises OperationalError
        adapter_pre = SQLAlchemyAdapter(database_url=async_db_url)
        with pytest.raises(OperationalError, match="no such column"):
            async with adapter_pre.session_maker() as session:
                await adapter_pre.get_password_credential(session, user_id)
        await adapter_pre.engine.dispose()

        # 3. Stamp 0001_initial_schema and run Alembic upgrade head
        alembic_cfg = get_alembic_config(sync_db_url)
        command.stamp(alembic_cfg, "0001_initial_schema")
        command.upgrade(alembic_cfg, "head")

        # 4. Assert zero schema drift after legacy upgrade
        command.check(alembic_cfg)

        # 5. Post migration: verify adapter queries successfully
        adapter_post = SQLAlchemyAdapter(database_url=async_db_url)
        async with adapter_post.session_maker() as session:
            user = await adapter_post.get_user_by_email(
                session, "legacy_a2@example.com"
            )
            assert user is not None
            assert user.password_credential is not None
            assert user.password_credential.password_updated_at is not None

        await adapter_post.engine.dispose()


@pytest.mark.asyncio
async def test_migration_adopt_legacy_a3_schema():
    """Test adopting authentic v0.1.0a3 create_all() schema (with password_updated_at) to head."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_a3_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        sync_engine = create_engine(sync_db_url)

        # 1. Create authentic v0.1.0a3 schema via Base.metadata.create_all()
        Base.metadata.create_all(sync_engine)

        with sync_engine.connect() as conn:
            # Verify schema inspector identifies v0.1.0a3
            classification = inspect_legacy_schema(conn)
            assert classification == "v0.1.0a3"

        # 2. Stamp head directly for v0.1.0a3 schemas
        alembic_cfg = get_alembic_config(sync_db_url)
        command.stamp(alembic_cfg, "head")

        # 3. Assert zero schema drift
        command.check(alembic_cfg)


@pytest.mark.asyncio
async def test_migration_upgrade_from_0002():
    """Test upgrading an Alembic-managed database from 0002 to head adds missing indexes cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "upgrade_0002_test.db")
        sync_db_url = f"sqlite:///{db_path}"

        alembic_cfg = get_alembic_config(sync_db_url)
        # Apply up to 0002
        command.upgrade(alembic_cfg, "0002_add_password_updated_at")

        sync_engine = create_engine(sync_db_url)
        with sync_engine.connect() as conn:
            # Invariant: Must be recognized as alembic_managed, NOT misclassified as legacy v0.1.0a3!
            classification = inspect_legacy_schema(conn)
            assert classification == "alembic_managed"

            # Verify sessions indexes are currently absent
            inspector = sa.inspect(conn)
            indexes = {idx["name"] for idx in inspector.get_indexes("sessions")}
            assert "ix_sessions_user_id" not in indexes
            assert "ix_sessions_expires_at" not in indexes

        # Upgrade to head (0003)
        command.upgrade(alembic_cfg, "head")

        # Verify indexes are created and zero drift exists
        with sync_engine.connect() as conn:
            inspector = sa.inspect(conn)
            indexes = {idx["name"] for idx in inspector.get_indexes("sessions")}
            assert "ix_sessions_user_id" in indexes
            assert "ix_sessions_expires_at" in indexes

        command.check(alembic_cfg)


def test_migration_downgrade_and_reupgrade():
    """Test migration reversibility: upgrade head -> downgrade 0002 -> upgrade head -> downgrade base -> upgrade head."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "reversibility_test.db")
        sync_db_url = f"sqlite:///{db_path}"

        alembic_cfg = get_alembic_config(sync_db_url)

        # 1. Upgrade to head
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)

        # 2. Downgrade to 0002
        command.downgrade(alembic_cfg, "0002_add_password_updated_at")

        # 3. Upgrade back to head
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)

        # 4. Downgrade to base
        command.downgrade(alembic_cfg, "base")

        # 5. Upgrade back to head
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


def test_inspect_legacy_schema_outcomes():
    """Test inspect_legacy_schema across valid, alembic-managed, and invalid schema states."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "inspect_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        engine = create_engine(sync_db_url)

        # 1. Empty database -> unrecognized
        with engine.connect() as conn:
            assert inspect_legacy_schema(conn) == "unrecognized"

        # 2. Partial tables (only users table) -> unrecognized
        with engine.connect() as conn:
            conn.execute(
                text(
                    "CREATE TABLE users (id CHAR(36) PRIMARY KEY, is_active BOOLEAN NOT NULL DEFAULT 1, is_superuser BOOLEAN NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)"
                )
            )
            conn.commit()
            assert inspect_legacy_schema(conn) == "unrecognized"

        # 3. Corrupt types (integer email and password fields, nullable sensitive columns, missing unique constraints)
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE users"))
            conn.execute(
                text(
                    "CREATE TABLE users (id INTEGER PRIMARY KEY, is_active BOOLEAN, is_superuser BOOLEAN, created_at TIMESTAMP, updated_at TIMESTAMP)"
                )
            )
            conn.execute(
                text(
                    "CREATE TABLE email_addresses (id INTEGER PRIMARY KEY, user_id INTEGER, email INTEGER, is_verified BOOLEAN, is_primary BOOLEAN, created_at TIMESTAMP)"
                )
            )
            conn.execute(
                text(
                    "CREATE TABLE password_credentials (id INTEGER PRIMARY KEY, user_id INTEGER, hashed_password INTEGER, password_updated_at TIMESTAMP, created_at TIMESTAMP, updated_at TIMESTAMP)"
                )
            )
            conn.execute(
                text(
                    "CREATE TABLE sessions (id INTEGER PRIMARY KEY, user_id INTEGER, created_at TIMESTAMP, expires_at TIMESTAMP, ip_address TEXT, user_agent TEXT)"
                )
            )
            conn.commit()
            # Must strictly fail closed and return unrecognized!
            assert inspect_legacy_schema(conn) == "unrecognized"

        # 4. Alembic-managed database -> alembic_managed
        with engine.connect() as conn:
            conn.execute(
                text(
                    "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO alembic_version VALUES ('0002_add_password_updated_at')"
                )
            )
            conn.commit()
            assert inspect_legacy_schema(conn) == "alembic_managed"


def test_get_alembic_config_helper_percent_escaping():
    """Test get_alembic_config handles percent-encoded database URLs without ConfigParser interpolation error."""
    test_url = "postgresql+asyncpg://user:p%25ss@localhost:5432/test_db%25"
    config = get_alembic_config(test_url)

    # get_main_option should return unescaped URL
    retrieved_url = config.get_main_option("sqlalchemy.url")
    assert retrieved_url == test_url


def test_env_py_loads_database_url_from_env(monkeypatch: pytest.MonkeyPatch):
    """Test env.py resolves FASTAPI_ACCOUNTS_DATABASE_URL environment variable when sqlalchemy.url is omitted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "env_test.db")
        sync_db_url = f"sqlite:///{db_path}"

        monkeypatch.setenv("FASTAPI_ACCOUNTS_DATABASE_URL", sync_db_url)

        # Create config without sqlalchemy.url set
        alembic_cfg = get_alembic_config()
        # Upgrade to head using environment variable URL
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)
