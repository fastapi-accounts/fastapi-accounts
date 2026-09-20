import os
import tempfile
import uuid
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy import create_engine, text

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.migrations import (
    get_alembic_config,
    inspect_legacy_schema,
)
from fastapi_accounts.migrations.legacy import SchemaState
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
                hashed_password="$argon2id$mockhash",
                is_verified=True,
            )
            await session.commit()

        async with adapter.session_maker() as session:
            queried = await adapter.get_user_by_email(session, "fresh@example.com")
            assert queried is not None
            assert queried.password_credential is not None
            assert queried.password_credential.credential_version == 1

        await adapter.engine.dispose()


@pytest.mark.asyncio
async def test_migration_upgrade_from_legacy_a2_schema():
    """Test upgrade from authentic v0.1.0a2 create_all() schema to head."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_a2_test.db")
        sync_db_url = f"sqlite:///{db_path}"

        sync_engine = create_engine(sync_db_url)

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

            res = inspect_legacy_schema(conn)
            assert res.state == SchemaState.UNVERSIONED_A2
            assert res.stamp_revision == "0001_initial_schema"

        alembic_cfg = get_alembic_config(sync_db_url)
        command.stamp(alembic_cfg, res.stamp_revision)
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


@pytest.mark.asyncio
async def test_migration_adopt_legacy_a3_schema():
    """Test adopting authentic v0.1.0a3 schema (with password_updated_at but no credential_version)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_a3_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        sync_engine = create_engine(sync_db_url)

        meta_a3 = sa.MetaData()
        sa.Table(
            "users",
            meta_a3,
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
        sa.Table(
            "email_addresses",
            meta_a3,
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
        sa.Table(
            "password_credentials",
            meta_a3,
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
            sa.Column(
                "password_updated_at", sa.DateTime(timezone=True), nullable=False
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        sa.Table(
            "sessions",
            meta_a3,
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
        meta_a3.create_all(sync_engine)

        with sync_engine.connect() as conn:
            res = inspect_legacy_schema(conn)
            assert res.state == SchemaState.UNVERSIONED_A3
            assert res.stamp_revision == "0003_add_session_indexes"

        alembic_cfg = get_alembic_config(sync_db_url)
        command.stamp(alembic_cfg, res.stamp_revision)
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


@pytest.mark.asyncio
async def test_migration_adopt_unversioned_current_schema():
    """Test adopting current unmanaged schema created via Base.metadata.create_all()."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "current_unmanaged.db")
        sync_db_url = f"sqlite:///{db_path}"
        sync_engine = create_engine(sync_db_url)

        Base.metadata.create_all(sync_engine)

        with sync_engine.connect() as conn:
            res = inspect_legacy_schema(conn)
            assert res.state == SchemaState.UNVERSIONED_CURRENT
            assert res.stamp_revision == "0004_add_credential_version"

        alembic_cfg = get_alembic_config(sync_db_url)
        command.stamp(alembic_cfg, res.stamp_revision)
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


@pytest.mark.asyncio
async def test_migration_upgrade_from_0002():
    """Test upgrading an Alembic-managed database from 0002 to head adds missing indexes cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "upgrade_0002_test.db")
        sync_db_url = f"sqlite:///{db_path}"

        alembic_cfg = get_alembic_config(sync_db_url)
        command.upgrade(alembic_cfg, "0002_add_password_updated_at")

        sync_engine = create_engine(sync_db_url)
        with sync_engine.connect() as conn:
            res = inspect_legacy_schema(conn)
            assert res.state == SchemaState.ALEMBIC_MANAGED

        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


def test_migration_downgrade_and_reupgrade():
    """Test migration reversibility: upgrade head -> downgrade 0002 -> upgrade head -> downgrade base -> upgrade head."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "reversibility_test.db")
        sync_db_url = f"sqlite:///{db_path}"

        alembic_cfg = get_alembic_config(sync_db_url)
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)

        command.downgrade(alembic_cfg, "0002_add_password_updated_at")
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)

        command.downgrade(alembic_cfg, "base")
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


def test_inspect_legacy_schema_outcomes():
    """Test inspect_legacy_schema across valid, alembic-managed, and invalid schema states."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "inspect_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        engine = create_engine(sync_db_url)

        # 1. Empty database -> UNKNOWN
        with engine.connect() as conn:
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN

        # 2. Partial tables -> UNKNOWN
        with engine.connect() as conn:
            conn.execute(
                text(
                    "CREATE TABLE users (id CHAR(36) PRIMARY KEY, is_active BOOLEAN NOT NULL DEFAULT 1, is_superuser BOOLEAN NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)"
                )
            )
            conn.commit()
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN

        # 3. Corrupt types -> UNKNOWN
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
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN

        # 4. Unknown Alembic revision -> UNKNOWN
        with engine.connect() as conn:
            conn.execute(
                text(
                    "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
                )
            )
            conn.execute(
                text("INSERT INTO alembic_version VALUES ('9999_unknown_revision')")
            )
            conn.commit()
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN

        # 5. Multiple revision rows in alembic_version -> UNKNOWN
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM alembic_version"))
            conn.execute(
                text("INSERT INTO alembic_version VALUES ('0001_initial_schema')")
            )
            # Add second version row without PK restriction on test table
            conn.execute(text("DROP TABLE alembic_version"))
            conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
            conn.execute(
                text("INSERT INTO alembic_version VALUES ('0001_initial_schema')")
            )
            conn.execute(
                text(
                    "INSERT INTO alembic_version VALUES ('0002_add_password_updated_at')"
                )
            )
            conn.commit()
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN

        # 6. Alembic version table present with 4 junk tables -> UNKNOWN
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE alembic_version"))
            conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
            conn.execute(
                text(
                    "INSERT INTO alembic_version VALUES ('0004_add_credential_version')"
                )
            )
            conn.execute(text("DROP TABLE users"))
            conn.execute(text("DROP TABLE email_addresses"))
            conn.execute(text("DROP TABLE password_credentials"))
            conn.execute(text("DROP TABLE sessions"))
            # Create junk tables with wrong schema
            conn.execute(text("CREATE TABLE users (junk_col TEXT)"))
            conn.execute(text("CREATE TABLE email_addresses (junk_col TEXT)"))
            conn.execute(text("CREATE TABLE password_credentials (junk_col TEXT)"))
            conn.execute(text("CREATE TABLE sessions (junk_col TEXT)"))
            conn.commit()
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN

        # 7. Check constraint with non-positive predicate (e.g. <= 0) -> UNKNOWN
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
            conn.execute(text("DROP TABLE users"))
            conn.execute(text("DROP TABLE email_addresses"))
            conn.execute(text("DROP TABLE password_credentials"))
            conn.execute(text("DROP TABLE sessions"))
            conn.execute(
                text(
                    "CREATE TABLE users (id CHAR(36) PRIMARY KEY, is_active BOOLEAN NOT NULL DEFAULT 1, is_superuser BOOLEAN NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)"
                )
            )
            conn.execute(
                text(
                    "CREATE TABLE email_addresses (id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL REFERENCES users(id), email VARCHAR(320) NOT NULL UNIQUE, is_verified BOOLEAN NOT NULL DEFAULT 0, is_primary BOOLEAN NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL)"
                )
            )
            conn.execute(
                text(
                    "CREATE TABLE sessions (id VARCHAR(64) PRIMARY KEY, user_id CHAR(36) NOT NULL REFERENCES users(id), created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, ip_address VARCHAR(45), user_agent VARCHAR(512))"
                )
            )
            conn.execute(text("CREATE INDEX ix_sessions_user_id ON sessions(user_id)"))
            conn.execute(
                text("CREATE INDEX ix_sessions_expires_at ON sessions(expires_at)")
            )
            # password_credentials with bad check constraint <= 0
            conn.execute(
                text(
                    "CREATE TABLE password_credentials (id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL UNIQUE REFERENCES users(id), hashed_password VARCHAR(1024) NOT NULL, password_updated_at TIMESTAMP NOT NULL, credential_version INTEGER NOT NULL DEFAULT 1, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, CONSTRAINT ck_bad CHECK (credential_version <= 0))"
                )
            )
            conn.commit()
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN

        # 8. NUMERIC column type for credential_version -> UNKNOWN
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE password_credentials"))
            conn.execute(
                text(
                    "CREATE TABLE password_credentials (id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL UNIQUE REFERENCES users(id), hashed_password VARCHAR(1024) NOT NULL, password_updated_at TIMESTAMP NOT NULL, credential_version NUMERIC(10, 0) NOT NULL DEFAULT 1, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, CONSTRAINT ck_password_credentials_credential_version_positive CHECK (credential_version >= 1))"
                )
            )
            conn.commit()
            assert inspect_legacy_schema(conn).state == SchemaState.UNKNOWN


def test_get_alembic_config_helper_percent_escaping():
    test_url = "postgresql+asyncpg://user:p%25ss@localhost:5432/test_db%25"
    config = get_alembic_config(test_url)
    assert config.get_main_option("sqlalchemy.url") == test_url


def test_env_py_loads_database_url_from_env(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "env_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        monkeypatch.setenv("FASTAPI_ACCOUNTS_DATABASE_URL", sync_db_url)
        alembic_cfg = get_alembic_config()
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


def test_migration_0004_rejects_pre_existing_drift():
    """Verify that upgrading a managed database from 0003 to 0004 fails closed if credential_version column already exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "drift_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        alembic_cfg = get_alembic_config(sync_db_url)

        # Upgrade to 0003
        command.upgrade(alembic_cfg, "0003_add_session_indexes")

        # Manually add credential_version column out-of-band to simulate schema drift
        engine = create_engine(sync_db_url)
        with engine.connect() as conn:
            conn.execute(
                text(
                    "ALTER TABLE password_credentials ADD COLUMN credential_version INTEGER DEFAULT 1"
                )
            )
            conn.commit()

        # Upgrading to head (0004) must fail closed with RuntimeError
        with pytest.raises(RuntimeError, match="Schema drift detected"):
            command.upgrade(alembic_cfg, "head")
