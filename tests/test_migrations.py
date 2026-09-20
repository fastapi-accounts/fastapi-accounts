import os
import tempfile
import uuid
from datetime import datetime, timezone

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter


@pytest.mark.asyncio
async def test_migration_fresh_database():
    """Test initializing a completely fresh database with alembic upgrade head."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "fresh_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        async_db_url = f"sqlite+aiosqlite:///{db_path}"

        # 1. Run Alembic upgrade head on an empty database
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", sync_db_url)
        command.upgrade(alembic_cfg, "head")

        # 2. Verify tables and operations work cleanly with SQLAlchemyAdapter
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
async def test_migration_upgrade_from_legacy_schema():
    """Test upgrade from legacy v0.1.0a2 schema without password_updated_at column to v0.1.0a3+."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        async_db_url = f"sqlite+aiosqlite:///{db_path}"

        # 1. Create legacy schema (v0.1.0a2) directly using SQLite sync engine
        sync_engine = create_engine(sync_db_url)
        with sync_engine.connect() as conn:
            # Create users table
            conn.execute(
                text(
                    """
                CREATE TABLE users (
                    id CHAR(36) PRIMARY KEY,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    is_superuser BOOLEAN NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
            """
                )
            )
            # Create email_addresses table
            conn.execute(
                text(
                    """
                CREATE TABLE email_addresses (
                    id CHAR(36) PRIMARY KEY,
                    user_id CHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    email VARCHAR(320) NOT NULL UNIQUE,
                    is_verified BOOLEAN NOT NULL DEFAULT 0,
                    is_primary BOOLEAN NOT NULL DEFAULT 1,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
            """
                )
            )
            # Create legacy password_credentials table WITHOUT password_updated_at
            conn.execute(
                text(
                    """
                CREATE TABLE password_credentials (
                    id CHAR(36) PRIMARY KEY,
                    user_id CHAR(36) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                    hashed_password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
            """
                )
            )
            # Create sessions table
            conn.execute(
                text(
                    """
                CREATE TABLE sessions (
                    id VARCHAR(64) PRIMARY KEY,
                    user_id CHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent VARCHAR(512)
                )
            """
                )
            )

            # Insert legacy user record
            now_iso = datetime.now(timezone.utc).isoformat()
            user_id = "11111111111111111111111111111111"
            conn.execute(
                text(
                    """
                INSERT INTO users (id, is_active, is_superuser, created_at, updated_at)
                VALUES (:id, 1, 0, :now, :now)
            """
                ),
                {"id": user_id, "now": now_iso},
            )
            conn.execute(
                text(
                    """
                INSERT INTO email_addresses (id, user_id, email, is_verified, is_primary, created_at, updated_at)
                VALUES ('22222222222222222222222222222222', :user_id, 'legacy@example.com', 1, 1, :now, :now)
            """
                ),
                {"user_id": user_id, "now": now_iso},
            )
            conn.execute(
                text(
                    """
                INSERT INTO password_credentials (id, user_id, hashed_password, created_at, updated_at)
                VALUES ('33333333333333333333333333333333', :user_id, '$argon2id$mockhash', :now, :now)
            """
                ),
                {"user_id": user_id, "now": now_iso},
            )
            conn.commit()

        # 2. Before migration: querying with current model raises OperationalError (missing password_updated_at)
        adapter_pre = SQLAlchemyAdapter(database_url=async_db_url)
        with pytest.raises(OperationalError, match="no such column"):
            async with adapter_pre.session_maker() as session:
                await adapter_pre.get_password_credential(session, uuid.UUID(user_id))
        await adapter_pre.engine.dispose()

        # 3. Stamp 0001_initial_schema and run Alembic Upgrade to head (0002_add_password_updated_at)
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", sync_db_url)
        command.stamp(alembic_cfg, "0001_initial_schema")
        command.upgrade(alembic_cfg, "head")

        # 4. Post migration: verify column exists and adapter queries successfully without OperationalError
        adapter_post = SQLAlchemyAdapter(database_url=async_db_url)
        async with adapter_post.session_maker() as session:
            user = await adapter_post.get_user_by_email(session, "legacy@example.com")
            assert user is not None
            assert user.password_credential is not None
            # Verify password_updated_at is populated
            assert user.password_credential.password_updated_at is not None

        await adapter_post.engine.dispose()
