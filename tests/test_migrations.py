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
            assert res.stamp_revision == "0005_add_session_credential_version"

        alembic_cfg = get_alembic_config(sync_db_url)
        command.stamp(alembic_cfg, res.stamp_revision)
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


@pytest.mark.asyncio
async def test_migration_adopt_legacy_a4_schema():
    """Test adopting authentic v0.1.0a4 schema (with password_credentials.credential_version but no sessions.credential_version)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_a4_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        sync_engine = create_engine(sync_db_url)

        alembic_cfg = get_alembic_config(sync_db_url)
        command.upgrade(alembic_cfg, "0004_add_credential_version")

        # Now drop alembic_version table to simulate unmanaged a4 database
        with sync_engine.connect() as conn:
            conn.execute(text("DROP TABLE alembic_version"))
            conn.commit()

            res = inspect_legacy_schema(conn)
            assert res.state == SchemaState.UNVERSIONED_A4
            assert res.stamp_revision == "0004_add_credential_version"

        command.stamp(alembic_cfg, res.stamp_revision)
        command.upgrade(alembic_cfg, "head")
        command.check(alembic_cfg)


@pytest.mark.asyncio
async def test_migration_0005_backfill_and_reversibility():
    """Test upgrading 0004 -> 0005 backfills session credential_version and downgrades cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "backfill_0005.db")
        sync_db_url = f"sqlite:///{db_path}"
        engine = create_engine(sync_db_url)

        alembic_cfg = get_alembic_config(sync_db_url)
        command.upgrade(alembic_cfg, "0004_add_credential_version")

        user1_id = uuid.uuid4()
        user2_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        with engine.connect() as conn:
            conn.execute(
                text(
                    "INSERT INTO users (id, is_active, is_superuser, created_at, updated_at) "
                    "VALUES (:u1, 1, 0, :now, :now), (:u2, 1, 0, :now, :now)"
                ),
                {"u1": str(user1_id), "u2": str(user2_id), "now": now},
            )
            # user 1 has credential_version = 3
            conn.execute(
                text(
                    "INSERT INTO password_credentials (id, user_id, hashed_password, credential_version, password_updated_at, created_at, updated_at) "
                    "VALUES (:cid, :u1, 'hash', 3, :now, :now, :now)"
                ),
                {"cid": str(uuid.uuid4()), "u1": str(user1_id), "now": now},
            )
            # user 2 has no password credentials (e.g. OAuth user)
            # Insert sessions for both
            conn.execute(
                text(
                    "INSERT INTO sessions (id, user_id, created_at, expires_at) "
                    "VALUES ('sess1', :u1, :now, :now), ('sess2', :u2, :now, :now)"
                ),
                {"u1": str(user1_id), "u2": str(user2_id), "now": now},
            )
            conn.commit()

        # Upgrade to 0005
        command.upgrade(alembic_cfg, "0005_add_session_credential_version")
        command.check(alembic_cfg)

        with engine.connect() as conn:
            sess1_v = conn.execute(
                text("SELECT credential_version FROM sessions WHERE id = 'sess1'")
            ).scalar()
            sess2_v = conn.execute(
                text("SELECT credential_version FROM sessions WHERE id = 'sess2'")
            ).scalar()
            assert sess1_v == 3
            assert sess2_v == 1

        # Test downgrade to 0004
        command.downgrade(alembic_cfg, "0004_add_credential_version")
        with engine.connect() as conn:
            cols = {c["name"] for c in sa.inspect(conn).get_columns("sessions")}
            assert "credential_version" not in cols

        # Re-upgrade to head
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
                    "INSERT INTO alembic_version VALUES ('0005_add_session_credential_version')"
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

        # Helper to build canonical metadata clone
        def clone_metadata() -> sa.MetaData:
            m = sa.MetaData()
            for table in Base.metadata.sorted_tables:
                table.to_metadata(m)
            return m

        def set_check_constraint(table: sa.Table, expr: str, name: str) -> None:
            table.c.credential_version.constraints.clear()
            for c in list(table.constraints):
                if isinstance(c, sa.CheckConstraint):
                    table.constraints.remove(c)
            table.append_constraint(sa.CheckConstraint(expr, name=name))

        def replace_fk(table: sa.Table, target_table: str, target_column: str) -> None:
            for constraint in list(table.constraints):
                if isinstance(constraint, sa.ForeignKeyConstraint):
                    table.constraints.remove(constraint)
            table.append_constraint(
                sa.ForeignKeyConstraint(
                    ["user_id"], [f"{target_table}.{target_column}"]
                )
            )

        def set_composite_pk(table: sa.Table, col_name: str) -> None:
            for c in list(table.constraints):
                if isinstance(c, sa.PrimaryKeyConstraint):
                    table.constraints.remove(c)
            table.append_constraint(
                sa.PrimaryKeyConstraint(table.c.id, table.c[col_name])
            )

        def assert_mutation_rejected_both_modes(mut_fn, label: str) -> None:
            # Mode A: Unmanaged schema
            with tempfile.TemporaryDirectory() as td:
                eng = create_engine(f"sqlite:///{td}/unmanaged_{label}.db")
                m = clone_metadata()
                mut_fn(m)
                m.create_all(eng)
                with eng.connect() as conn:
                    res = inspect_legacy_schema(conn)
                    assert res.state == SchemaState.UNKNOWN, (
                        f"Unmanaged mutation {label} expected UNKNOWN, got {res.state}"
                    )
                eng.dispose()

            # Mode B: Managed (0005) schema
            with tempfile.TemporaryDirectory() as td:
                eng = create_engine(f"sqlite:///{td}/managed_{label}.db")
                m = clone_metadata()
                mut_fn(m)
                m.create_all(eng)
                with eng.connect() as conn:
                    conn.execute(
                        text(
                            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
                        )
                    )
                    conn.execute(
                        text(
                            "INSERT INTO alembic_version (version_num) VALUES ('0005_add_session_credential_version')"
                        )
                    )
                    conn.commit()
                    res = inspect_legacy_schema(conn)
                    assert res.state == SchemaState.UNKNOWN, (
                        f"Managed 0005 mutation {label} expected UNKNOWN, got {res.state}"
                    )
                eng.dispose()

        mutations = [
            # 1. Composite primary keys across all 4 tables
            (
                "users_composite_pk",
                lambda m: set_composite_pk(m.tables["users"], "created_at"),
            ),
            (
                "email_composite_pk",
                lambda m: set_composite_pk(m.tables["email_addresses"], "user_id"),
            ),
            (
                "sessions_composite_pk",
                lambda m: set_composite_pk(m.tables["sessions"], "user_id"),
            ),
            (
                "creds_composite_pk",
                lambda m: set_composite_pk(m.tables["password_credentials"], "user_id"),
            ),
            # 2. Check constraints
            (
                "bad_ck_negative",
                lambda m: set_check_constraint(
                    m.tables["password_credentials"],
                    "credential_version <= 0",
                    "ck_bad",
                ),
            ),
            (
                "tautology_ck",
                lambda m: set_check_constraint(
                    m.tables["password_credentials"],
                    "1=1",
                    "ck_password_credentials_credential_version_positive",
                ),
            ),
            # 3. Numeric credential version
            (
                "numeric_cred_v",
                lambda m: setattr(
                    m.tables["password_credentials"].c.credential_version,
                    "type",
                    sa.Numeric(),
                ),
            ),
            # 4. Composite email uniqueness
            (
                "composite_email_unique",
                lambda m: (
                    [
                        m.tables["email_addresses"].indexes.remove(idx)
                        for idx in list(m.tables["email_addresses"].indexes)
                        if idx.unique
                    ],
                    [
                        m.tables["email_addresses"].constraints.remove(c)
                        for c in list(m.tables["email_addresses"].constraints)
                        if isinstance(c, sa.UniqueConstraint)
                    ],
                    sa.Index(
                        "ix_comp_email",
                        m.tables["email_addresses"].c.email,
                        m.tables["email_addresses"].c.user_id,
                        unique=True,
                    ),
                ),
            ),
            # 5. TIME types instead of TIMESTAMP/DATETIME
            (
                "password_updated_at_TIME",
                lambda m: setattr(
                    m.tables["password_credentials"].c.password_updated_at,
                    "type",
                    sa.Time(),
                ),
            ),
            (
                "user_created_at_TIME",
                lambda m: setattr(m.tables["users"].c.created_at, "type", sa.Time()),
            ),
            (
                "email_created_at_TIME",
                lambda m: setattr(
                    m.tables["email_addresses"].c.created_at, "type", sa.Time()
                ),
            ),
            (
                "session_expires_at_TIME",
                lambda m: setattr(m.tables["sessions"].c.expires_at, "type", sa.Time()),
            ),
            # 6. Undersized string contracts
            (
                "user_id_short_string",
                lambda m: setattr(m.tables["users"].c.id, "type", sa.String(1)),
            ),
            (
                "email_id_short_string",
                lambda m: setattr(
                    m.tables["email_addresses"].c.id, "type", sa.String(1)
                ),
            ),
            (
                "email_short_string_1",
                lambda m: setattr(
                    m.tables["email_addresses"].c.email, "type", sa.String(1)
                ),
            ),
            (
                "email_short_string_32",
                lambda m: setattr(
                    m.tables["email_addresses"].c.email, "type", sa.String(32)
                ),
            ),
            (
                "password_hash_short_string_1",
                lambda m: setattr(
                    m.tables["password_credentials"].c.hashed_password,
                    "type",
                    sa.String(1),
                ),
            ),
            (
                "password_hash_short_string_32",
                lambda m: setattr(
                    m.tables["password_credentials"].c.hashed_password,
                    "type",
                    sa.String(32),
                ),
            ),
            (
                "password_hash_short_string_255",
                lambda m: setattr(
                    m.tables["password_credentials"].c.hashed_password,
                    "type",
                    sa.String(255),
                ),
            ),
            (
                "session_id_short_string_32",
                lambda m: setattr(m.tables["sessions"].c.id, "type", sa.String(32)),
            ),
            # 7. Optional session columns invalid types and non-nullable mutations
            (
                "session_ip_integer",
                lambda m: setattr(
                    m.tables["sessions"].c.ip_address, "type", sa.Integer()
                ),
            ),
            (
                "session_ua_integer",
                lambda m: setattr(
                    m.tables["sessions"].c.user_agent, "type", sa.Integer()
                ),
            ),
            (
                "session_ip_not_null",
                lambda m: setattr(m.tables["sessions"].c.ip_address, "nullable", False),
            ),
            (
                "session_ua_not_null",
                lambda m: setattr(m.tables["sessions"].c.user_agent, "nullable", False),
            ),
            # 8. Foreign key targets
            (
                "email_fk_wrong_target",
                lambda m: replace_fk(m.tables["email_addresses"], "users", "is_active"),
            ),
            (
                "session_fk_wrong_target",
                lambda m: replace_fk(m.tables["sessions"], "users", "is_active"),
            ),
            (
                "creds_fk_wrong_target",
                lambda m: replace_fk(
                    m.tables["password_credentials"], "users", "is_active"
                ),
            ),
        ]

        for label, mut_fn in mutations:
            assert_mutation_rejected_both_modes(mut_fn, label)

        # 9. Positive controls: Unbounded TEXT supported across all string columns
        with tempfile.TemporaryDirectory() as td:
            eng = create_engine(f"sqlite:///{td}/text_positive_unmanaged.db")
            m = clone_metadata()
            m.tables["email_addresses"].c.email.type = sa.Text()
            m.tables["password_credentials"].c.hashed_password.type = sa.Text()
            m.tables["sessions"].c.id.type = sa.Text()
            m.tables["sessions"].c.ip_address.type = sa.Text()
            m.tables["sessions"].c.user_agent.type = sa.Text()
            m.create_all(eng)
            with eng.connect() as conn:
                res = inspect_legacy_schema(conn)
                assert res.state == SchemaState.UNVERSIONED_CURRENT
            eng.dispose()

        with tempfile.TemporaryDirectory() as td:
            eng = create_engine(f"sqlite:///{td}/text_positive_managed.db")
            m = clone_metadata()
            m.tables["email_addresses"].c.email.type = sa.Text()
            m.tables["password_credentials"].c.hashed_password.type = sa.Text()
            m.tables["sessions"].c.id.type = sa.Text()
            m.tables["sessions"].c.ip_address.type = sa.Text()
            m.tables["sessions"].c.user_agent.type = sa.Text()
            m.create_all(eng)
            with eng.connect() as conn:
                conn.execute(
                    text(
                        "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
                    )
                )
                conn.execute(
                    text(
                        "INSERT INTO alembic_version (version_num) VALUES ('0005_add_session_credential_version')"
                    )
                )
                conn.commit()
                res = inspect_legacy_schema(conn)
                assert res.state == SchemaState.ALEMBIC_MANAGED
            eng.dispose()


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


def test_migration_0005_rejects_pre_existing_drift():
    """Verify that upgrading a managed database from 0004 to 0005 fails closed if sessions.credential_version column already exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "drift_0005_test.db")
        sync_db_url = f"sqlite:///{db_path}"
        alembic_cfg = get_alembic_config(sync_db_url)

        # Upgrade to 0004
        command.upgrade(alembic_cfg, "0004_add_credential_version")

        # Manually add credential_version column on sessions out-of-band
        engine = create_engine(sync_db_url)
        with engine.connect() as conn:
            conn.execute(
                text(
                    "ALTER TABLE sessions ADD COLUMN credential_version INTEGER DEFAULT 1"
                )
            )
            conn.commit()

        # Upgrading to head (0005) must fail closed with RuntimeError
        with pytest.raises(RuntimeError, match="Schema drift detected"):
            command.upgrade(alembic_cfg, "head")
