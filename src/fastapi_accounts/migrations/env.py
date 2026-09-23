import asyncio
import logging
import os
from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from fastapi_accounts.models.default import Base

logger = logging.getLogger("fastapi_accounts.migrations")

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_database_url() -> str:
    """Resolve database URL from config or environment variables."""
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        url = (
            os.environ.get("FASTAPI_ACCOUNTS_DATABASE_URL")
            or os.environ.get("DATABASE_URL")
            or ""
        )
    return url


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""
    url = get_database_url()
    if not url:
        raise ValueError(
            "No database URL configured. Specify 'sqlalchemy.url' in alembic.ini "
            "or set the FASTAPI_ACCOUNTS_DATABASE_URL / DATABASE_URL environment variable."
        )
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
    )

    is_mutating = "destination_rev" in context.get_context().opts

    with context.begin_transaction():
        if is_mutating and not context.is_offline_mode():
            try:
                inspector = sa.inspect(connection)
                if "alembic_version" in inspector.get_table_names():
                    connection.execute(
                        sa.text(
                            "UPDATE alembic_version "
                            "SET version_num = '0005_add_session_cred_version' "
                            "WHERE version_num = '0005_add_session_credential_version'"
                        )
                    )
            except Exception as e:
                logger.debug("Legacy revision normalization skipped: %s", e)

        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in online mode with async engine."""
    url = get_database_url()
    section = dict(config.get_section(config.config_ini_section, {}))
    if url:
        section["sqlalchemy.url"] = url
    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.begin() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in online mode."""
    connectable = config.attributes.get("connection", None)

    if connectable is not None:
        do_run_migrations(connectable)
        return

    url = get_database_url()
    if not url:
        raise ValueError(
            "No database URL configured. Specify 'sqlalchemy.url' in alembic.ini "
            "or set the FASTAPI_ACCOUNTS_DATABASE_URL / DATABASE_URL environment variable."
        )

    if "+aiosqlite" in url or "+asyncpg" in url:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as pool_exec:
                pool_exec.submit(asyncio.run, run_async_migrations()).result()
        else:
            asyncio.run(run_async_migrations())
    else:
        section = dict(config.get_section(config.config_ini_section, {}))
        section["sqlalchemy.url"] = url
        sync_engine = engine_from_config(
            section,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
        with sync_engine.begin() as connection:
            do_run_migrations(connection)
        sync_engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
