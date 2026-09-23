"""Alembic migrations package for FastAPI Accounts."""

from __future__ import annotations

import importlib.resources
from typing import TYPE_CHECKING

from fastapi_accounts.migrations.legacy import (
    SchemaInspectionResult,
    SchemaState,
)

if TYPE_CHECKING:
    from alembic.config import Config
    from sqlalchemy.engine import Connection
    from sqlalchemy.ext.asyncio import AsyncConnection


def get_migrations_directory() -> str:
    """Return the absolute filesystem path to the packaged Alembic migrations directory."""
    return str(importlib.resources.files("fastapi_accounts").joinpath("migrations"))


def get_alembic_config(database_url: str | None = None) -> Config:
    """Construct an Alembic Config instance pointing to the packaged migrations.

    Args:
        database_url: Optional database connection URL (e.g. "sqlite:///./accounts.db").
                      Percent signs (%) will be escaped to "%%" to prevent ConfigParser
                      interpolation errors.
    """
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", get_migrations_directory())
    if database_url is not None:
        # Escape percent signs so configparser does not treat them as interpolation keys
        escaped_url = database_url.replace("%", "%%")
        config.set_main_option("sqlalchemy.url", escaped_url)
    return config


def inspect_legacy_schema(connection: Connection) -> SchemaInspectionResult:
    """Inspect an existing database schema and classify it."""
    from fastapi_accounts.migrations.legacy import inspect_legacy_schema as _inspect

    return _inspect(connection)


async def async_inspect_legacy_schema(
    connection: AsyncConnection,
) -> SchemaInspectionResult:
    """Async wrapper for legacy schema inspection."""
    from fastapi_accounts.migrations.legacy import (
        async_inspect_legacy_schema as _async_inspect,
    )

    return await _async_inspect(connection)


def normalize_legacy_revision(connection: Connection) -> bool:
    """Normalize legacy 35-character revision '0005_add_session_credential_version' to '0005_add_session_cred_version'.

    Executes within the connection's active transaction context.
    Returns True if a legacy revision row was updated, False otherwise.
    """
    import sqlalchemy as sa

    inspector = sa.inspect(connection)
    if "alembic_version" not in inspector.get_table_names():
        return False
    res = connection.execute(
        sa.text(
            "UPDATE alembic_version "
            "SET version_num = '0005_add_session_cred_version' "
            "WHERE version_num = '0005_add_session_credential_version'"
        )
    )
    count = res.rowcount if hasattr(res, "rowcount") else 0
    return bool(count and count > 0)


__all__ = [
    "SchemaInspectionResult",
    "SchemaState",
    "async_inspect_legacy_schema",
    "get_alembic_config",
    "get_migrations_directory",
    "inspect_legacy_schema",
    "normalize_legacy_revision",
]
