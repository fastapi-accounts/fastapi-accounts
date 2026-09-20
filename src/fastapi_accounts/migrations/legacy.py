"""Legacy schema verification and adoption helpers for FastAPI Accounts."""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection
    from sqlalchemy.ext.asyncio import AsyncConnection


def inspect_legacy_schema(connection: Connection) -> str:
    """Inspect an existing database schema and classify it.

    Returns:
        "v0.1.0a2": If the schema matches the baseline v0.1.0a2 model structure (missing password_updated_at).
        "v0.1.0a3": If the schema matches the v0.1.0a3+ model structure (including password_updated_at).
        "unrecognized": If required tables, columns, constraints, or foreign keys are missing or invalid.
    """
    try:
        inspector = sa.inspect(connection)
        tables = set(inspector.get_table_names())

        required_tables = {
            "users",
            "email_addresses",
            "password_credentials",
            "sessions",
        }
        if not required_tables.issubset(tables):
            return "unrecognized"

        # 1. Inspect users table
        user_cols = {c["name"]: c for c in inspector.get_columns("users")}
        req_user_cols = {"id", "is_active", "is_superuser", "created_at", "updated_at"}
        if not req_user_cols.issubset(user_cols.keys()):
            return "unrecognized"
        user_pk = inspector.get_pk_constraint("users")
        if not user_pk or "id" not in user_pk.get("constrained_columns", []):
            return "unrecognized"

        # 2. Inspect email_addresses table
        email_cols = {c["name"]: c for c in inspector.get_columns("email_addresses")}
        req_email_cols = {
            "id",
            "user_id",
            "email",
            "is_verified",
            "is_primary",
            "created_at",
        }
        if not req_email_cols.issubset(email_cols.keys()):
            return "unrecognized"
        email_pk = inspector.get_pk_constraint("email_addresses")
        if not email_pk or "id" not in email_pk.get("constrained_columns", []):
            return "unrecognized"
        email_fks = inspector.get_foreign_keys("email_addresses")
        if not any(
            fk.get("referred_table") == "users"
            and "user_id" in fk.get("constrained_columns", [])
            for fk in email_fks
        ):
            return "unrecognized"

        # 3. Inspect sessions table
        session_cols = {c["name"]: c for c in inspector.get_columns("sessions")}
        req_session_cols = {
            "id",
            "user_id",
            "created_at",
            "expires_at",
            "ip_address",
            "user_agent",
        }
        if not req_session_cols.issubset(session_cols.keys()):
            return "unrecognized"
        session_pk = inspector.get_pk_constraint("sessions")
        if not session_pk or "id" not in session_pk.get("constrained_columns", []):
            return "unrecognized"
        session_fks = inspector.get_foreign_keys("sessions")
        if not any(
            fk.get("referred_table") == "users"
            and "user_id" in fk.get("constrained_columns", [])
            for fk in session_fks
        ):
            return "unrecognized"

        # 4. Inspect password_credentials table
        cred_cols = {
            c["name"]: c for c in inspector.get_columns("password_credentials")
        }
        req_cred_cols = {"id", "user_id", "hashed_password", "created_at", "updated_at"}
        if not req_cred_cols.issubset(cred_cols.keys()):
            return "unrecognized"
        cred_pk = inspector.get_pk_constraint("password_credentials")
        if not cred_pk or "id" not in cred_pk.get("constrained_columns", []):
            return "unrecognized"
        cred_fks = inspector.get_foreign_keys("password_credentials")
        if not any(
            fk.get("referred_table") == "users"
            and "user_id" in fk.get("constrained_columns", [])
            for fk in cred_fks
        ):
            return "unrecognized"

        # Distinguish v0.1.0a2 vs v0.1.0a3 based on password_updated_at presence
        if "password_updated_at" not in cred_cols:
            return "v0.1.0a2"
        else:
            return "v0.1.0a3"

    except (
        SQLAlchemyError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        AttributeError,
    ):
        return "unrecognized"


async def async_inspect_legacy_schema(connection: AsyncConnection) -> str:
    """Async wrapper around inspect_legacy_schema running through run_sync."""
    return await connection.run_sync(inspect_legacy_schema)
