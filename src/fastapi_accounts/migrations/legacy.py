"""Legacy schema verification and adoption helpers for FastAPI Accounts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection
    from sqlalchemy.ext.asyncio import AsyncConnection


def _is_bool_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    return "BOOL" in t or t.startswith(("INTEGER", "TINYINT", "INT"))


def _is_datetime_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    return "TIMESTAMP" in t or "DATETIME" in t or "TIME" in t


def _is_string_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    return any(k in t for k in ("CHAR", "VARCHAR", "STRING", "TEXT", "UUID"))


def inspect_legacy_schema(connection: Connection) -> str:
    """Inspect an existing database schema and classify it.

    Returns:
        "alembic_managed": If the database is already tracked by Alembic (alembic_version table exists).
        "v0.1.0a2": If the schema strictly matches the unmanaged baseline v0.1.0a2 model structure (missing password_updated_at).
        "v0.1.0a3": If the schema strictly matches the unmanaged v0.1.0a3+ model structure (including password_updated_at).
        "unrecognized": If required tables, columns, constraints, foreign keys, or indexes are missing, corrupt, or invalid.
    """
    try:
        inspector = sa.inspect(connection)
        tables = set(inspector.get_table_names())

        # 1. Check if database is already managed by Alembic
        if "alembic_version" in tables:
            return "alembic_managed"

        required_tables = {
            "users",
            "email_addresses",
            "password_credentials",
            "sessions",
        }
        if not required_tables.issubset(tables):
            return "unrecognized"

        # 2. Inspect users table
        user_cols = {c["name"]: c for c in inspector.get_columns("users")}
        req_user_cols = {"id", "is_active", "is_superuser", "created_at", "updated_at"}
        if not req_user_cols.issubset(user_cols.keys()):
            return "unrecognized"
        for col_name in req_user_cols:
            if user_cols[col_name]["nullable"] is not False:
                return "unrecognized"
        if not _is_string_type(user_cols["id"]["type"]):
            return "unrecognized"
        if not _is_bool_type(user_cols["is_active"]["type"]) or not _is_bool_type(
            user_cols["is_superuser"]["type"]
        ):
            return "unrecognized"
        if not _is_datetime_type(
            user_cols["created_at"]["type"]
        ) or not _is_datetime_type(user_cols["updated_at"]["type"]):
            return "unrecognized"
        user_pk = inspector.get_pk_constraint("users")
        if not user_pk or "id" not in user_pk.get("constrained_columns", []):
            return "unrecognized"

        # 3. Inspect email_addresses table
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
        for col_name in req_email_cols:
            if email_cols[col_name]["nullable"] is not False:
                return "unrecognized"
        if (
            not _is_string_type(email_cols["id"]["type"])
            or not _is_string_type(email_cols["user_id"]["type"])
            or not _is_string_type(email_cols["email"]["type"])
        ):
            return "unrecognized"
        if not _is_bool_type(email_cols["is_verified"]["type"]) or not _is_bool_type(
            email_cols["is_primary"]["type"]
        ):
            return "unrecognized"
        if not _is_datetime_type(email_cols["created_at"]["type"]):
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
        # Validate unique constraint/index on email
        email_uqs = inspector.get_unique_constraints("email_addresses")
        email_idxs = inspector.get_indexes("email_addresses")
        has_unique_email = any(
            "email" in uq.get("column_names", []) for uq in email_uqs
        ) or any(
            idx.get("unique") and "email" in idx.get("column_names", [])
            for idx in email_idxs
        )
        if not has_unique_email:
            return "unrecognized"

        # 4. Inspect sessions table
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
        for col_name in ("id", "user_id", "created_at", "expires_at"):
            if session_cols[col_name]["nullable"] is not False:
                return "unrecognized"
        if not _is_string_type(session_cols["id"]["type"]) or not _is_string_type(
            session_cols["user_id"]["type"]
        ):
            return "unrecognized"
        if not _is_datetime_type(
            session_cols["created_at"]["type"]
        ) or not _is_datetime_type(session_cols["expires_at"]["type"]):
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
        # Validate session indexes exist for both historical create_all schemas
        session_indexes = inspector.get_indexes("sessions")
        has_user_idx = any(
            "user_id" in idx.get("column_names", []) for idx in session_indexes
        )
        has_expires_idx = any(
            "expires_at" in idx.get("column_names", []) for idx in session_indexes
        )
        if not (has_user_idx and has_expires_idx):
            return "unrecognized"

        # 5. Inspect password_credentials table
        cred_cols = {
            c["name"]: c for c in inspector.get_columns("password_credentials")
        }
        req_cred_cols = {"id", "user_id", "hashed_password", "created_at", "updated_at"}
        if not req_cred_cols.issubset(cred_cols.keys()):
            return "unrecognized"
        for col_name in req_cred_cols:
            if cred_cols[col_name]["nullable"] is not False:
                return "unrecognized"
        if (
            not _is_string_type(cred_cols["id"]["type"])
            or not _is_string_type(cred_cols["user_id"]["type"])
            or not _is_string_type(cred_cols["hashed_password"]["type"])
        ):
            return "unrecognized"
        if not _is_datetime_type(
            cred_cols["created_at"]["type"]
        ) or not _is_datetime_type(cred_cols["updated_at"]["type"]):
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
        # Validate unique constraint/index on user_id
        cred_uqs = inspector.get_unique_constraints("password_credentials")
        cred_idxs = inspector.get_indexes("password_credentials")
        has_unique_user = any(
            "user_id" in uq.get("column_names", []) for uq in cred_uqs
        ) or any(
            idx.get("unique") and "user_id" in idx.get("column_names", [])
            for idx in cred_idxs
        )
        if not has_unique_user:
            return "unrecognized"

        # Distinguish v0.1.0a2 vs v0.1.0a3 based on password_updated_at presence & type
        if "password_updated_at" not in cred_cols:
            return "v0.1.0a2"
        else:
            pwd_col = cred_cols["password_updated_at"]
            if pwd_col["nullable"] is not False or not _is_datetime_type(
                pwd_col["type"]
            ):
                return "unrecognized"
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
