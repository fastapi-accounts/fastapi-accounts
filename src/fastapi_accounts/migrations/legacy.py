"""Legacy schema verification and adoption helpers for FastAPI Accounts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection
    from sqlalchemy.ext.asyncio import AsyncConnection


KNOWN_REVISIONS = {
    "0001_initial_schema",
    "0002_add_password_updated_at",
    "0003_add_session_indexes",
    "0004_add_credential_version",
}


class SchemaState(str, Enum):
    UNVERSIONED_A2 = "unversioned_a2"
    UNVERSIONED_A3 = "unversioned_a3"
    UNVERSIONED_CURRENT = "unversioned_current"
    ALEMBIC_MANAGED = "alembic_managed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SchemaInspectionResult:
    state: SchemaState
    stamp_revision: str | None = None
    target_revision: str = "head"
    details: dict[str, Any] = field(default_factory=dict)


def _is_bool_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    return "BOOL" in t or t.startswith(("INTEGER", "TINYINT", "INT"))


def _is_datetime_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    return "TIMESTAMP" in t or "DATETIME" in t or "TIME" in t


def _is_string_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    return any(k in t for k in ("CHAR", "VARCHAR", "STRING", "TEXT", "UUID"))


def _is_int_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    return "INT" in t or "INTEGER" in t or "NUMERIC" in t


def inspect_legacy_schema(connection: Connection) -> SchemaInspectionResult:
    """Inspect an existing database schema and classify it strictly.

    Returns:
        SchemaInspectionResult with state in SchemaState (UNVERSIONED_A2, UNVERSIONED_A3,
        UNVERSIONED_CURRENT, ALEMBIC_MANAGED, UNKNOWN) and recommended stamp_revision.
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
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"error": "Missing required tables", "found": list(tables)},
            )

        # 1. Check if database is already managed by Alembic
        if "alembic_version" in tables:
            try:
                res = connection.execute(
                    sa.text("SELECT version_num FROM alembic_version")
                )
                version_rows = [row[0] for row in res.fetchall()]
                current_rev = version_rows[0] if version_rows else None
                if not current_rev or current_rev not in KNOWN_REVISIONS:
                    return SchemaInspectionResult(
                        state=SchemaState.UNKNOWN,
                        details={
                            "error": f"Unknown or empty alembic revision: {current_rev}"
                        },
                    )
                return SchemaInspectionResult(
                    state=SchemaState.ALEMBIC_MANAGED,
                    stamp_revision=None,
                    target_revision="head",
                    details={"alembic_managed": True, "current_revision": current_rev},
                )
            except Exception as e:
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={"error": f"Failed querying alembic_version: {e}"},
                )

        # 2. Inspect users table
        user_cols = {c["name"]: c for c in inspector.get_columns("users")}
        req_user_cols = {"id", "is_active", "is_superuser", "created_at", "updated_at"}
        if not req_user_cols.issubset(user_cols.keys()):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "users", "error": "Missing columns"},
            )
        for col_name in req_user_cols:
            if user_cols[col_name]["nullable"] is not False:
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "users",
                        "error": f"Column {col_name} is nullable",
                    },
                )
        if not _is_string_type(user_cols["id"]["type"]):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "users", "error": "Invalid id type"},
            )
        if not _is_bool_type(user_cols["is_active"]["type"]) or not _is_bool_type(
            user_cols["is_superuser"]["type"]
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "users", "error": "Invalid boolean types"},
            )
        if not _is_datetime_type(
            user_cols["created_at"]["type"]
        ) or not _is_datetime_type(user_cols["updated_at"]["type"]):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "users", "error": "Invalid timestamp types"},
            )
        user_pk = inspector.get_pk_constraint("users")
        if not user_pk or "id" not in user_pk.get("constrained_columns", []):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "users", "error": "Missing primary key"},
            )

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
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "email_addresses", "error": "Missing columns"},
            )
        for col_name in req_email_cols:
            if email_cols[col_name]["nullable"] is not False:
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "email_addresses",
                        "error": f"Column {col_name} is nullable",
                    },
                )
        if (
            not _is_string_type(email_cols["id"]["type"])
            or not _is_string_type(email_cols["user_id"]["type"])
            or not _is_string_type(email_cols["email"]["type"])
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "email_addresses",
                    "error": "Invalid string column types",
                },
            )
        if not _is_bool_type(email_cols["is_verified"]["type"]) or not _is_bool_type(
            email_cols["is_primary"]["type"]
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "email_addresses", "error": "Invalid boolean types"},
            )
        if not _is_datetime_type(email_cols["created_at"]["type"]):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "email_addresses", "error": "Invalid timestamp type"},
            )
        email_pk = inspector.get_pk_constraint("email_addresses")
        if not email_pk or "id" not in email_pk.get("constrained_columns", []):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "email_addresses", "error": "Missing primary key"},
            )
        email_fks = inspector.get_foreign_keys("email_addresses")
        if not any(
            fk.get("referred_table") == "users"
            and "user_id" in fk.get("constrained_columns", [])
            for fk in email_fks
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "email_addresses",
                    "error": "Missing foreign key to users",
                },
            )
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
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "email_addresses",
                    "error": "Missing unique index on email",
                },
            )

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
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "sessions", "error": "Missing columns"},
            )
        for col_name in ("id", "user_id", "created_at", "expires_at"):
            if session_cols[col_name]["nullable"] is not False:
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "sessions",
                        "error": f"Column {col_name} is nullable",
                    },
                )
        if not _is_string_type(session_cols["id"]["type"]) or not _is_string_type(
            session_cols["user_id"]["type"]
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "sessions", "error": "Invalid string column types"},
            )
        if not _is_datetime_type(
            session_cols["created_at"]["type"]
        ) or not _is_datetime_type(session_cols["expires_at"]["type"]):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "sessions", "error": "Invalid timestamp types"},
            )
        session_pk = inspector.get_pk_constraint("sessions")
        if not session_pk or "id" not in session_pk.get("constrained_columns", []):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "sessions", "error": "Missing primary key"},
            )
        session_fks = inspector.get_foreign_keys("sessions")
        if not any(
            fk.get("referred_table") == "users"
            and "user_id" in fk.get("constrained_columns", [])
            for fk in session_fks
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "sessions", "error": "Missing foreign key to users"},
            )
        session_indexes = inspector.get_indexes("sessions")
        has_user_idx = any(
            "user_id" in idx.get("column_names", []) for idx in session_indexes
        )
        has_expires_idx = any(
            "expires_at" in idx.get("column_names", []) for idx in session_indexes
        )
        if not (has_user_idx and has_expires_idx):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "sessions", "error": "Missing session indexes"},
            )

        # 5. Inspect password_credentials table
        cred_cols = {
            c["name"]: c for c in inspector.get_columns("password_credentials")
        }
        req_cred_cols = {"id", "user_id", "hashed_password", "created_at", "updated_at"}
        if not req_cred_cols.issubset(cred_cols.keys()):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "password_credentials", "error": "Missing columns"},
            )
        for col_name in req_cred_cols:
            if cred_cols[col_name]["nullable"] is not False:
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "password_credentials",
                        "error": f"Column {col_name} is nullable",
                    },
                )
        if (
            not _is_string_type(cred_cols["id"]["type"])
            or not _is_string_type(cred_cols["user_id"]["type"])
            or not _is_string_type(cred_cols["hashed_password"]["type"])
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "password_credentials",
                    "error": "Invalid string column types",
                },
            )
        if not _is_datetime_type(
            cred_cols["created_at"]["type"]
        ) or not _is_datetime_type(cred_cols["updated_at"]["type"]):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "password_credentials",
                    "error": "Invalid timestamp types",
                },
            )
        cred_pk = inspector.get_pk_constraint("password_credentials")
        if not cred_pk or "id" not in cred_pk.get("constrained_columns", []):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "password_credentials",
                    "error": "Missing primary key",
                },
            )
        cred_fks = inspector.get_foreign_keys("password_credentials")
        if not any(
            fk.get("referred_table") == "users"
            and "user_id" in fk.get("constrained_columns", [])
            for fk in cred_fks
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "password_credentials",
                    "error": "Missing foreign key to users",
                },
            )
        cred_uqs = inspector.get_unique_constraints("password_credentials")
        cred_idxs = inspector.get_indexes("password_credentials")
        has_unique_user = any(
            "user_id" in uq.get("column_names", []) for uq in cred_uqs
        ) or any(
            idx.get("unique") and "user_id" in idx.get("column_names", [])
            for idx in cred_idxs
        )
        if not has_unique_user:
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "password_credentials",
                    "error": "Missing unique index on user_id",
                },
            )

        # Distinguish unmanaged versions: UNVERSIONED_A2, UNVERSIONED_A3, UNVERSIONED_CURRENT
        if "credential_version" in cred_cols:
            cred_v_col = cred_cols["credential_version"]
            if cred_v_col["nullable"] is not False or not _is_int_type(
                cred_v_col["type"]
            ):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "password_credentials",
                        "error": "Invalid credential_version column",
                    },
                )
            if "password_updated_at" not in cred_cols:
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "password_credentials",
                        "error": "Missing password_updated_at on current schema",
                    },
                )
            return SchemaInspectionResult(
                state=SchemaState.UNVERSIONED_CURRENT,
                stamp_revision="0004_add_credential_version",
                target_revision="head",
            )
        elif "password_updated_at" in cred_cols:
            pwd_col = cred_cols["password_updated_at"]
            if pwd_col["nullable"] is not False or not _is_datetime_type(
                pwd_col["type"]
            ):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "password_credentials",
                        "error": "Invalid password_updated_at column",
                    },
                )
            return SchemaInspectionResult(
                state=SchemaState.UNVERSIONED_A3,
                stamp_revision="0003_add_session_indexes",
                target_revision="head",
            )
        else:
            return SchemaInspectionResult(
                state=SchemaState.UNVERSIONED_A2,
                stamp_revision="0001_initial_schema",
                target_revision="head",
            )

    except (
        SQLAlchemyError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        AttributeError,
    ) as e:
        return SchemaInspectionResult(
            state=SchemaState.UNKNOWN, details={"exception": str(e)}
        )


async def async_inspect_legacy_schema(
    connection: AsyncConnection,
) -> SchemaInspectionResult:
    """Async wrapper around inspect_legacy_schema running through run_sync."""
    return await connection.run_sync(inspect_legacy_schema)
