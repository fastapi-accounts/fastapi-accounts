"""Legacy schema verification and adoption helpers for FastAPI Accounts."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection
    from sqlalchemy.ext.asyncio import AsyncConnection

logger = logging.getLogger("fastapi_accounts.migrations.legacy")

KNOWN_REVISIONS = {
    "0001_initial_schema",
    "0002_add_password_updated_at",
    "0003_add_session_indexes",
    "0004_add_credential_version",
    "0005_add_session_credential_version",
}


class SchemaState(str, Enum):
    UNVERSIONED_A2 = "unversioned_a2"
    UNVERSIONED_A3 = "unversioned_a3"
    UNVERSIONED_A4 = "unversioned_a4"
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
    if t.startswith("TIME") and not t.startswith("TIMESTAMP"):
        return False
    return "TIMESTAMP" in t or "DATETIME" in t


def _is_string_type(
    col_type: Any, min_length: int | None = None, allow_uuid: bool = False
) -> bool:
    t = str(col_type).upper()
    valid_keywords: tuple[str, ...] = (
        ("CHAR", "VARCHAR", "STRING", "TEXT", "UUID")
        if allow_uuid
        else ("CHAR", "VARCHAR", "STRING", "TEXT")
    )
    if not any(k in t for k in valid_keywords):
        return False
    if min_length is not None and not (allow_uuid and "UUID" in t):
        length = getattr(col_type, "length", None)
        if length is not None and length < min_length:
            return False
        m = re.search(r"\((\d+)\)", t)
        if m:
            val = int(m.group(1))
            if val < min_length:
                return False
    return True


def _is_int_type(col_type: Any) -> bool:
    t = str(col_type).upper()
    if any(bad in t for bad in ("NUMERIC", "DECIMAL", "FLOAT", "REAL", "DOUBLE")):
        return False
    return any(k in t for k in ("INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT"))


def _normalize_predicate(sqltext: str) -> str:
    """Normalize SQL constraint text by stripping quotes, whitespace, and wrapping parens."""
    s = sqltext.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        matched = False
        for i, c in enumerate(s):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and i == len(s) - 1:
                    matched = True
                    break
                elif depth == 0:
                    break
        if matched:
            s = s[1:-1].strip()
        else:
            break
    s = s.replace('"', "").replace("`", "").replace("'", "")
    s = re.sub(r"\s+", "", s).lower()
    return s


def _is_valid_positive_cred_v_predicate(sqltext: str) -> bool:
    if not sqltext:
        return False
    norm = _normalize_predicate(sqltext)
    if any(forbidden in norm for forbidden in ("or", "and", "1=1", "true", "<=", "<")):
        return False
    return norm in ("credential_version>=1", "credential_version>0")


def _extract_sqlite_check_predicates(table_sql: str) -> list[str]:
    checks = []
    pattern = re.compile(r"\bCHECK\s*\(", re.IGNORECASE)
    for m in pattern.finditer(table_sql):
        start = m.end() - 1
        depth = 0
        end = -1
        for i in range(start, len(table_sql)):
            if table_sql[i] == "(":
                depth += 1
            elif table_sql[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end != -1:
            expr = table_sql[start + 1 : end]
            checks.append(expr)
    return checks


def _has_positive_credential_version_check(
    connection: Connection, inspector: Any, table_name: str = "password_credentials"
) -> bool:
    # 1. Try inspector get_check_constraints
    try:
        cks = inspector.get_check_constraints(table_name)
        for ck in cks or []:
            sqltext = str(ck.get("sqltext") or "").strip()
            if sqltext and _is_valid_positive_cred_v_predicate(sqltext):
                return True
    except (NotImplementedError, AttributeError, SQLAlchemyError) as e:
        logger.debug("Check constraint reflection unavailable: %s", e)

    # 2. Check dialect-specific sqlite_master DDL if SQLite
    try:
        if connection.dialect.name == "sqlite":
            res = connection.execute(
                sa.text(
                    f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table_name}'"
                )
            ).scalar()
            if res:
                for expr in _extract_sqlite_check_predicates(str(res)):
                    if _is_valid_positive_cred_v_predicate(expr):
                        return True
    except SQLAlchemyError as e:
        logger.debug("sqlite_master DDL query unavailable: %s", e)

    return False


def _has_fk_to_users_id(fks: Any, local_col: str = "user_id") -> bool:
    for fk in fks or []:
        if (
            fk.get("referred_table") == "users"
            and list(fk.get("constrained_columns") or []) == [local_col]
            and list(fk.get("referred_columns") or []) == ["id"]
        ):
            return True
    return False


def inspect_legacy_schema(connection: Connection) -> SchemaInspectionResult:
    """Inspect an existing database schema and classify it strictly.

    Returns:
        SchemaInspectionResult with state in SchemaState (UNVERSIONED_A2, UNVERSIONED_A3,
        UNVERSIONED_A4, UNVERSIONED_CURRENT, ALEMBIC_MANAGED, UNKNOWN) and recommended stamp_revision.
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

        # 1. Inspect users table
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
        if not _is_string_type(user_cols["id"]["type"], min_length=32, allow_uuid=True):
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
        if not user_pk or list(user_pk.get("constrained_columns") or []) != ["id"]:
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"table": "users", "error": "Missing or invalid primary key"},
            )

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
            not _is_string_type(
                email_cols["id"]["type"], min_length=32, allow_uuid=True
            )
            or not _is_string_type(
                email_cols["user_id"]["type"], min_length=32, allow_uuid=True
            )
            or not _is_string_type(
                email_cols["email"]["type"], min_length=320, allow_uuid=False
            )
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
        if not email_pk or list(email_pk.get("constrained_columns") or []) != ["id"]:
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "email_addresses",
                    "error": "Missing or invalid primary key",
                },
            )
        email_fks = inspector.get_foreign_keys("email_addresses")
        if not _has_fk_to_users_id(email_fks, "user_id"):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "email_addresses",
                    "error": "Missing foreign key to users.id",
                },
            )
        email_uqs = inspector.get_unique_constraints("email_addresses")
        email_idxs = inspector.get_indexes("email_addresses")
        has_unique_email = any(
            uq.get("column_names") == ["email"] for uq in email_uqs
        ) or any(
            idx.get("unique") and idx.get("column_names") == ["email"]
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
        if (
            session_cols["ip_address"]["nullable"] is not True
            or session_cols["user_agent"]["nullable"] is not True
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "sessions",
                    "error": "Optional session columns ip_address and user_agent must be nullable",
                },
            )
        if (
            not _is_string_type(
                session_cols["id"]["type"], min_length=64, allow_uuid=False
            )
            or not _is_string_type(
                session_cols["user_id"]["type"], min_length=32, allow_uuid=True
            )
            or not _is_string_type(
                session_cols["ip_address"]["type"], min_length=45, allow_uuid=False
            )
            or not _is_string_type(
                session_cols["user_agent"]["type"], min_length=512, allow_uuid=False
            )
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
        if not session_pk or list(session_pk.get("constrained_columns") or []) != [
            "id"
        ]:
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "sessions",
                    "error": "Missing or invalid primary key",
                },
            )
        session_fks = inspector.get_foreign_keys("sessions")
        if not _has_fk_to_users_id(session_fks, "user_id"):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "sessions",
                    "error": "Missing foreign key to users.id",
                },
            )
        session_indexes = inspector.get_indexes("sessions")
        has_user_idx = any(
            idx.get("column_names") == ["user_id"] for idx in session_indexes
        )
        has_expires_idx = any(
            idx.get("column_names") == ["expires_at"] for idx in session_indexes
        )

        # 4. Inspect password_credentials table
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
            not _is_string_type(cred_cols["id"]["type"], min_length=32, allow_uuid=True)
            or not _is_string_type(
                cred_cols["user_id"]["type"], min_length=32, allow_uuid=True
            )
            or not _is_string_type(
                cred_cols["hashed_password"]["type"],
                min_length=1024,
                allow_uuid=False,
            )
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
        if not cred_pk or list(cred_pk.get("constrained_columns") or []) != ["id"]:
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "password_credentials",
                    "error": "Missing or invalid primary key",
                },
            )
        cred_fks = inspector.get_foreign_keys("password_credentials")
        if not _has_fk_to_users_id(cred_fks, "user_id"):
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={
                    "table": "password_credentials",
                    "error": "Missing foreign key to users.id",
                },
            )
        cred_uqs = inspector.get_unique_constraints("password_credentials")
        cred_idxs = inspector.get_indexes("password_credentials")
        has_unique_user = any(
            uq.get("column_names") == ["user_id"] for uq in cred_uqs
        ) or any(
            idx.get("unique") and idx.get("column_names") == ["user_id"]
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

        # 5. Check if database is managed by Alembic
        if "alembic_version" in tables:
            try:
                res = connection.execute(
                    sa.text("SELECT version_num FROM alembic_version")
                )
                version_rows = [row[0] for row in res.fetchall()]
                if len(version_rows) != 1:
                    return SchemaInspectionResult(
                        state=SchemaState.UNKNOWN,
                        details={
                            "error": f"Expected exactly 1 alembic_version row, found {len(version_rows)}"
                        },
                    )
                current_rev = version_rows[0]
                if current_rev not in KNOWN_REVISIONS:
                    return SchemaInspectionResult(
                        state=SchemaState.UNKNOWN,
                        details={"error": f"Unknown alembic revision: {current_rev}"},
                    )
                # Verify structural fingerprint matches the claimed revision
                if current_rev == "0005_add_session_credential_version":
                    if (
                        "credential_version" not in cred_cols
                        or "password_updated_at" not in cred_cols
                        or "credential_version" not in session_cols
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0005 revision missing credential_version or password_updated_at columns"
                            },
                        )
                    if cred_cols["credential_version"][
                        "nullable"
                    ] is not False or not _is_int_type(
                        cred_cols["credential_version"]["type"]
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0005 revision invalid password_credentials.credential_version column"
                            },
                        )
                    if cred_cols["password_updated_at"][
                        "nullable"
                    ] is not False or not _is_datetime_type(
                        cred_cols["password_updated_at"]["type"]
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0005 revision invalid password_updated_at column"
                            },
                        )
                    if not _has_positive_credential_version_check(
                        connection, inspector, "password_credentials"
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0005 revision missing positive check constraint on password_credentials.credential_version"
                            },
                        )
                    if session_cols["credential_version"][
                        "nullable"
                    ] is not False or not _is_int_type(
                        session_cols["credential_version"]["type"]
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0005 revision invalid sessions.credential_version column"
                            },
                        )
                    if not _has_positive_credential_version_check(
                        connection, inspector, "sessions"
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0005 revision missing positive check constraint on sessions.credential_version"
                            },
                        )
                    if not (has_user_idx and has_expires_idx):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={"error": "0005 revision missing session indexes"},
                        )
                elif current_rev == "0004_add_credential_version":
                    if (
                        "credential_version" not in cred_cols
                        or "password_updated_at" not in cred_cols
                        or "credential_version" in session_cols
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={"error": "0004 revision structural mismatch"},
                        )
                    if cred_cols["credential_version"][
                        "nullable"
                    ] is not False or not _is_int_type(
                        cred_cols["credential_version"]["type"]
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0004 revision invalid credential_version column"
                            },
                        )
                    if cred_cols["password_updated_at"][
                        "nullable"
                    ] is not False or not _is_datetime_type(
                        cred_cols["password_updated_at"]["type"]
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0004 revision invalid password_updated_at column"
                            },
                        )
                    if not _has_positive_credential_version_check(
                        connection, inspector, "password_credentials"
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0004 revision missing positive check constraint on credential_version"
                            },
                        )
                    if not (has_user_idx and has_expires_idx):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={"error": "0004 revision missing session indexes"},
                        )
                elif current_rev == "0003_add_session_indexes":
                    if (
                        "password_updated_at" not in cred_cols
                        or "credential_version" in cred_cols
                        or "credential_version" in session_cols
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={"error": f"{current_rev} structural mismatch"},
                        )
                    if cred_cols["password_updated_at"][
                        "nullable"
                    ] is not False or not _is_datetime_type(
                        cred_cols["password_updated_at"]["type"]
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": f"{current_rev} invalid password_updated_at column"
                            },
                        )
                    if not (has_user_idx and has_expires_idx):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={"error": f"{current_rev} missing session indexes"},
                        )
                elif current_rev == "0002_add_password_updated_at":
                    if (
                        "password_updated_at" not in cred_cols
                        or "credential_version" in cred_cols
                        or "credential_version" in session_cols
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={"error": f"{current_rev} structural mismatch"},
                        )
                    if cred_cols["password_updated_at"][
                        "nullable"
                    ] is not False or not _is_datetime_type(
                        cred_cols["password_updated_at"]["type"]
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": f"{current_rev} invalid password_updated_at column"
                            },
                        )
                elif current_rev == "0001_initial_schema":
                    if (
                        "password_updated_at" in cred_cols
                        or "credential_version" in cred_cols
                        or "credential_version" in session_cols
                    ):
                        return SchemaInspectionResult(
                            state=SchemaState.UNKNOWN,
                            details={
                                "error": "0001 structural mismatch: extra columns found"
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

        # 6. Unmanaged database classification
        if "credential_version" in session_cols and "credential_version" in cred_cols:
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
            if not _has_positive_credential_version_check(
                connection, inspector, "password_credentials"
            ):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "password_credentials",
                        "error": "Missing credential_version check constraint",
                    },
                )
            sess_v_col = session_cols["credential_version"]
            if sess_v_col["nullable"] is not False or not _is_int_type(
                sess_v_col["type"]
            ):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "sessions",
                        "error": "Invalid credential_version column",
                    },
                )
            if not _has_positive_credential_version_check(
                connection, inspector, "sessions"
            ):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "sessions",
                        "error": "Missing credential_version check constraint on sessions",
                    },
                )
            if not (has_user_idx and has_expires_idx):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={"table": "sessions", "error": "Missing session indexes"},
                )
            return SchemaInspectionResult(
                state=SchemaState.UNVERSIONED_CURRENT,
                stamp_revision="0005_add_session_credential_version",
                target_revision="head",
            )
        elif (
            "credential_version" in cred_cols
            and "credential_version" not in session_cols
        ):
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
                        "error": "Missing password_updated_at on 0004 schema",
                    },
                )
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
            if not _has_positive_credential_version_check(
                connection, inspector, "password_credentials"
            ):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={
                        "table": "password_credentials",
                        "error": "Missing credential_version check constraint",
                    },
                )
            if not (has_user_idx and has_expires_idx):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={"table": "sessions", "error": "Missing session indexes"},
                )
            return SchemaInspectionResult(
                state=SchemaState.UNVERSIONED_A4,
                stamp_revision="0004_add_credential_version",
                target_revision="head",
            )
        elif (
            "password_updated_at" in cred_cols
            and "credential_version" not in cred_cols
            and "credential_version" not in session_cols
        ):
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
            if not (has_user_idx and has_expires_idx):
                return SchemaInspectionResult(
                    state=SchemaState.UNKNOWN,
                    details={"table": "sessions", "error": "Missing session indexes"},
                )
            return SchemaInspectionResult(
                state=SchemaState.UNVERSIONED_A3,
                stamp_revision="0003_add_session_indexes",
                target_revision="head",
            )
        elif (
            "password_updated_at" not in cred_cols
            and "credential_version" not in cred_cols
            and "credential_version" not in session_cols
        ):
            return SchemaInspectionResult(
                state=SchemaState.UNVERSIONED_A2,
                stamp_revision="0001_initial_schema",
                target_revision="head",
            )
        else:
            return SchemaInspectionResult(
                state=SchemaState.UNKNOWN,
                details={"error": "Schema in inconsistent intermediate state"},
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
