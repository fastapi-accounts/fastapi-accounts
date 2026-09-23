# Database Migrations & Legacy Schema Adoption

FastAPI Accounts provides bundled Alembic migrations for its default declarative models, supporting deterministic schema inspection, backward-compatible migration paths, and adoption of unmanaged databases.

---

## 📦 Packaged Migrations Overview

The library ships with migrations located in `fastapi_accounts.migrations`:

| Revision | Description | Max ID Length |
|---|---|---|
| `0001_initial_schema` | Initial tables: `users`, `email_addresses`, `password_credentials`, `sessions` | 19 chars |
| `0002_add_password_updated_at` | Adds `password_updated_at` to `password_credentials` | 27 chars |
| `0003_add_session_indexes` | Adds lookup indexes on `sessions.user_id` and `sessions.expires_at` | 23 chars |
| `0004_add_credential_version` | Adds `credential_version` (CAS protection) to `password_credentials` | 26 chars |
| `0005_add_session_cred_version` | Adds `credential_version` to `sessions` for session revocation tracking | 28 chars |

All migration identifiers are strictly $\le 32$ characters to maintain compatibility with the default `VARCHAR(32)` `alembic_version.version_num` column across PostgreSQL and SQLite.

---

## ⚙️ Configuration & Execution

### 1. Programmatic Migration Execution

You can run migrations programmatically in application startup scripts or CI/CD pipelines using the `get_alembic_config` helper:

```python
from alembic import command
from fastapi_accounts.migrations import get_alembic_config

# Point Alembic directly to packaged migrations for your database URL
config = get_alembic_config("postgresql+asyncpg://user:pass@localhost/dbname")
command.upgrade(config, "head")
```

### 2. Alembic CLI Configuration (`alembic.ini`)

To manage migrations via the standard `alembic` CLI, you can create an `alembic.ini` file referencing the package:

```ini
[alembic]
script_location = fastapi_accounts:migrations
sqlalchemy.url = postgresql+asyncpg://user:pass@localhost/dbname

# Standard logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

To supply the database URL dynamically via environment variables, omit or leave `sqlalchemy.url` blank in `alembic.ini` (since an explicit URL in `alembic.ini` takes precedence), then set `FASTAPI_ACCOUNTS_DATABASE_URL`:

```bash
export FASTAPI_ACCOUNTS_DATABASE_URL="postgresql+asyncpg://user:pass@localhost/dbname"
alembic upgrade head
alembic check
```

> [!NOTE]
> Bundled migrations manage the library's default declarative models (`Base.metadata`). If your application extends models with custom tables or modifies default table names, manage those models within your application's own Alembic migration environment.

---

## 🔍 Schema State Inspection & Adoption

If you have an existing database initialized with earlier pre-release versions (`v0.1.0a2`, `v0.1.0a3`, `v0.1.0a4`) or via `adapter.create_all()`, use `inspect_legacy_schema` to detect your current schema structure and determine the correct migration/stamp strategy.

### Inspecting Schema State

```python
from sqlalchemy import create_engine
from fastapi_accounts.migrations import SchemaState, inspect_legacy_schema

# Use psycopg v3 driver for PostgreSQL
engine = create_engine("postgresql+psycopg://user:pass@localhost/dbname")
with engine.connect() as conn:
    result = inspect_legacy_schema(conn)
    print(f"Detected State: {result.state.value}")
    if result.stamp_revision:
        print(f"Recommended Stamp Revision: {result.stamp_revision}")
```

### Schema State Reference Matrix

| Detected `SchemaState` | Schema Signatures | Recommended Action |
|---|---|---|
| `ALEMBIC_MANAGED` | Database has `alembic_version` table with known revision. | Run `alembic upgrade head` directly. |
| `UNVERSIONED_CURRENT` | Unversioned schema with `sessions.credential_version` and `password_credentials.credential_version`. | `alembic stamp 0005_add_session_cred_version`<br>`alembic upgrade head` |
| `UNVERSIONED_A4` | Contains `password_credentials.credential_version` but lacks `sessions.credential_version`. | `alembic stamp 0004_add_credential_version`<br>`alembic upgrade head` |
| `UNVERSIONED_A3` | Contains `password_credentials.password_updated_at` and session indexes, but lacks `credential_version`. | `alembic stamp 0003_add_session_indexes`<br>`alembic upgrade head` |
| `UNVERSIONED_A2` | Baseline tables exist, but lacks `password_updated_at`. | `alembic stamp 0001_initial_schema`<br>`alembic upgrade head` |
| `UNKNOWN` | Schema has missing required tables, unknown columns, or custom drift. | **Do not stamp.** Inspect table structures for discrepancies. |

> [!TIP]
> For a brand-new, empty database, running `alembic upgrade head` (or `await adapter.create_all()` in development) initializes all tables starting from `0001_initial_schema`.

---

## 🔄 Historical Revision Recovery (`0005_add_session_credential_version`)

In early pre-release builds of `v0.1.0a5`, revision 0005 was temporarily identified as `0005_add_session_credential_version` (35 characters). This exceeded the 32-character limit on PostgreSQL. It was canonically renamed to `0005_add_session_cred_version` (28 characters).

### Behavior of Legacy Stamped Databases

* **Read-Only Commands:** Running read-only commands (`alembic current` or `alembic check`) against a database stamped with `0005_add_session_credential_version` will raise `CommandError: Can't locate revision identified by '0005_add_session_credential_version'` without mutating database state.
* **Automatic Upgrade Normalization:** Running `alembic upgrade head` automatically detects the legacy identifier and safely rewrites it to `0005_add_session_cred_version` inside the migration transaction.
* **Programmatic Normalization:** You can explicitly normalize the version row before running read-only inspection commands using `normalize_legacy_revision`:

```python
from sqlalchemy import create_engine
from fastapi_accounts.migrations import normalize_legacy_revision

engine = create_engine("postgresql+psycopg://user:pass@localhost/dbname")
with engine.begin() as conn:
    updated = normalize_legacy_revision(conn)
    if updated:
        print("Normalized legacy 0005 revision to 0005_add_session_cred_version")
```

---

## 🛠️ Custom Models & Declarative Extensions

If you extend or implement custom declarative models using the mixin classes:

1. **User Model:** Inherit from `UserMixin` (table name `users`).
2. **Email Address Model:** Inherit from `EmailAddressMixin` (table name `email_addresses`).
3. **Password Credential Model:** Inherit from `PasswordCredentialMixin` (table name `password_credentials`).
4. **Session Model:** Inherit from `SessionMixin` (table name `sessions`).

```python
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from fastapi_accounts.models.mixins import (
    EmailAddressMixin,
    PasswordCredentialMixin,
    SessionMixin,
    UserMixin,
)


class Base(DeclarativeBase):
    pass


class User(Base, UserMixin):
    __tablename__ = "users"
    # Custom application fields
    full_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    # Required for the adapter to populate `UserPrincipal.email` and `UserPrincipal.is_verified`
    emails: Mapped[list["EmailAddress"]] = relationship("EmailAddress", lazy="joined")


class EmailAddress(Base, EmailAddressMixin):
    __tablename__ = "email_addresses"


class PasswordCredential(Base, PasswordCredentialMixin):
    __tablename__ = "password_credentials"


class Session(Base, SessionMixin):
    __tablename__ = "sessions"
    # Custom additional columns on sessions
    device_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
```

> [!NOTE]
> `PasswordCredentialMixin` and `SessionMixin` define foreign keys targeting `users.id`. If your application customizes the user table name (e.g. `app_users`), you must explicitly define `user_id` on the related models referencing `app_users.id`, and pass your custom model classes to `SQLAlchemyAdapter(user_model=User, email_model=EmailAddress, credential_model=PasswordCredential, session_model=Session)`.
