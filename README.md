# FastAPI Accounts ⚡

*Modern, zero-boilerplate authentication and account management for FastAPI.*

[![PyPI](https://img.shields.io/pypi/v/fastapi-accounts?color=brightgreen&label=PyPI)](https://pypi.org/project/fastapi-accounts)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/fastapi-accounts/fastapi-accounts/blob/main/LICENSE)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2-E92063.svg?logo=pydantic&logoColor=white)](https://pydantic.dev)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org)
[![Discussions](https://img.shields.io/badge/Community-Discussions-brightgreen.svg)](https://github.com/fastapi-accounts/fastapi-accounts/discussions)

---

## 💡 The Vision

Django developers have `django-allauth`.  
TypeScript developers have `Better-Auth` and `Lucia`.  
**FastAPI developers deserve a modern, batteries-included authentication and account management engine.**

Today, building authentication in FastAPI usually means either:
1. **Writing 1,000+ lines of custom boilerplate** (Argon2 hashing, JWT/token issuance, password reset tokens, email verification, OAuth state handling) for every new project.
2. **Wrestling with complex generic typing and multi-file wiring** in older libraries that are now in maintenance mode.
3. **Paying steep monthly fees** to vendor-locked cloud auth providers (Clerk, Auth0).

**FastAPI Accounts** provides a modular, production-hardened authentication and account management engine built for **FastAPI**, **Pydantic v2**, and **Async SQLAlchemy 2.0**.

📖 *Read our full story: [**The Journey of FastAPI Accounts (JOURNEY.md)**](JOURNEY.md).*

---

## ✨ Key Capabilities

* **⚡ Minimal Setup:** Core authentication and account endpoints mounted with a single router and sensible defaults.
* **🍪 Dual-Transport Architecture:**
  * **Cookie Transport (Web & SPAs):** `HttpOnly` `SameSite=Lax` session cookies with `Secure=True` by default.
  * **Bearer Transport (Mobile & CLI):** `Authorization: Bearer <token>` token transport.
* **🛡️ Security-First Primitives:**
  * **Async Offloaded Argon2id:** Hashing and verification run off the event loop via worker threads with configurable `CapacityLimiter`.
  * **Timing Oracle Equalization:** Missing users execute dummy hash verification to prevent response-time enumeration.
  * **Monotonic Credential Versioning:** Database check-constrained `credential_version >= 1` with atomic Compare-And-Swap (CAS) to guarantee single-use reset tokens even under frozen or skewed system clocks.
  * **Session-Bound CSRF Protection:** Signed double-submit CSRF tokens and strict `Origin`/`Referer` validation against untrusted or sibling origins.
  * **PII-Safe Rate Limiting:** Built-in sliding-window limiter with HMAC-hashed identity keys protecting sensitive authentication flows.
  * **Session Revocation:** Invalidation of existing sessions upon password reset or change.
  * **Response DTO Whitelisting:** Strict serialization returning immutable `UserPrincipal` DTOs.
  * **Sanitized Logging:** Zero raw security tokens or credential material in stdout/stderr/logs.
* **🗄️ Database & Schema Management:**
  * Async SQLAlchemy 2.0 with type-annotated declarative mixins.
  * Request-scoped session dependency injection honoring `app.dependency_overrides`.
  * Packaged Alembic migrations for default models with deterministic upgrade and adoption paths.

---

## 🚀 Quickstart

### 1. Installation

```bash
# Install with SQLite driver:
pip install "fastapi-accounts[sqlite]" --pre

# Or install with PostgreSQL driver and Alembic migrations:
pip install "fastapi-accounts[postgres,migrations]" --pre

# Or with uv:
uv add "fastapi-accounts[sqlite]" --prerelease=allow
```

### 2. Basic Application (`app.py`)

```python
import os
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi_accounts import (
    CookieTransport,
    FastAPIAccounts,
    SQLAlchemyAdapter,
    UserPrincipal,
)

# 1. Initialize adapter & account engine
# In production, provide a secret key representing at least 256 bits of entropy:
# $ export FASTAPI_ACCOUNTS_SECRET_KEY=$(openssl rand -hex 32)
adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./accounts.db")
accounts = FastAPIAccounts(
    adapter=adapter,
    secret_key=os.environ["FASTAPI_ACCOUNTS_SECRET_KEY"],
    # For local development without HTTPS, set cookie_secure=False:
    transport=CookieTransport(cookie_secure=False),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically create database tables on startup (for dev/quickstart)
    await adapter.create_all()
    yield


# 2. Mount all auth & account endpoints in one line
app = FastAPI(title="My API", lifespan=lifespan)
app.include_router(accounts.router, prefix="/api/v1/auth", tags=["Auth"])


# 3. Protect any endpoint with clean dependency injection returning UserPrincipal DTO
@app.get("/api/v1/profile")
async def get_profile(user: UserPrincipal = Depends(accounts.current_active_user)):
    return {"message": f"Welcome back, {user.email}!", "user_id": user.id}
```

---

## 🗄️ Database Migrations & Legacy Adoption

FastAPI Accounts includes packaged Alembic migrations for its default declarative models.

### Programmatic Migration Execution

```python
from alembic import command
from fastapi_accounts.migrations import get_alembic_config

# Point Alembic directly to packaged migrations
config = get_alembic_config("sqlite:///./accounts.db")
command.upgrade(config, "head")
```

### CLI Configuration (`alembic.ini`)

You can reference the packaged migrations directly in your `alembic.ini`:

```ini
[alembic]
script_location = fastapi_accounts:migrations
sqlalchemy.url = sqlite:///./accounts.db
```

Or provide your database URL via environment variable:
```bash
export FASTAPI_ACCOUNTS_DATABASE_URL="sqlite:///./accounts.db"
alembic upgrade head
alembic check
```

> [!NOTE]
> Bundled migrations manage the library's default declarative models. Applications implementing custom model classes and table names should manage those schemas within their own Alembic environment.

### Safe Legacy Database Upgrade Workflow

If upgrading an existing database initialized with `v0.1.0a2` or `v0.1.0a3` using `adapter.create_all()`:

1. **Back up your database** prior to executing schema commands.
2. **Inspect your schema** to verify compatibility:
   ```python
   from sqlalchemy import create_engine
   from fastapi_accounts.migrations import inspect_legacy_schema, SchemaState

   engine = create_engine("sqlite:///./accounts.db")
   with engine.connect() as conn:
       result = inspect_legacy_schema(conn)
       print(f"Detected schema state: {result.state.value}")
   ```
3. **Apply the appropriate migration path:**
   * **If `ALEMBIC_MANAGED`** (database is already tracked by Alembic):
     ```bash
     alembic upgrade head
     ```
   * **If `UNVERSIONED_CURRENT`** (unmanaged schema with `credential_version` and indexes):
     ```bash
     alembic stamp 0004_add_credential_version
     alembic upgrade head
     ```
   * **If `UNVERSIONED_A3`** (unmanaged schema containing `password_updated_at` and indexes):
     ```bash
     alembic stamp 0003_add_session_indexes
     alembic upgrade head
     ```
   * **If `UNVERSIONED_A2`** (unmanaged baseline lacking `password_updated_at` column):
     ```bash
     alembic stamp 0001_initial_schema
     alembic upgrade head
     ```
   * **If `UNKNOWN`:** Do not stamp; inspect your database schema for custom modifications or structural discrepancies.

---

## 🧪 Running Tests

FastAPI Accounts comes with a comprehensive automated test suite:

```bash
# Clone the repository
git clone https://github.com/fastapi-accounts/fastapi-accounts.git
cd fastapi-accounts

# Run tests with pytest
pytest -v
```

---

## 📄 License

FastAPI Accounts is open-source software licensed under the [Apache License 2.0](LICENSE).
