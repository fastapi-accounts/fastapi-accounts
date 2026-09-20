# FastAPI Accounts ⚡

*Modern, zero-boilerplate authentication and complete account management for FastAPI.*

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

**FastAPI Accounts** solves this: an async-first, zero-boilerplate authentication and account management engine built natively for **FastAPI**, **Pydantic v2**, and **Async SQLAlchemy 2.0**.

📖 *Read our full story: [**The Journey of FastAPI Accounts (JOURNEY.md)**](JOURNEY.md).*

---

## ✨ Key Capabilities

* **⚡ 15-Line Setup:** Complete authentication and account lifecycle mounted with a single router and sensible defaults.
* **🍪 Dual-Transport Architecture:**
  * **Cookie Transport (Web & SPAs):** `HttpOnly` `SameSite=Lax` session cookies.
  * **Bearer Transport (Mobile & CLI):** `Authorization: Bearer <token>` token transport.
* **🛡️ Security-First Primitives:**
  * **Argon2id** password hashing via `pwdlib`.
  * **Single-Use Password Reset:** Fail-closed timed token verification with database atomic compare-and-swap (CAS) to prevent sequential and concurrent replay attacks.
  * **Session Revocation:** Immediate invalidation of all existing sessions upon password reset.
  * **Response DTO Whitelisting:** Strict serialization preventing accidental hash disclosure.
  * **Sanitized Logging:** Zero raw security tokens or credential material in stdout/stderr/logs.
* **🗄️ Database & Schema Management:**
  * Async SQLAlchemy 2.0 with type-annotated declarative mixins.
  * Included Alembic migrations with expand/backfill/constrain upgrade paths.

---

## 🚀 Quickstart (15 Lines of Code)

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
from fastapi_accounts import FastAPIAccounts, SQLAlchemyAdapter

# 1. Initialize adapter & account engine
# In production, provide a cryptographically random secret (>= 32 chars / 256 bits):
# $ export FASTAPI_ACCOUNTS_SECRET_KEY=$(openssl rand -hex 32)
adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./accounts.db")
accounts = FastAPIAccounts(
    adapter=adapter,
    secret_key=os.environ.get(
        "FASTAPI_ACCOUNTS_SECRET_KEY",
        "dev-secret-key-must-be-at-least-32-chars-long-change-in-prod-1234567890",
    ),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically create database tables on startup (for dev/quickstart)
    await adapter.create_all()
    yield


# 2. Mount all auth & account endpoints in one line
app = FastAPI(title="My API", lifespan=lifespan)
app.include_router(accounts.router, prefix="/api/v1/auth", tags=["Auth"])


# 3. Protect any endpoint with clean dependency injection
@app.get("/api/v1/profile")
async def get_profile(user=Depends(accounts.current_active_user)):
    return {"message": f"Welcome back, {user.primary_email}!", "user_id": user.id}
```

---

## 🗄️ Database Migrations & Legacy Adoption

FastAPI Accounts ships with production-ready Alembic migrations.

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
   from fastapi_accounts.migrations import inspect_legacy_schema

   engine = create_engine("sqlite:///./accounts.db")
   with engine.connect() as conn:
       version = inspect_legacy_schema(conn)
       print(f"Detected schema version: {version}")
   ```
3. **Apply the appropriate migration path:**
   * **If `alembic_managed`** (database is already tracked by Alembic):
     ```bash
     # Do NOT stamp; simply upgrade to head
     alembic upgrade head
     ```
   * **If `v0.1.0a2`** (unmanaged baseline lacking `password_updated_at` column):
     ```bash
     alembic stamp 0001_initial_schema
     alembic upgrade head
     ```
   * **If `v0.1.0a3`** (unmanaged schema containing `password_updated_at` and indexes):
     ```bash
     alembic stamp head
     ```
   * **If `unrecognized`:** Do not stamp; inspect your database schema for custom modifications.

---

## 🗺️ Roadmap & Milestones

| Milestone | Target Capabilities | Status |
| :--- | :--- | :---: |
| **v0.1.0a4** | Argon2id hashing, Single-use password reset with CAS, Dual-transport (Cookies + Bearer), Async SQLAlchemy 2.0 & Alembic migrations (`fastapi_accounts:migrations`), Fail-safe database commit durability, Sanitized logging & DTO whitelisting | 🎯 **Hardened on `fix/phase1-hardening` (v0.1.0a4 candidate)** |
| **v0.1.0a5 (Async Performance & DI)** | Offload Argon2id hashing (`anyio.to_thread`), Request-scoped DB session injection, Timing oracle equalization | 🎯 **Next Sprint** |
| **v0.2.0a1 (Packaging & Typing)** | Complete type annotations, OpenAPI `securitySchemes` authorization in Swagger, Production secure cookie defaults | 📋 Planned |
| **v0.3.0 (Multi-Email & DB Matrix)** | Secondary email lifecycle & promotion, PostgreSQL service container CI integration matrix | 📋 Planned |
| **v0.4.0 (Social Accounts & MFA)** | Google OAuth2/OIDC integration, Safe social account linking, TOTP MFA | 📋 Planned |
| **Future Horizons** | CSRF tokens & Origin binding, Refresh token rotation, Session device management, WebAuthn Passkeys | 💡 Under RFC |


---

## 🧪 Running Tests

FastAPI Accounts comes with an automated test suite:

```bash
# Clone the repository
git clone https://github.com/fastapi-accounts/fastapi-accounts.git
cd fastapi-accounts

# Run tests with uv
uv run --all-extras pytest
```

---

## 💬 Join the Community & RFC

We are actively designing the OAuth linking and Passkey architecture:
* 💡 **Have feedback or ideas?** Join our [GitHub Discussions](https://github.com/fastapi-accounts/fastapi-accounts/discussions).
* 🐛 **Found a bug or missing feature?** Open an [Issue](https://github.com/fastapi-accounts/fastapi-accounts/issues).
* ⭐ **Support the project:** Star this repository on GitHub!

---

## 📄 License

FastAPI Accounts is open-source software licensed under the [Apache License 2.0](LICENSE).
