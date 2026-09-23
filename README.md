# FastAPI Accounts ⚡

FastAPI Accounts provides email/password account management and database-backed sessions for FastAPI. It includes registration, email verification, login/logout, password reset/change, cookie or bearer transport, and dependencies for protecting routes. It uses async SQLAlchemy for persistence; applications supply email delivery and their frontend.

Status: alpha. Review the compatibility, migration and deployment guidance before adopting it.

---

## Supported Capabilities and Boundaries

**Capabilities:**
* **Account Management:** Email/password registration, login, logout, and authenticated password changes.
* **Email Verification:** Issuance of verification tokens; applications supply the delivery callback and frontend flow.
* **Password Resets:** Issuance of secure reset tokens; applications supply the delivery callback.
* **Transports:** Cookie transport (for SPAs/web) and Bearer transport (for mobile/APIs).
* **Route Protection:** Dependency injection (`current_active_user`, `current_superuser`) returning immutable DTOs.
* **Database Integration:** Async SQLAlchemy 2.0 with default models and packaged Alembic migrations.

**Boundaries (Not Currently Provided):**
FastAPI Accounts focuses strictly on email/password flows. It **does not** provide:
* OAuth / OpenID Connect (Social Logins)
* Multi-Factor Authentication (MFA)
* Passkeys / WebAuthn
* General-purpose Role-Based Access Control (RBAC) or granular permissions

---

## Installation

Install via pip:
```bash
pip install fastapi-accounts
```

To include the PostgreSQL driver and packaged Alembic migrations, install with the `postgres` and `migrations` extras:
```bash
pip install "fastapi-accounts[postgres,migrations]"
```

---

## Quickstart

Get a complete, working authentication API running locally with a disposable SQLite database.

First, generate a secure secret key and expose it as an environment variable:
```bash
export FASTAPI_ACCOUNTS_SECRET_KEY=$(openssl rand -hex 32)
```

Create `main.py`:

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

adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./accounts.db")
accounts = FastAPIAccounts(
    adapter=adapter,
    secret_key=os.environ["FASTAPI_ACCOUNTS_SECRET_KEY"],
    # For local HTTP development, set cookie_secure=False:
    transport=CookieTransport(cookie_secure=False),
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically create tables on startup (recommended for disposable development)
    await adapter.create_all()
    yield

app = FastAPI(title="My API", lifespan=lifespan)
app.include_router(accounts.router, prefix="/api/v1/auth", tags=["Auth"])

@app.get("/api/v1/profile")
async def get_profile(user: UserPrincipal = Depends(accounts.current_active_user)):
    return {"message": f"Welcome, {user.email}!", "user_id": str(user.id)}
```

Run with Uvicorn:
```bash
uvicorn main:app --reload
```

---

## Cookie versus Bearer Behavior

Cookie and bearer transports use the same database-backed sessions. Bearer access tokens are opaque session credentials, not JWTs.

Logging out immediately revokes the session in the database. Password resets invalidate existing sessions and previously issued reset challenges.

---

## Email Verification and Reset Delivery

Your application supplies email delivery through callbacks. FastAPI Accounts generates verification and reset tokens; your callback delivers the corresponding link to the user.

Without a callback, the library simply logs a notification event and returns. You must hook into `on_after_request_password_reset` or `on_after_register` to dispatch the emails.

For a complete example showing token delivery, frontend URL construction and callback-failure handling, see [examples/basic_app.py](examples/basic_app.py).

---

## Essential Configuration and Deployment Limits

FastAPI Accounts uses the following secure defaults and limits out of the box:

| Setting | Default Value | Description |
|---|---|---|
| **Email verification before login** | Disabled | Users can log in immediately without verifying their email. |
| **Session lifetime** | 14 days | Active sessions expire after two weeks. |
| **Password-reset token lifetime** | 15 minutes | Reset links expire quickly to limit exposure. |
| **Cookie protections** | `HttpOnly`, `SameSite=Lax`, `Secure=True` | Secure by default; requires explicit `cookie_secure=False` for local HTTP development. |
| **Rate limiting** | Enabled (in-memory) | Enabled by default, but currently limited to a **single process**. |
| **Email delivery** | Application-supplied | The library generates tokens; you provide the delivery callback. |

---

## Database Migrations and Customization

Use `create_all()` for a disposable development database. Use packaged migrations for managed deployments. Install the migrations extra and follow the migration guide.

```python
from alembic import command
from fastapi_accounts.migrations import get_alembic_config

config = get_alembic_config("postgresql+asyncpg://user:pass@localhost/dbname")
command.upgrade(config, "head")
```

**Further Documentation:**
* [Database Migrations (docs/migrations.md)](docs/migrations.md) — For legacy stamping, custom-model migration ownership, and recovery procedures.
* [The Journey of FastAPI Accounts (JOURNEY.md)](JOURNEY.md) — For our ecosystem vision and design rationale.

---

## Development, Security, and License

### Contributions & Testing
To run the test suite, install the development dependencies:
```bash
git clone https://github.com/fastapi-accounts/fastapi-accounts.git
cd fastapi-accounts
pip install -e ".[dev]"
```

PostgreSQL integration tests require a disposable test database explicitly exported:
```bash
export TEST_POSTGRES_URL="postgresql+asyncpg://user:pass@localhost/test_db"
pytest -v
```

### Security
The library uses dummy password verification to reduce timing differences and restricts sensitive endpoints with rate limiting. Library-generated logging excludes credentials and raw authentication tokens. Application callbacks, middleware, and proxies remain outside that guarantee.

For vulnerability reporting and our security policy, please read [SECURITY.md](SECURITY.md).

### License
FastAPI Accounts is licensed under the [Apache License 2.0](LICENSE).
