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

## ✨ Key Features

* **⚡ 15-Line Setup:** Complete authentication system mounted with a single router and sensible defaults.
* **🍪 Native Dual-Transport:**
  * **For Web & SPAs (React, Next.js, Vue, Svelte):** Secure `HttpOnly` `SameSite=Lax` cookies with built-in CSRF protection.
  * **For Mobile & CLI (iOS, Flutter, React Native, Postman):** `Authorization: Bearer <token>` with refresh token rotation.
* **📬 Real-World Account Management:**
  * Multiple email addresses per account (Primary + Verified state machine, just like GitHub).
  * Secure, stateless cryptographic email verification workflows (`/verify-email` & `/request-verify-email`).
* **🛡️ Modern Security Primitives:**
  * Modern **Argon2id** password hashing via `pwdlib`.
  * Active session tracking (view devices/IPs, "Logout everywhere").
* **🚀 Modern Python Native:**
  * Built exclusively for Python 3.10+, Pydantic v2, and Async SQLAlchemy 2.0.
  * Ready-to-use model mixins that plug directly into your existing Alembic migrations.

---

## 🚀 Quickstart (15 Lines of Code)

### 1. Installation

```bash
pip install fastapi-accounts --pre
# or with uv:
uv add fastapi-accounts --prerelease=allow
```

### 2. Basic Application (`app.py`)

```python
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi_accounts import FastAPIAccounts, SQLAlchemyAdapter

# 1. Initialize the adapter and account engine
adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./accounts.db")
accounts = FastAPIAccounts(adapter=adapter, secret_key="super-secret-key-change-me")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically create database tables on startup (for quickstarts/dev)
    await adapter.create_all()
    yield

# 2. Mount all auth & account endpoints in one line
app = FastAPI(title="My API", lifespan=lifespan)
app.include_router(accounts.router, prefix="/api/v1/auth", tags=["Auth"])

# 3. Protect any endpoint with clean dependency injection
@app.get("/api/v1/profile")
async def get_profile(user = Depends(accounts.current_active_user)):
    return {"message": f"Welcome back, {user.primary_email}!", "user_id": user.id}
```

Run your app:
```bash
uvicorn app:app --reload
```

Visit **`http://localhost:8000/docs`** to see your fully documented authentication endpoints:
* `POST /api/v1/auth/register`
* `POST /api/v1/auth/verify-email`
* `POST /api/v1/auth/request-verify-email`
* `POST /api/v1/auth/login`
* `POST /api/v1/auth/logout`
* `GET  /api/v1/auth/me`

---

## 🗺️ Roadmap & Milestones

| Milestone | Target Capabilities | Status |
| :--- | :--- | :---: |
| **v0.1.0-alpha (Shipped)** | Email/Password (Argon2id), Email verification, Resend verification, Multi-email models, Async SQLAlchemy 2.0 adapter, Dual-transport (Cookies + Bearer) | ✅ **Completed** |
| **v0.1.x (Core Hardening)** | Password reset/recovery workflows, Multi-email addition/removal, Primary email changes, PostgreSQL integration tests | 🏗️ **In Progress** |
| **v0.2.0 (Social Accounts)** | Google OAuth2/OIDC integration, Safe social account linking with anti-takeover checks | 📋 Planned |
| **Future Horizons** | Additional OAuth providers (GitHub, Apple), Active session device management, TOTP / MFA | 💡 Under RFC |

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
