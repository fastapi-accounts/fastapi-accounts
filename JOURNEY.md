# The Journey of FastAPI Accounts: Building in Public ⚡

> *"Django developers had `django-allauth`. TypeScript developers got `Better-Auth`. FastAPI developers were still copying and pasting the same 1,000 lines of auth boilerplate on every new project. This is the authentic story of why and how FastAPI Accounts was born."*

---

## 📅 Chapter 1: The Spark & The Initial Proposal

Every backend developer building on FastAPI knows this feeling:
You start a fresh, exciting project. You have great ideas for your API endpoints. But before you can write a single line of business logic, you hit the wall:

* *How am I going to handle password hashing?* (Wait, `passlib` is deprecated on Python 3.12+).
* *Where do I store the verification tokens?*
* *How do I handle email confirmation safely?*
* *Should I store JWTs in `localStorage` or HTTP-only cookies?*
* *What happens when a user wants to log in with Google, but their email is already registered locally?*

In Django, you simply install `django-allauth` and move on. In FastAPI, existing libraries either felt abandoned, were in maintenance mode (`fastapi-users`), or required complex generic typing gymnastics just to register a user. The alternative was paying steep monthly fees for hosted auth vendors like Clerk or Auth0.

The initial question was simple:
> **"Why doesn't FastAPI have its own `django-allauth`?"**

---

## 🔍 Chapter 2: The Critical Pivot (Avoiding the Monolith Trap)

The original idea was to build a direct FastAPI equivalent of `django-allauth`. 

However, after deep architectural reflection and studying previous generations of Python auth tools, a crucial reality emerged:

1. **Django is a monolith:** It provides a built-in ORM, standard session middleware, templates, and server-side redirects.
2. **FastAPI is an asynchronous, decoupled API toolkit:** FastAPI apps serve Single Page Apps (React, Next.js, Vue), mobile apps (Flutter, iOS), and microservices.
3. **The Multi-ORM Trap:** Studying why `fastapi-users` went into maintenance mode revealed that trying to support 4 different database ORMs simultaneously created excessive abstraction layers and hurt developer experience.

We realized our North Star shouldn't be a 2010 server-rendered Django port. It needed to be the **API-first, modern identity engine for the 2020s**—inspired by the developer experience of tools like `Better-Auth` and `Lucia`, but built natively for modern Python.

---

## 🏷️ Chapter 3: Naming, Identity, and the Organization

We initially considered names like `FastAuth`. But upon researching PyPI, GitHub, and domains, we found that "FastAuth" was heavily fragmented across unrelated crypto wallets, healthcare SaaS tools, and abandoned packages.

We wanted a name that clearly stated: **This is not just another JWT token helper; this is a complete, multi-email account management system.**

We secured:
* 🏛️ **GitHub Organization:** [`github.com/fastapi-accounts`](https://github.com/fastapi-accounts)
* 📦 **PyPI Namespace:** `pip install fastapi-accounts`
* ⚖️ **Open Source License:** Apache 2.0

---

## 🧠 Chapter 4: The Architect's Warning & The "Steel Thread"

At this point, we had a detailed README, a comprehensive roadmap, and an RFC proposal. 

Then came a critical architectural insight:
> *"FastAPI Accounts has started top-down with great vision. But the biggest risk of top-down projects is **premature abstraction**—designing interfaces for 20 features before writing a single line of working code. Stop expanding horizontally. Build one complete, working vertical slice first."*

We took this advice to heart. Instead of talking about Passkeys, MFA, and 15 OAuth providers, we focused on building the **"Steel Thread"** (the minimal end-to-end slice):

1. **Modern Cryptography:** Using François Voron’s modern `pwdlib` for Argon2id password hashing.
2. **True Domain Modeling:** Separating `User`, `EmailAddress` (with verified/primary state machine), `PasswordCredential`, and `Session`.
3. **Dual Transport:** Secure `HttpOnly` cookies for SPAs and `Authorization: Bearer` for mobile APIs.
4. **Radical Simplicity:** Keeping user setup under 15 lines of code with Async SQLAlchemy 2.0.

---

## 🚀 Chapter 5: Day 1 Milestone — Code That Actually Works

In September 2026, we wrote the core engine from scratch:
* `FastAPIAccounts` orchestrator & route builder
* `SQLAlchemyAdapter` with native async session handling
* Automated test suite in `pytest-asyncio` covering registration, duplicate email rejection, verification tokens, cookie/bearer sessions, and revocation.

**Result:** 8 out of 8 integration tests passed in 0.73s, and our 15-line demo app (`examples/basic_app.py`) booted up with working OpenAPI Swagger documentation on the very first try.

```python
# The 15-Line Promise Delivered:
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi_accounts import FastAPIAccounts, SQLAlchemyAdapter

adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./accounts.db")
accounts = FastAPIAccounts(adapter=adapter, secret_key="env:AUTH_SECRET_KEY")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await adapter.create_all()
    yield

app = FastAPI(title="My API", lifespan=lifespan)
app.include_router(accounts.router, prefix="/api/v1/auth")

@app.get("/me")
async def get_me(user = Depends(accounts.current_active_user)):
    return {"email": user.primary_email}
```

---

## 🗺️ Chapter 6: The Near-Term Focus

We are building this project **100% in the open**, focusing on pragmatic, production-tested steps rather than premature feature sprawl.

Our current roadmap:
- [x] **v0.1.0-alpha (Shipped):** Core Email/Password, Email Verification lifecycle, Session Management, Dual Transports (Cookie + Bearer), Async SQLAlchemy 2.0.
- [ ] **v0.1.x (Hardening & Core Account Flows):**
  - Password reset & recovery workflow (`/request-password-reset`, `/reset-password`).
  - Multi-email management (adding secondary emails, changing primary email).
  - PostgreSQL & MySQL integration tests alongside SQLite.
- [ ] **v0.2.0 (First Social Provider):**
  - Google OAuth2/OIDC integration with anti-takeover verification checks.
- [ ] **Future Horizons (Community-Driven):**
  - Additional OAuth providers (GitHub, Apple) and MFA/TOTP as real user demand dictates.

We believe that open source thrives on honesty, community collaboration, and relentless focus on developer experience. 

If you want to help shape the future of authentication in FastAPI, join our [GitHub Discussions](https://github.com/fastapi-accounts/fastapi-accounts/discussions) and build with us! 🚀
