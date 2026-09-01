# FastAPI Accounts ⚡

<p align="center">
  <em>An open-source initiative to build the modern, complete authentication and account-management engine for FastAPI.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active%20Design%20%26%20Development-orange.svg" alt="Status: RFC / WIP">
  <a href="https://github.com/fastapi-accounts/fastapi-accounts/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://github.com/fastapi-accounts/fastapi-accounts/discussions"><img src="https://img.shields.io/badge/Community-RFC%20%26%20Feedback-brightgreen.svg" alt="Discussions"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white" alt="Python 3.10+"></a>
</p>

---

> [!IMPORTANT]
> **🚧 Project Status: Architecture & RFC Phase**
> 
> This project is currently in **active design and early development**. We are building in the open and sharing our proposed architecture, API design, and roadmap to gather feedback from the FastAPI community before publishing the first release (`v0.1.0-alpha`).
> 
> 👉 **Have feedback or ideas? Join our [RFC Discussion on GitHub](https://github.com/fastapi-accounts/fastapi-accounts/discussions)!**

---

## 💡 Why We Are Building This

In the Python and Django ecosystem, `django-allauth` has long been the gold standard for full-featured authentication and account management. In the TypeScript world, projects like `Better-Auth` and `Lucia` transformed developer experience for modern APIs.

However, in the **FastAPI** ecosystem, developers still face a fragmented choice:
1. **Write 1,000+ lines of custom boilerplate** for hashing, JWTs, password resets, verification emails, and OAuth state handling on every new project.
2. **Wrestle with complex generic typing and multi-file wiring** in older libraries that are now in maintenance mode.
3. **Pay steep monthly fees** to vendor-locked cloud auth providers (Clerk, Auth0).

**FastAPI Accounts** is our initiative to solve this: a modern, async-first, zero-boilerplate authentication and account management engine built natively for FastAPI, Pydantic v2, and Async SQLAlchemy 2.0.

---

## 🎯 What We Are Planning to Build

```
                      FASTAPI ACCOUNTS ARCHITECTURE
                                    │
    ┌─────────────────┬─────────────┴─────────────┬─────────────────┐
    ▼                 ▼                           ▼                 ▼
[Core Accounts]    [Dual Transport]            [Social OAuth]    [Modern Security]
• Email / Password • HttpOnly Cookies (SPA)    • Google & GitHub • Session Revocation
• Multi-Email per  • Bearer Tokens (Mobile)    • Safe Account    • TOTP / 2FA
  User (Verified)  • Automatic CSRF Handling     Linking (Anti-  • Passkeys /
• Reset / Verify                                 Takeover Checks)  WebAuthn
```

### 1. Radical Developer Experience (< 15 Lines of Code)
No multi-file boilerplate gymnastics. Mount all authentication and account management routes with clean dependency injection.

### 2. Dual-Transport for Web & Mobile
* **SPAs (Next.js, React, Vue, Svelte):** Secure, `SameSite=Lax`, `HttpOnly` session cookies with CSRF protection.
* **Mobile & CLI (iOS, Flutter, React Native):** Standard `Authorization: Bearer <token>` with refresh token rotation.

### 3. Real-World Multi-Email & Account Linking
* Support multiple email addresses per user (Primary vs. Secondary, Verified vs. Unverified), matching standard production requirements.
* Strict email verification state checks to prevent OAuth account-takeover exploits.

### 4. Modern Python Stack
Built cleanly for **Python 3.10+**, **Pydantic v2**, and **Async SQLAlchemy 2.0**.

---

## 🛠️ Proposed API Design (RFC Preview)

*This is our intended developer experience. We would love your feedback on this syntax!*

```python
from fastapi import FastAPI, Depends
from fastapi_accounts import FastAPIAccounts, SQLAlchemyAdapter
from fastapi_accounts.providers import GoogleProvider, GitHubProvider

app = FastAPI(title="My API")

# 1. Initialize the account engine
accounts = FastAPIAccounts(
    adapter=SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./app.db"),
    secret_key="env:AUTH_SECRET_KEY",
    providers=[
        GoogleProvider(client_id="...", client_secret="..."),
        GitHubProvider(client_id="...", client_secret="..."),
    ],
)

# 2. Mount all auth & account endpoints in one line
app.include_router(accounts.router, prefix="/api/v1/auth", tags=["Auth"])

# 3. Protect routes with clean dependency injection
@app.get("/api/v1/profile")
async def get_profile(user = Depends(accounts.current_active_user)):
    return {"id": user.id, "primary_email": user.primary_email}
```

---

## 🗺️ Development Roadmap

| Milestone | Target Capabilities | Status |
| :--- | :--- | :---: |
| **Phase 0: RFC & Architecture** | Finalize data models, schema contracts, and API specification | 🔄 **In Progress** |
| **Phase 1: Core Foundation (`v0.1.0-alpha`)** | Email/Password (Argon2id), Email verification, Password reset, Multi-email models, Async SQLAlchemy 2.0 adapter, Dual-transport (Cookies + Bearer) | 📋 Planned |
| **Phase 2: Social & Sessions (`v0.2.0`)** | Google & GitHub OAuth2/OIDC, Safe account linking/unlinking, Active session tracking & device logout | 📋 Planned |
| **Phase 3: MFA & Advanced (`v0.3.0`)** | TOTP 2-Factor Authentication, WebAuthn / Passkeys, Apple / Microsoft OAuth | 📋 Planned |
| **Phase 4: Client Tooling (`v0.4.0`)** | Typed TypeScript/React client helper SDKs | 📋 Planned |

---

## 🤝 How You Can Get Involved

Because we are in the earliest design phase, **community input directly shapes this project**:

1. **Review the API Design:** Does the proposed syntax fit your FastAPI projects? Share thoughts in [Discussions](https://github.com/fastapi-accounts/fastapi-accounts/discussions).
2. **Request Features:** Tell us what pain points you've had with existing Python auth libraries by opening an [Issue](https://github.com/fastapi-accounts/fastapi-accounts/issues).
3. **Star the Repository:** Star the project to stay updated on our progress and `v0.1.0-alpha` release milestones!

---

## 📄 License

FastAPI Accounts will be released as open-source software licensed under the [Apache License 2.0](LICENSE).
