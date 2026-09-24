import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from fastapi_accounts import (
    CookieTransport,
    FastAPIAccounts,
    SQLAlchemyAdapter,
    UserPrincipal,
)

# 1. Initialize the adapter and account engine
# In production, set cookie_secure=True (default) and pass secret_key via environment variable:
# export FASTAPI_ACCOUNTS_SECRET_KEY=$(openssl rand -hex 32)
secret_key = os.environ.get("FASTAPI_ACCOUNTS_SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "Missing environment variable FASTAPI_ACCOUNTS_SECRET_KEY. "
        "Generate a strong 32+ byte secret: export FASTAPI_ACCOUNTS_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    )

adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./example_accounts.db")


async def mock_register_hook(user: UserPrincipal, token: str) -> None:
    url = f"https://frontend.example.com/register?token={token}"
    print(f"[Mock Email] Sent register link to {user.email}")
    print(f"[Mock Email] Action URL: {url[:38]}...[REDACTED]")


async def mock_reset_hook(user: UserPrincipal, token: str) -> None:
    url = f"https://frontend.example.com/password-reset?token={token}"
    print(f"[Mock Email] Sent password-reset link to {user.email}")
    print(f"[Mock Email] Action URL: {url[:44]}...[REDACTED]")


async def mock_delivery_failure(
    action: str, user: UserPrincipal, exc: Exception
) -> None:
    print(f"[Mock Email] Failed to send {action} email to {user.email}: {exc}")


accounts = FastAPIAccounts(
    adapter=adapter,
    secret_key=secret_key,
    transport=CookieTransport(cookie_secure=False),
    on_after_register=mock_register_hook,
    on_after_request_password_reset=mock_reset_hook,
    on_delivery_failure=mock_delivery_failure,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create SQLite database tables on startup
    await adapter.create_all()
    yield


# 2. Create FastAPI application and mount the auth router
app = FastAPI(title="FastAPI Accounts Demo", lifespan=lifespan)
app.include_router(
    accounts.router, prefix="/api/v1/auth", tags=["Authentication & Accounts"]
)


# 3. Protect any endpoint with clean dependency injection returning UserPrincipal DTO
@app.get("/api/v1/profile")
async def get_profile(user: UserPrincipal = Depends(accounts.current_active_user)):
    return {
        "message": f"Welcome back, {user.email}!",
        "user_id": user.id,
        "is_superuser": user.is_superuser,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
