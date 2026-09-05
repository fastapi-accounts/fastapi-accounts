from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from fastapi_accounts import FastAPIAccounts, SQLAlchemyAdapter

# 1. Initialize the adapter and account engine
adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///./example_accounts.db")
accounts = FastAPIAccounts(adapter=adapter, secret_key="super-secret-key-change-me")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create SQLite database tables on startup
    await adapter.create_all()
    yield


# 2. Create FastAPI application and mount the auth router
app = FastAPI(title="FastAPI Accounts Demo", lifespan=lifespan)
app.include_router(accounts.router, prefix="/api/v1/auth", tags=["Authentication & Accounts"])


# 3. Protect any endpoint with clean dependency injection
@app.get("/api/v1/profile")
async def get_profile(user=Depends(accounts.current_active_user)):
    return {
        "message": f"Welcome back, {user.primary_email}!",
        "user_id": user.id,
        "is_superuser": user.is_superuser,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
