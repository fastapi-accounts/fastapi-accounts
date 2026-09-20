import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.models.default import User


@pytest.mark.asyncio
async def test_a01_commit_before_response_guarantee(cookie_accounts: FastAPIAccounts):
    """A01: Ensure mutations are explicitly committed before the HTTP response is returned."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "a01_commit@example.com", "password": "SecurePassword123!"},
        )
        assert reg_resp.status_code == 201

        # Query directly with a fresh database session to confirm data is committed
        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "a01_commit@example.com"
            )
            assert user is not None
            assert user.primary_email == "a01_commit@example.com"
            assert user.password_credential is not None


@pytest.mark.asyncio
async def test_a01_injected_commit_failure_prevents_201_response(
    cookie_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected commit failure must abort request, prevent 201 response, and suppress side-effects."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    dispatched: list[str] = []

    async def mock_callback(user, token):
        dispatched.append(user.primary_email)

    cookie_accounts.on_after_register = mock_callback

    original_commit = AsyncSession.commit

    async def failing_commit(self):
        raise SQLAlchemyError("Simulated database failure during commit")

    monkeypatch.setattr(AsyncSession, "commit", failing_commit)

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "a01_fail@example.com", "password": "FailPassword123!"},
        )
        # Must return 500 Internal Server Error, NEVER 201 Created
        assert resp.status_code == 500

    # Restore commit to query database with a clean session
    monkeypatch.setattr(AsyncSession, "commit", original_commit)

    # Invariant: No side-effect email dispatch was called
    assert len(dispatched) == 0

    # Invariant: User was NOT persisted in the database
    async with cookie_accounts.adapter.session_maker() as session:
        user = await cookie_accounts.adapter.get_user_by_email(
            session, "a01_fail@example.com"
        )
        assert user is None


@pytest.mark.asyncio
async def test_a03_current_superuser_dependency(cookie_accounts: FastAPIAccounts):
    """A03: current_superuser must grant access to superusers, return 403 for non-superusers, and 401 for unauthenticated."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    @app.get("/admin/dashboard")
    async def admin_dashboard(user: User = Depends(cookie_accounts.current_superuser)):
        return {"message": "Welcome Admin", "email": user.primary_email}

    transport = ASGITransport(app=app)

    # 1. Unauthenticated request -> 401
    async with AsyncClient(
        transport=transport, base_url="http://test"
    ) as client_unauth:
        resp = await client_unauth.get("/admin/dashboard")
        assert resp.status_code == 401

    # 2. Regular User (is_superuser=False) -> 403 Forbidden
    async with AsyncClient(
        transport=transport, base_url="http://test"
    ) as client_regular:
        # Register normal user
        reg_resp = await client_regular.post(
            "/api/v1/auth/register",
            json={"email": "regular@example.com", "password": "RegularPassword123!"},
        )
        assert reg_resp.status_code == 201

        # Login
        login_resp = await client_regular.post(
            "/api/v1/auth/login",
            json={"email": "regular@example.com", "password": "RegularPassword123!"},
        )
        assert login_resp.status_code == 200

        # Attempt to access superuser endpoint
        forbidden_resp = await client_regular.get("/admin/dashboard")
        assert forbidden_resp.status_code == 403
        assert "Superuser privileges are required" in forbidden_resp.json()["detail"]

    # 3. Superuser (is_superuser=True) -> 200 OK
    async with AsyncClient(transport=transport, base_url="http://test") as client_admin:
        # Create superuser directly in database
        async with cookie_accounts.adapter.session_maker() as session:
            _admin_user, _ = await cookie_accounts.adapter.create_user_with_password(
                session=session,
                email="admin@example.com",
                password="AdminPassword123!",
                is_superuser=True,
            )
            await session.commit()

        # Login as superuser
        login_admin = await client_admin.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "AdminPassword123!"},
        )
        assert login_admin.status_code == 200

        # Access superuser endpoint -> 200 OK
        admin_resp = await client_admin.get("/admin/dashboard")
        assert admin_resp.status_code == 200
        assert admin_resp.json()["message"] == "Welcome Admin"
        assert admin_resp.json()["email"] == "admin@example.com"
