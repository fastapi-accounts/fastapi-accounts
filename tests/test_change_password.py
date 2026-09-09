import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_accounts.core import FastAPIAccounts


@pytest.mark.asyncio
async def test_change_password_success(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    @app.get("/protected")
    async def protected_endpoint(user=Depends(cookie_accounts.current_active_user)):
        return {"email": user.primary_email}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register and login
        await client.post(
            "/api/v1/auth/register",
            json={"email": "grace@example.com", "password": "OriginalPassword123!"},
        )
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "grace@example.com", "password": "OriginalPassword123!"},
        )
        assert login_resp.status_code == 200

        # 2. Change password
        change_resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "OriginalPassword123!",
                "new_password": "BrandNewPassword456!",
                "revoke_other_sessions": True,
            },
        )
        assert change_resp.status_code == 200
        assert change_resp.json()["message"] == "Password changed successfully."

        # 3. Verify current session is preserved
        prot_resp = await client.get("/protected")
        assert prot_resp.status_code == 200
        assert prot_resp.json()["email"] == "grace@example.com"

        # 4. Old password fails login
        old_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "grace@example.com", "password": "OriginalPassword123!"},
        )
        assert old_login.status_code == 401

        # 5. New password succeeds login
        new_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "grace@example.com", "password": "BrandNewPassword456!"},
        )
        assert new_login.status_code == 200


@pytest.mark.asyncio
async def test_change_password_incorrect_current_password(
    cookie_accounts: FastAPIAccounts,
):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "heidi@example.com", "password": "CorrectPassword123!"},
        )
        await client.post(
            "/api/v1/auth/login",
            json={"email": "heidi@example.com", "password": "CorrectPassword123!"},
        )

        # Attempt to change with wrong current password
        bad_change = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongCurrentPassword!",
                "new_password": "ShouldNotBeSet123!",
            },
        )
        assert bad_change.status_code == 400
        assert "Current password is incorrect." in bad_change.json()["detail"]


@pytest.mark.asyncio
async def test_change_password_revoke_other_sessions(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    @app.get("/protected")
    async def protected_endpoint(user=Depends(cookie_accounts.current_active_user)):
        return {"email": user.primary_email}

    transport = ASGITransport(app=app)
    # Client A (Device 1)
    async with AsyncClient(transport=transport, base_url="http://test") as client_a:
        await client_a.post(
            "/api/v1/auth/register",
            json={"email": "ivan@example.com", "password": "IvanPassword123!"},
        )
        login_a = await client_a.post(
            "/api/v1/auth/login",
            json={"email": "ivan@example.com", "password": "IvanPassword123!"},
        )
        assert login_a.status_code == 200

        # Client B (Device 2)
        async with AsyncClient(transport=transport, base_url="http://test") as client_b:
            login_b = await client_b.post(
                "/api/v1/auth/login",
                json={"email": "ivan@example.com", "password": "IvanPassword123!"},
            )
            assert login_b.status_code == 200

            # Both devices can access protected endpoint
            assert (await client_a.get("/protected")).status_code == 200
            assert (await client_b.get("/protected")).status_code == 200

            # Client A changes password and requests revocation of other sessions
            change_resp = await client_a.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "IvanPassword123!",
                    "new_password": "NewIvanPassword456!",
                    "revoke_other_sessions": True,
                },
            )
            assert change_resp.status_code == 200

            # Client A remains active
            assert (await client_a.get("/protected")).status_code == 200

            # Client B is revoked (401)
            assert (await client_b.get("/protected")).status_code == 401


@pytest.mark.asyncio
async def test_change_password_preserve_other_sessions(
    cookie_accounts: FastAPIAccounts,
):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    @app.get("/protected")
    async def protected_endpoint(user=Depends(cookie_accounts.current_active_user)):
        return {"email": user.primary_email}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client_a:
        await client_a.post(
            "/api/v1/auth/register",
            json={"email": "judy@example.com", "password": "JudyPassword123!"},
        )
        await client_a.post(
            "/api/v1/auth/login",
            json={"email": "judy@example.com", "password": "JudyPassword123!"},
        )

        async with AsyncClient(transport=transport, base_url="http://test") as client_b:
            await client_b.post(
                "/api/v1/auth/login",
                json={"email": "judy@example.com", "password": "JudyPassword123!"},
            )

            # Change password with revoke_other_sessions=False
            change_resp = await client_a.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "JudyPassword123!",
                    "new_password": "NewJudyPassword456!",
                    "revoke_other_sessions": False,
                },
            )
            assert change_resp.status_code == 200

            # Both remain active
            assert (await client_a.get("/protected")).status_code == 200
            assert (await client_b.get("/protected")).status_code == 200


@pytest.mark.asyncio
async def test_change_password_unauthenticated(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "AnyPassword123!",
                "new_password": "NewPassword123!",
            },
        )
        assert resp.status_code == 401
