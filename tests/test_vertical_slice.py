import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_accounts.core import FastAPIAccounts


@pytest.mark.asyncio
async def test_cookie_transport_vertical_slice(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    @app.get("/protected")
    async def protected_endpoint(user=Depends(cookie_accounts.current_active_user)):
        return {"user_id": str(user.id), "email": user.primary_email}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register a new user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "alice@example.com", "password": "SecurePassword123!"},
        )
        assert reg_resp.status_code == 201
        reg_data = reg_resp.json()
        assert reg_data["primary_email"] == "alice@example.com"
        assert reg_data["emails"][0]["is_verified"] is False

        # 2. Duplicate registration should fail
        dup_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "alice@example.com", "password": "AnotherPassword123!"},
        )
        assert dup_resp.status_code == 400
        assert "already exists" in dup_resp.json()["detail"]

        # 3. Request a new verification email
        req_verify_resp = await client.post(
            "/api/v1/auth/request-verify-email",
            json={"email": "alice@example.com"},
        )
        assert req_verify_resp.status_code == 200

        # 4. Verify email with token
        token = cookie_accounts.generate_email_verification_token("alice@example.com")
        verify_resp = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": token},
        )
        assert verify_resp.status_code == 200

        # 4. Login with wrong password should fail
        bad_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "WrongPassword!"},
        )
        assert bad_login.status_code == 401

        # 5. Login with correct password
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "SecurePassword123!"},
        )
        assert login_resp.status_code == 200
        assert "fastapi_accounts_session" in login_resp.cookies

        # 6. Access protected route with cookie
        me_resp = await client.get("/protected")
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == "alice@example.com"

        # 7. Access /me endpoint
        profile_resp = await client.get("/api/v1/auth/me")
        assert profile_resp.status_code == 200
        assert profile_resp.json()["primary_email"] == "alice@example.com"

        # 8. Logout
        logout_resp = await client.post("/api/v1/auth/logout")
        assert logout_resp.status_code == 200

        # 9. Access protected route after logout without valid session
        unauth_client = AsyncClient(transport=transport, base_url="http://test")
        unauth_resp = await unauth_client.get("/protected")
        assert unauth_resp.status_code == 401


@pytest.mark.asyncio
async def test_bearer_transport_vertical_slice(bearer_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(bearer_accounts.router, prefix="/api/v1/auth")

    @app.get("/protected")
    async def protected_endpoint(user=Depends(bearer_accounts.current_active_user)):
        return {"email": user.primary_email}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register
        await client.post(
            "/api/v1/auth/register",
            json={"email": "bob@example.com", "password": "BobSecurePassword123!"},
        )

        # 2. Login (returns access_token)
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "bob@example.com", "password": "BobSecurePassword123!"},
        )
        assert login_resp.status_code == 200
        token_data = login_resp.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"
        token = token_data["access_token"]

        # 3. Access protected route with Bearer header
        headers = {"Authorization": f"Bearer {token}"}
        prot_resp = await client.get("/protected", headers=headers)
        assert prot_resp.status_code == 200
        assert prot_resp.json()["email"] == "bob@example.com"

        # 4. Access protected route with invalid token
        bad_headers = {"Authorization": "Bearer invalid_token_12345"}
        bad_resp = await client.get("/protected", headers=bad_headers)
        assert bad_resp.status_code == 401
