import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.transports.cookie import CookieTransport


@pytest.mark.asyncio
async def test_password_reset_flow_e2e(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    @app.get("/protected")
    async def protected_endpoint(user=Depends(cookie_accounts.current_active_user)):
        return {"email": user.primary_email}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register a user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "charlie@example.com", "password": "OldPassword123!"},
        )
        assert reg_resp.status_code == 201

        # 2. Login to obtain an active session
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "charlie@example.com", "password": "OldPassword123!"},
        )
        assert login_resp.status_code == 200
        assert "fastapi_accounts_session" in login_resp.cookies

        # 3. Verify access to protected endpoint with active session
        prot_resp = await client.get("/protected")
        assert prot_resp.status_code == 200
        assert prot_resp.json()["email"] == "charlie@example.com"

        # 4. Request password reset
        req_reset_resp = await client.post(
            "/api/v1/auth/request-password-reset",
            json={"email": "charlie@example.com"},
        )
        assert req_reset_resp.status_code == 200
        assert "password reset link has been sent" in req_reset_resp.json()["message"]

        # 5. Generate token directly for testing reset endpoint
        user = await cookie_accounts.adapter.get_user_by_email(
            await cookie_accounts.adapter.session_maker().__aenter__(),
            "charlie@example.com",
        )
        assert user is not None
        reset_token = cookie_accounts.generate_password_reset_token(
            user.id, "charlie@example.com"
        )

        # 6. Complete password reset with new password
        reset_resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": reset_token, "new_password": "NewSecurePassword456!"},
        )
        assert reset_resp.status_code == 200
        assert "reset successfully" in reset_resp.json()["message"]

        # 7. INVARIANT: Previous active session must be REVOKED immediately
        revoked_resp = await client.get("/protected")
        assert revoked_resp.status_code == 401

        # 8. Login with OLD password must FAIL
        old_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "charlie@example.com", "password": "OldPassword123!"},
        )
        assert old_login.status_code == 401

        # 9. Login with NEW password must SUCCEED
        new_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "charlie@example.com", "password": "NewSecurePassword456!"},
        )
        assert new_login.status_code == 200

        # 10. Access protected endpoint with new session
        new_prot = await client.get("/protected")
        assert new_prot.status_code == 200
        assert new_prot.json()["email"] == "charlie@example.com"


@pytest.mark.asyncio
async def test_password_reset_anti_enumeration(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Request password reset for a non-existent email
        resp = await client.post(
            "/api/v1/auth/request-password-reset",
            json={"email": "nonexistent@example.com"},
        )
        assert resp.status_code == 200
        assert "password reset link has been sent" in resp.json()["message"]


@pytest.mark.asyncio
async def test_password_reset_tampered_and_expired_tokens(
    cookie_accounts: FastAPIAccounts,
):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        await client.post(
            "/api/v1/auth/register",
            json={"email": "david@example.com", "password": "DavidPassword123!"},
        )

        user = await cookie_accounts.adapter.get_user_by_email(
            await cookie_accounts.adapter.session_maker().__aenter__(),
            "david@example.com",
        )
        assert user is not None

        # 1. Tampered signature
        valid_token = cookie_accounts.generate_password_reset_token(
            user.id, "david@example.com"
        )
        tampered_token = valid_token[:-4] + "abcd"
        bad_sig_resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": tampered_token, "new_password": "NewPassword123!"},
        )
        assert bad_sig_resp.status_code == 400
        assert "Invalid or expired" in bad_sig_resp.json()["detail"]

        # 2. Expired token (created with -10 seconds max_age)
        expired_token = cookie_accounts.token_signer.create_token(
            {
                "sub": str(user.id),
                "email": "david@example.com",
                "action": "reset_password",
            },
            max_age_seconds=-10,
        )
        expired_resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": expired_token, "new_password": "NewPassword123!"},
        )
        assert expired_resp.status_code == 400
        assert "Invalid or expired" in expired_resp.json()["detail"]


@pytest.mark.asyncio
async def test_cross_action_token_isolation(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "eve@example.com", "password": "EvePassword123!"},
        )

        # 1. Try to use an email verification token to reset password
        verify_token = cookie_accounts.generate_email_verification_token(
            "eve@example.com"
        )
        cross_resp1 = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": verify_token, "new_password": "NewEvePassword123!"},
        )
        assert cross_resp1.status_code == 400
        assert "Invalid or expired" in cross_resp1.json()["detail"]

        # 2. Try to use a password reset token to verify email
        user = await cookie_accounts.adapter.get_user_by_email(
            await cookie_accounts.adapter.session_maker().__aenter__(),
            "eve@example.com",
        )
        assert user is not None
        reset_token = cookie_accounts.generate_password_reset_token(
            user.id, "eve@example.com"
        )
        cross_resp2 = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": reset_token},
        )
        assert cross_resp2.status_code == 400
        assert "Invalid or expired" in cross_resp2.json()["detail"]


@pytest.mark.asyncio
async def test_custom_password_reset_callback(adapter: SQLAlchemyAdapter):
    dispatched_tokens = []

    async def custom_callback(user, token):
        dispatched_tokens.append((user.primary_email, token))

    accounts = FastAPIAccounts(
        adapter=adapter,
        secret_key="callback-test-secret",
        transport=CookieTransport(),
        on_after_request_password_reset=custom_callback,
    )

    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "frank@example.com", "password": "FrankPassword123!"},
        )

        resp = await client.post(
            "/api/v1/auth/request-password-reset",
            json={"email": "frank@example.com"},
        )
        assert resp.status_code == 200
        assert len(dispatched_tokens) == 1
        email, token = dispatched_tokens[0]
        assert email == "frank@example.com"

        # Verify the dispatched token is valid
        payload = accounts.verify_password_reset_token(token)
        assert payload is not None
        assert payload["email"] == "frank@example.com"
        assert payload["action"] == "reset_password"
