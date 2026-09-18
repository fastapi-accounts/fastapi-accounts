import os

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.core import FastAPIAccounts


@pytest.mark.asyncio
async def test_s1_password_reset_token_single_use(cookie_accounts: FastAPIAccounts):
    """S1: Password reset token must be strictly single-use; replay attempts must be rejected."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "s1_replay@example.com", "password": "OriginalPassword123!"},
        )
        assert reg_resp.status_code == 201

        # Request password reset
        await client.post(
            "/api/v1/auth/request-password-reset",
            json={"email": "s1_replay@example.com"},
        )

        user = await cookie_accounts.adapter.get_user_by_email(
            await cookie_accounts.adapter.session_maker().__aenter__(),
            "s1_replay@example.com",
        )
        assert user is not None
        cred = await cookie_accounts.adapter.get_password_credential(
            await cookie_accounts.adapter.session_maker().__aenter__(), user.id
        )
        assert cred is not None

        reset_token = cookie_accounts.generate_password_reset_token(
            user.id, "s1_replay@example.com", pwd_ts=cred.password_updated_at
        )

        # First use: must SUCCEED
        resp1 = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": reset_token, "new_password": "NewPasswordOne123!"},
        )
        assert resp1.status_code == 200
        assert "reset successfully" in resp1.json()["message"]

        # Replay attempt with same token within validity window: must FAIL (400)
        resp2 = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": reset_token, "new_password": "NewPasswordTwo456!"},
        )
        assert resp2.status_code == 400
        assert "Invalid or expired" in resp2.json()["detail"]


@pytest.mark.asyncio
async def test_s1_password_reset_token_invalidated_by_password_change(
    cookie_accounts: FastAPIAccounts,
):
    """S1: If user changes password, any previously issued password reset token must become invalid."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register & Login
        await client.post(
            "/api/v1/auth/register",
            json={"email": "s1_inval@example.com", "password": "OldPassword123!"},
        )
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "s1_inval@example.com", "password": "OldPassword123!"},
        )
        assert login_resp.status_code == 200

        user = await cookie_accounts.adapter.get_user_by_email(
            await cookie_accounts.adapter.session_maker().__aenter__(),
            "s1_inval@example.com",
        )
        assert user is not None
        cred = await cookie_accounts.adapter.get_password_credential(
            await cookie_accounts.adapter.session_maker().__aenter__(), user.id
        )
        assert cred is not None

        # Generate a reset token before changing password
        reset_token = cookie_accounts.generate_password_reset_token(
            user.id, "s1_inval@example.com", pwd_ts=cred.password_updated_at
        )

        # User changes password via /change-password
        change_resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "OldPassword123!",
                "new_password": "ChangedPassword123!",
            },
        )
        assert change_resp.status_code == 200

        # Attempt to use previously issued reset token: must FAIL (400)
        reset_resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": reset_token, "new_password": "AttemptPassword456!"},
        )
        assert reset_resp.status_code == 400
        assert "Invalid or expired" in reset_resp.json()["detail"]


@pytest.mark.asyncio
async def test_s2_login_response_dto_whitelisting(
    cookie_accounts: FastAPIAccounts, bearer_accounts: FastAPIAccounts
):
    """S2: Login response must never leak password credentials or argon2 hash."""
    # 1. Cookie Transport
    app_cookie = FastAPI()
    app_cookie.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport_c = ASGITransport(app=app_cookie)
    async with AsyncClient(transport=transport_c, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "s2_cookie@example.com", "password": "SecretPassword123!"},
        )
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "s2_cookie@example.com", "password": "SecretPassword123!"},
        )
        assert login_resp.status_code == 200
        data = login_resp.json()
        assert "primary_email" in data
        assert "password_credential" not in data
        assert "hashed_password" not in data
        assert "$argon2" not in login_resp.text
        assert (
            "password" not in login_resp.text.lower()
            or "password_credential" not in login_resp.text
        )

    # 2. Bearer Transport
    app_bearer = FastAPI()
    app_bearer.include_router(bearer_accounts.router, prefix="/api/v1/auth")

    transport_b = ASGITransport(app=app_bearer)
    async with AsyncClient(transport=transport_b, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "s2_bearer@example.com", "password": "SecretPassword123!"},
        )
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "s2_bearer@example.com", "password": "SecretPassword123!"},
        )
        assert login_resp.status_code == 200
        data = login_resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "password_credential" not in data
        assert "$argon2" not in login_resp.text


@pytest.mark.asyncio
async def test_s3_no_raw_tokens_in_stdout(
    cookie_accounts: FastAPIAccounts, capsys: pytest.CaptureFixture
):
    """S3: Ensure raw security tokens are never printed to server stdout/stderr."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "s3_stdout@example.com", "password": "StdoutPassword123!"},
        )
        assert reg_resp.status_code == 201

        # Request password reset
        req_resp = await client.post(
            "/api/v1/auth/request-password-reset",
            json={"email": "s3_stdout@example.com"},
        )
        assert req_resp.status_code == 200

        captured = capsys.readouterr()
        # Verify no raw token or link was printed to stdout
        assert "Verification link for" not in captured.out
        assert "Password reset link for" not in captured.out


def test_s4_secret_key_length_validation(adapter: SQLAlchemyAdapter):
    """S4: FastAPIAccounts must enforce at least 32-character (256-bit) secret keys at initialization."""
    # 1. Empty string
    with pytest.raises(ValueError, match="at least 32 characters"):
        FastAPIAccounts(adapter=adapter, secret_key="")

    # 2. Too short (< 32 chars)
    with pytest.raises(ValueError, match="at least 32 characters"):
        FastAPIAccounts(adapter=adapter, secret_key="short-secret-key-123")

    # 3. Exactly 32 chars must SUCCEED
    valid_32 = "12345678901234567890123456789012"
    acc = FastAPIAccounts(adapter=adapter, secret_key=valid_32)
    assert acc.secret_key == valid_32

    # 4. env: prefix with missing env var
    with pytest.raises(ValueError, match="is not set"):
        FastAPIAccounts(
            adapter=adapter, secret_key="env:NON_EXISTENT_SECRET_KEY_ENV_VAR"
        )

    # 5. env: prefix with valid env var
    os.environ["VALID_TEST_SECRET"] = "a" * 32
    try:
        acc_env = FastAPIAccounts(adapter=adapter, secret_key="env:VALID_TEST_SECRET")
        assert acc_env.secret_key == "a" * 32
    finally:
        del os.environ["VALID_TEST_SECRET"]
