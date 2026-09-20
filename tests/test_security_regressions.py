import asyncio
import logging
import os

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.transports.cookie import CookieTransport


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

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "s1_replay@example.com"
            )
            assert user is not None
            cred = await cookie_accounts.adapter.get_password_credential(
                session, user.id
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

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "s1_inval@example.com"
            )
            assert user is not None
            cred = await cookie_accounts.adapter.get_password_credential(
                session, user.id
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
async def test_s1_legacy_token_without_pwd_ts_rejected_fail_closed(
    cookie_accounts: FastAPIAccounts,
):
    """S1: Signed tokens missing pwd_ts (e.g. from legacy v0.1.0a2 releases) must FAIL CLOSED."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "s1_legacy@example.com", "password": "LegacyPassword123!"},
        )
        assert reg_resp.status_code == 201

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "s1_legacy@example.com"
            )
            assert user is not None

        # Forge a signed token in legacy format without pwd_ts claim
        legacy_token = cookie_accounts.token_signer.create_token(
            {
                "sub": str(user.id),
                "email": "s1_legacy@example.com",
                "action": "reset_password",
            },
            max_age_seconds=900,
        )

        # Attempt redemption: MUST fail closed with 400
        resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": legacy_token, "new_password": "NewLegacyPassword456!"},
        )
        assert resp.status_code == 400
        assert "Invalid or expired" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_s1_tampered_or_invalid_pwd_ts_rejected_fail_closed(
    cookie_accounts: FastAPIAccounts,
):
    """S1: Tokens with non-integer or zero pwd_ts must FAIL CLOSED."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "s1_tamper@example.com", "password": "TamperPassword123!"},
        )

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "s1_tamper@example.com"
            )
            assert user is not None

        for bad_pwd_ts in [0, -1, "invalid_str", None, 999999]:
            token = cookie_accounts.token_signer.create_token(
                {
                    "sub": str(user.id),
                    "email": "s1_tamper@example.com",
                    "action": "reset_password",
                    "pwd_ts": bad_pwd_ts,
                },
                max_age_seconds=900,
            )
            resp = await client.post(
                "/api/v1/auth/reset-password",
                json={"token": token, "new_password": "NewTamperPassword456!"},
            )
            assert resp.status_code == 400
            assert "Invalid or expired" in resp.json()["detail"]


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
async def test_s3_no_raw_tokens_in_stdout_or_logs(
    adapter: SQLAlchemyAdapter,
    capsys: pytest.CaptureFixture,
    caplog: pytest.LogCaptureFixture,
):
    """S3: Ensure raw security tokens are never leaked to stdout, stderr, or loggers."""
    dispatched_verification_tokens: list[str] = []
    dispatched_reset_tokens: list[str] = []

    async def on_register(user, token):
        dispatched_verification_tokens.append(token)

    async def on_reset(user, token):
        dispatched_reset_tokens.append(token)

    accounts = FastAPIAccounts(
        adapter=adapter,
        secret_key="a" * 32,
        transport=CookieTransport(),
        debug=True,
        on_after_register=on_register,
        on_after_request_password_reset=on_reset,
    )

    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    with caplog.at_level(logging.DEBUG):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Register user
            reg_resp = await client.post(
                "/api/v1/auth/register",
                json={"email": "s3_audit@example.com", "password": "AuditPassword123!"},
            )
            assert reg_resp.status_code == 201

            # 2. Request password reset
            req_resp = await client.post(
                "/api/v1/auth/request-password-reset",
                json={"email": "s3_audit@example.com"},
            )
            assert req_resp.status_code == 200

    assert len(dispatched_verification_tokens) == 1
    assert len(dispatched_reset_tokens) == 1
    v_token = dispatched_verification_tokens[0]
    r_token = dispatched_reset_tokens[0]

    captured = capsys.readouterr()
    stdout_all = captured.out + captured.err
    log_all = caplog.text

    # Complete raw tokens MUST NEVER be present in stdout, stderr, or logs
    assert v_token not in stdout_all
    assert v_token not in log_all
    assert r_token not in stdout_all
    assert r_token not in log_all

    # Sensitive link texts from older versions must not exist
    assert "Verification link for" not in stdout_all
    assert "Password reset link for" not in stdout_all


def test_s4_secret_key_length_validation(adapter: SQLAlchemyAdapter):
    """S4: FastAPIAccounts must enforce at least 32-character secret keys at initialization."""
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


@pytest.mark.asyncio
async def test_s1_concurrent_reset_token_redemption(cookie_accounts: FastAPIAccounts):
    """S1: Simultaneous redemption of the exact same reset token must result in exactly 1 success and N-1 400 failures."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "s1_concurrent@example.com",
                "password": "OriginalPassword123!",
            },
        )

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "s1_concurrent@example.com"
            )
            assert user is not None
            assert user.password_credential is not None
            reset_token = cookie_accounts.generate_password_reset_token(
                user.id,
                "s1_concurrent@example.com",
                pwd_ts=user.password_credential.password_updated_at,
            )

        # Launch 5 concurrent reset requests simultaneously with the same token
        async def redeem(idx: int):
            return await client.post(
                "/api/v1/auth/reset-password",
                json={"token": reset_token, "new_password": f"NewConcurrentPwd{idx}!"},
            )

        responses = await asyncio.gather(*(redeem(i) for i in range(5)))
        status_codes = [r.status_code for r in responses]

        # Invariant: EXACTLY one request succeeds (200), and all other 4 fail (400)
        assert status_codes.count(200) == 1
        assert status_codes.count(400) == 4


@pytest.mark.asyncio
async def test_database_error_does_not_disclose_credentials_in_logs(
    cookie_accounts: FastAPIAccounts,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture,
):
    """S3/Security: Database exceptions containing sensitive hashes/passwords must never leak to logs or stdout/stderr."""
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.ext.asyncio import AsyncSession

    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    sensitive_fake_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$syntheticsecretleakvalue$fakehashdata"
    )
    sensitive_raw_pass = "SuperSensitivePasswordSecret999!"

    async def failing_commit_with_credentials(self):
        raise SQLAlchemyError(
            f"FAILED SQL: INSERT INTO password_credentials VALUES ('{sensitive_fake_hash}') WITH '{sensitive_raw_pass}'"
        )

    monkeypatch.setattr(AsyncSession, "commit", failing_commit_with_credentials)

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    with caplog.at_level(logging.DEBUG):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "s3_leaktest@example.com",
                    "password": sensitive_raw_pass,
                },
            )
            assert resp.status_code == 500

    captured = capsys.readouterr()
    all_output = captured.out + captured.err + caplog.text

    assert sensitive_fake_hash not in all_output
    assert sensitive_raw_pass not in all_output
