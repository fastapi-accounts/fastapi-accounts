from __future__ import annotations

import asyncio
import logging
import os
import tempfile

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.models.default import Base
from fastapi_accounts.transports.cookie import CookieTransport


@pytest.mark.asyncio
async def test_s1_password_reset_token_single_use(cookie_accounts: FastAPIAccounts):
    """S1: Monotonic credential_version guarantees password reset token is strictly single-use."""
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

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "s1_replay@example.com"
            )
            assert user is not None
            cred = await cookie_accounts.adapter.get_password_credential(
                session, user.id
            )
            assert cred is not None
            reset_token = cookie_accounts.service.generate_password_reset_token(
                user.id, "s1_replay@example.com", cred.credential_version
            )

        # First use: must SUCCEED
        resp1 = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": reset_token, "new_password": "NewPasswordOne123!"},
        )
        assert resp1.status_code == 200

        # Replay attempt with exact same token: must FAIL with 400
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
    """S1: Password change increments credential_version, immediately invalidating pending reset tokens."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
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
            reset_token = cookie_accounts.service.generate_password_reset_token(
                user.id, "s1_inval@example.com", cred.credential_version
            )

        # Change password via endpoint
        change_resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "OldPassword123!",
                "new_password": "ChangedPassword123!",
            },
        )
        assert change_resp.status_code == 200

        # Previous reset token must FAIL closed
        reset_resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": reset_token, "new_password": "AttemptPassword456!"},
        )
        assert reset_resp.status_code == 400


@pytest.mark.asyncio
async def test_s1_malformed_and_boolean_cred_v_rejected_fail_closed(
    cookie_accounts: FastAPIAccounts,
):
    """S1: Tokens with boolean, non-positive, string, or missing cred_v must FAIL CLOSED."""
    cookie_accounts.reset_password_rate_limit = (20, 300)
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

        # Test boolean True (which is int subclass in Python), False, 0, negative, string, None
        for bad_cred_v in [True, False, 0, -1, "invalid_str", None]:
            token = cookie_accounts.token_signer.create_token(
                {
                    "sub": str(user.id),
                    "email": "s1_tamper@example.com",
                    "action": "reset_password",
                    "token_v": 2,
                    "cred_v": bad_cred_v,
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
        assert "password_credential" not in data
        assert "hashed_password" not in data
        assert "$argon2" not in login_resp.text

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
        assert "$argon2" not in login_resp.text


@pytest.mark.asyncio
async def test_s3_no_raw_tokens_or_prefixes_in_stdout_or_logs(
    adapter: SQLAlchemyAdapter,
    capsys: pytest.CaptureFixture,
    caplog: pytest.LogCaptureFixture,
):
    """S3: Ensure zero token material or prefixes appear in logs or output."""
    dispatched_verification_tokens: list[str] = []

    async def on_register(user, token):
        dispatched_verification_tokens.append(token)

    accounts = FastAPIAccounts(
        adapter=adapter,
        secret_key="a" * 32,
        transport=CookieTransport(cookie_secure=False, csrf_protect=False),
        allowed_origins=["http://test"],
        debug=True,
        on_after_register=on_register,
    )

    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    with caplog.at_level(logging.DEBUG):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            reg_resp = await client.post(
                "/api/v1/auth/register",
                json={"email": "s3_audit@example.com", "password": "AuditPassword123!"},
            )
            assert reg_resp.status_code == 201

    assert len(dispatched_verification_tokens) == 1
    v_token = dispatched_verification_tokens[0]

    captured = capsys.readouterr()
    all_out = captured.out + captured.err + caplog.text

    assert v_token not in all_out
    assert v_token[:8] not in all_out


@pytest.mark.asyncio
async def test_s1_concurrent_reset_token_redemption():
    """S1: 5 simultaneous redemptions with identical token result in exactly 1 success (200) and 4 failures (400)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "concurrency_test.db")
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_maker = async_sessionmaker(
            bind=engine, class_=AsyncSession, expire_on_commit=False
        )
        adapter = SQLAlchemyAdapter(session_maker=session_maker, engine=engine)
        accounts = FastAPIAccounts(
            adapter=adapter,
            secret_key="a" * 32,
            transport=CookieTransport(cookie_secure=False, csrf_protect=False),
            allowed_origins=["http://test"],
        )

        app = FastAPI()
        app.include_router(accounts.router, prefix="/api/v1/auth")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "s1_concurrent@example.com",
                    "password": "OriginalPassword123!",
                },
            )

            async with adapter.session_maker() as session:
                user = await adapter.get_user_by_email(
                    session, "s1_concurrent@example.com"
                )
                assert user is not None
                cred = await adapter.get_password_credential(session, user.id)
                assert cred is not None
                reset_token = accounts.service.generate_password_reset_token(
                    user.id, "s1_concurrent@example.com", cred.credential_version
                )

            async def redeem(idx: int):
                return await client.post(
                    "/api/v1/auth/reset-password",
                    json={
                        "token": reset_token,
                        "new_password": f"NewConcurrentPwd{idx}!",
                    },
                )

            responses = await asyncio.gather(*(redeem(i) for i in range(5)))
            status_codes = [r.status_code for r in responses]

            assert status_codes.count(200) == 1
            assert status_codes.count(400) == 4

        await engine.dispose()


@pytest.mark.asyncio
async def test_utf8_password_byte_length_limit(cookie_accounts: FastAPIAccounts):
    """P0 #9: Password fields exceeding 128 UTF-8 bytes must be rejected."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 50 emojis where each emoji is 4 UTF-8 bytes = 200 bytes (> 128 bytes limit)
        long_emoji_password = "🔐" * 50
        assert len(long_emoji_password.encode("utf-8")) == 200

        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "emoji_long@example.com", "password": long_emoji_password},
        )
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_full_csrf_and_origin_protection_matrix(cookie_accounts: FastAPIAccounts):
    """P0 #7: Complete CSRF bootstrap, session binding, Origin/Referer validation, and mutation coverage."""
    assert isinstance(cookie_accounts.transport, CookieTransport)
    cookie_accounts.transport.csrf_protect = True
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Bootstrap GET /csrf
        csrf_resp = await client.get("/api/v1/auth/csrf")
        assert csrf_resp.status_code == 200
        assert "no-store" in csrf_resp.headers.get("cache-control", "")
        csrf_token = csrf_resp.json()["csrf_token"]
        assert "fastapi_accounts_csrf" in csrf_resp.cookies

        # 2. Reject sibling origin
        bad_origin_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "csrf_test@example.com", "password": "Password123!"},
            headers={"Origin": "https://evil.example.com", "X-CSRF-Token": csrf_token},
        )
        assert bad_origin_resp.status_code == 403

        # 3. Reject missing Origin & Referer
        no_origin_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "csrf_test@example.com", "password": "Password123!"},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert no_origin_resp.status_code == 403

        # 4. Valid register with CSRF + Origin -> 201 Created
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "csrf_test@example.com", "password": "Password123!"},
            headers={"Origin": "http://test", "X-CSRF-Token": csrf_token},
        )
        assert reg_resp.status_code == 201

        # 5. Valid login rotates to session-bound CSRF token -> 200 OK
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "csrf_test@example.com", "password": "Password123!"},
            headers={"Origin": "http://test", "X-CSRF-Token": csrf_token},
        )
        assert login_resp.status_code == 200
        # Cookie transport sets new session-bound CSRF cookie
        auth_csrf_cookie = client.cookies.get("fastapi_accounts_csrf")
        assert auth_csrf_cookie is not None

        # 6. Pre-auth CSRF token fails for authenticated mutation (/change-password)
        bad_auth_csrf = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "Password123!",
                "new_password": "NewPassword456!",
            },
            headers={"Origin": "http://test", "X-CSRF-Token": csrf_token},
        )
        assert bad_auth_csrf.status_code == 403

        # 7. Authenticated CSRF token succeeds -> 200 OK
        good_change = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "Password123!",
                "new_password": "NewPassword456!",
            },
            headers={"Origin": "http://test", "X-CSRF-Token": auth_csrf_cookie},
        )
        assert good_change.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route,payload,method",
    [
        (
            "/api/v1/auth/login",
            {"email": "rate_user@example.com", "password": "Password123!"},
            "POST",
        ),
        (
            "/api/v1/auth/register",
            {"email": "rate_reg@example.com", "password": "Password123!"},
            "POST",
        ),
        (
            "/api/v1/auth/request-password-reset",
            {"email": "rate_user@example.com"},
            "POST",
        ),
        (
            "/api/v1/auth/reset-password",
            {"token": "invalid_mock_token", "new_password": "Password123!"},
            "POST",
        ),
        (
            "/api/v1/auth/request-verify-email",
            {"email": "rate_user@example.com"},
            "POST",
        ),
        ("/api/v1/auth/verify-email", {"token": "invalid_mock_token"}, "POST"),
    ],
)
async def test_seven_routes_parameterized_rate_limiting(
    adapter: SQLAlchemyAdapter, route: str, payload: dict, method: str
):
    """P0 #8: Parameterized test verifying rate limits return HTTP 429 across sensitive routes."""
    accounts = FastAPIAccounts(
        adapter=adapter,
        secret_key="rate-limit-secret-key-at-least-32-chars-long",
        transport=CookieTransport(cookie_secure=False),
        allowed_origins=["http://test"],
    )
    # Set tight rate limit (2 requests / 60 seconds)
    accounts.login_rate_limit = (2, 60)
    accounts.register_rate_limit = (2, 60)
    accounts.request_reset_rate_limit = (2, 60)
    accounts.reset_password_rate_limit = (2, 60)
    accounts.request_verify_rate_limit = (2, 60)
    accounts.verify_email_rate_limit = (2, 60)
    accounts.change_password_rate_limit = (2, 60)

    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Get CSRF
        csrf_res = await client.get("/api/v1/auth/csrf")
        csrf_tok = csrf_res.json()["csrf_token"]
        headers = {"Origin": "http://test", "X-CSRF-Token": csrf_tok}

        # Request 1: allowed
        res1 = await client.post(route, json=payload, headers=headers)
        assert res1.status_code != 429
        # Request 2: allowed
        res2 = await client.post(route, json=payload, headers=headers)
        assert res2.status_code != 429
        # Request 3: must exceed limit and return 429
        res3 = await client.post(route, json=payload, headers=headers)
        assert res3.status_code == 429
        assert "Retry-After" in res3.headers
