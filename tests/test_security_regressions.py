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


@pytest.mark.asyncio
async def test_change_password_rate_limiting_authenticated(adapter: SQLAlchemyAdapter):
    """P0 #8: Verify /change-password route rate limiting for authenticated sessions."""
    accounts = FastAPIAccounts(
        adapter=adapter,
        secret_key="rate-limit-secret-key-at-least-32-chars-long",
        transport=CookieTransport(cookie_secure=False),
        allowed_origins=["http://test"],
    )
    accounts.change_password_rate_limit = (2, 60)

    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Bootstrap CSRF
        csrf_init = await client.get("/api/v1/auth/csrf")
        pre_csrf = csrf_init.json()["csrf_token"]
        pre_headers = {"Origin": "http://test", "X-CSRF-Token": pre_csrf}

        # Register and Login
        reg = await client.post(
            "/api/v1/auth/register",
            json={"email": "cp_rate@example.com", "password": "Password123!"},
            headers=pre_headers,
        )
        assert reg.status_code == 201

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "cp_rate@example.com", "password": "Password123!"},
            headers=pre_headers,
        )
        assert login.status_code == 200
        csrf_tok = client.cookies.get("fastapi_accounts_csrf")
        assert csrf_tok is not None
        headers = {"Origin": "http://test", "X-CSRF-Token": csrf_tok}

        # Attempt 1: wrong password, counts towards limit
        r1 = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongPassword1!",
                "new_password": "NewPassword123!",
            },
            headers=headers,
        )
        assert r1.status_code == 400

        # Attempt 2: wrong password, counts towards limit
        r2 = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongPassword2!",
                "new_password": "NewPassword123!",
            },
            headers=headers,
        )
        assert r2.status_code == 400

        # Attempt 3: exceeds limit -> 429 Too Many Requests
        r3 = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "Password123!",
                "new_password": "NewPassword123!",
            },
            headers=headers,
        )
        assert r3.status_code == 429
        assert "Retry-After" in r3.headers


@pytest.mark.asyncio
async def test_in_memory_sliding_window_limiter_capacity_and_multi_window():
    """P0 #8: Verify rate limiter capacity eviction preserves existing keys and handles distinct window durations."""
    from fastapi_accounts.security.rate_limiter import InMemorySlidingWindowLimiter

    limiter = InMemorySlidingWindowLimiter(max_keys=2)

    # 1. Capacity eviction must NOT reset an existing key's exhausted quota
    # Exhaust quota on key1 (max 1 req per hour)
    ok1, _ = await limiter.check_rate_limit("key1", max_requests=1, window_seconds=3600)
    assert ok1 is True
    ok1_exhausted, _ = await limiter.check_rate_limit(
        "key1", max_requests=1, window_seconds=3600
    )
    assert ok1_exhausted is False

    # Insert key2 (reaches capacity=2)
    ok2, _ = await limiter.check_rate_limit("key2", max_requests=1, window_seconds=3600)
    assert ok2 is True

    # Re-checking key1 at capacity must still be rejected (NOT evicted and reset!)
    ok1_recheck, _ = await limiter.check_rate_limit(
        "key1", max_requests=1, window_seconds=3600
    )
    assert ok1_recheck is False

    # Inserting key3 forces LRU eviction of key2 (since key1 was accessed more recently)
    ok3, _ = await limiter.check_rate_limit("key3", max_requests=1, window_seconds=3600)
    assert ok3 is True
    # key2 was evicted; key1 is still retained and still exhausted
    ok1_still_exhausted, _ = await limiter.check_rate_limit(
        "key1", max_requests=1, window_seconds=3600
    )
    assert ok1_still_exhausted is False

    # 2. Multi-window cross-talk isolation
    limiter_multi = InMemorySlidingWindowLimiter(max_keys=10)
    # k_long has a 1-hour window
    ok_long1, _ = await limiter_multi.check_rate_limit(
        "k_long", max_requests=1, window_seconds=3600
    )
    assert ok_long1 is True
    ok_long2, _ = await limiter_multi.check_rate_limit(
        "k_long", max_requests=1, window_seconds=3600
    )
    assert ok_long2 is False

    # k_short has a 0.05-second window
    ok_short1, _ = await limiter_multi.check_rate_limit(
        "k_short", max_requests=1, window_seconds=1
    )
    assert ok_short1 is True

    # k_long MUST NOT have been purged by k_short!
    ok_long3, _ = await limiter_multi.check_rate_limit(
        "k_long", max_requests=1, window_seconds=3600
    )
    assert ok_long3 is False


def test_resolve_client_ip_trusted_proxy():
    """P0 #8: Verify right-to-left untrusted proxy resolution."""
    from starlette.datastructures import Headers

    from fastapi_accounts.security.rate_limiter import resolve_client_ip

    class DummyClient:
        def __init__(self, host: str):
            self.host = host

    class DummyRequest:
        def __init__(self, client_host: str, headers_dict: dict[str, str]):
            self.client = DummyClient(client_host)
            self.headers = Headers(headers_dict)

    # 1. Untrusted peer: always returns client.host, ignoring X-Forwarded-For
    req0 = DummyRequest("10.0.0.1", {"x-forwarded-for": "198.51.100.1, 203.0.113.195"})
    assert resolve_client_ip(req0, trusted_proxies=["127.0.0.1"]) == "10.0.0.1"

    # 2. Trusted peer proxy: returns first untrusted IP from right to left
    req1 = DummyRequest("10.0.0.1", {"x-forwarded-for": "198.51.100.1, 203.0.113.195"})
    assert resolve_client_ip(req1, trusted_proxies=["10.0.0.1"]) == "203.0.113.195"

    # 3. Two trusted proxies: client is 198.51.100.1
    req2 = DummyRequest("10.0.0.1", {"x-forwarded-for": "198.51.100.1, 203.0.113.195"})
    assert (
        resolve_client_ip(req2, trusted_proxies=["10.0.0.1", "203.0.113.195"])
        == "198.51.100.1"
    )


@pytest.mark.asyncio
async def test_csrf_cross_type_and_session_ab_isolation(
    cookie_accounts: FastAPIAccounts,
):
    """P0 #7: Cross-type CSRF token rejection and session A/B isolation."""
    assert isinstance(cookie_accounts.transport, CookieTransport)
    cookie_accounts.transport.csrf_protect = True
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://test") as client_a,
        AsyncClient(transport=transport, base_url="http://test") as client_b,
    ):
        # Bootstrap pre-auth CSRF for both clients
        csrf_init_a = await client_a.get("/api/v1/auth/csrf")
        pre_auth_csrf_a = csrf_init_a.json()["csrf_token"]

        csrf_init_b = await client_b.get("/api/v1/auth/csrf")
        pre_auth_csrf_b = csrf_init_b.json()["csrf_token"]

        # Register User A and User B
        await client_a.post(
            "/api/v1/auth/register",
            json={"email": "user_a@example.com", "password": "PasswordA123!"},
            headers={"Origin": "http://test", "X-CSRF-Token": pre_auth_csrf_a},
        )
        await client_b.post(
            "/api/v1/auth/register",
            json={"email": "user_b@example.com", "password": "PasswordB123!"},
            headers={"Origin": "http://test", "X-CSRF-Token": pre_auth_csrf_b},
        )

        # Login User A
        login_a = await client_a.post(
            "/api/v1/auth/login",
            json={"email": "user_a@example.com", "password": "PasswordA123!"},
            headers={"Origin": "http://test", "X-CSRF-Token": pre_auth_csrf_a},
        )
        assert login_a.status_code == 200
        csrf_a = client_a.cookies.get("fastapi_accounts_csrf")
        assert csrf_a is not None

        # Login User B
        login_b = await client_b.post(
            "/api/v1/auth/login",
            json={"email": "user_b@example.com", "password": "PasswordB123!"},
            headers={"Origin": "http://test", "X-CSRF-Token": pre_auth_csrf_b},
        )
        assert login_b.status_code == 200
        csrf_b = client_b.cookies.get("fastapi_accounts_csrf")
        assert csrf_b is not None

        # 1. User A sends session B's CSRF token -> 403 Forbidden
        cross_csrf_resp = await client_a.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "PasswordA123!",
                "new_password": "NewPasswordA456!",
            },
            headers={"Origin": "http://test", "X-CSRF-Token": csrf_b},
        )
        assert cross_csrf_resp.status_code == 403

        # 2. User A sends pre-auth CSRF token to authenticated mutation -> 403 Forbidden
        pre_auth_on_auth_resp = await client_a.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "PasswordA123!",
                "new_password": "NewPasswordA456!",
            },
            headers={"Origin": "http://test", "X-CSRF-Token": pre_auth_csrf_a},
        )
        assert pre_auth_on_auth_resp.status_code == 403

        # 3. User A sends valid CSRF token -> 200 OK
        valid_resp = await client_a.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "PasswordA123!",
                "new_password": "NewPasswordA456!",
            },
            headers={"Origin": "http://test", "X-CSRF-Token": csrf_a},
        )
        assert valid_resp.status_code == 200

        # 4. User A logs out (POST /logout with session CSRF)
        logout1 = await client_a.post(
            "/api/v1/auth/logout",
            headers={"Origin": "http://test", "X-CSRF-Token": csrf_a},
        )
        assert logout1.status_code == 200

        # Second logout without CSRF is 403 Forbidden because CookieTransport enforces CSRF on all mutating endpoints
        logout_no_csrf = await client_a.post("/api/v1/auth/logout")
        assert logout_no_csrf.status_code == 403

        # Second logout with valid pre-auth CSRF token succeeds idempotently
        csrf_init_after = await client_a.get("/api/v1/auth/csrf")
        fresh_pre_auth = csrf_init_after.json()["csrf_token"]
        logout2 = await client_a.post(
            "/api/v1/auth/logout",
            headers={"Origin": "http://test", "X-CSRF-Token": fresh_pre_auth},
        )
        assert logout2.status_code == 200

        # Calling /me is now 401 Unauthorized
        assert (await client_a.get("/api/v1/auth/me")).status_code == 401


@pytest.mark.asyncio
async def test_login_reset_in_flight_race():
    """F1 / P0 #1, P0 #2, P0 #10: Verify in-flight login with old password fails atomically if password reset completes concurrently."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "race.db")
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        adapter = SQLAlchemyAdapter(engine=engine)
        accounts = FastAPIAccounts(
            adapter=adapter,
            secret_key="race-secret-test-key-long-enough-32bytes",
            transport=CookieTransport(cookie_secure=False),
        )
        app = FastAPI()
        app.include_router(accounts.router, prefix="/api/v1/auth")
        transport = ASGITransport(app=app)

        async with (
            AsyncClient(transport=transport, base_url="http://test") as victim,
            AsyncClient(transport=transport, base_url="http://test") as attacker,
        ):

            async def get_csrf_headers(client: AsyncClient) -> dict[str, str]:
                csrf_resp = await client.get("/api/v1/auth/csrf")
                token = csrf_resp.json()["csrf_token"]
                return {"Origin": "http://test", "X-CSRF-Token": token}

            # 1. Register victim user
            victim_pre_headers = await get_csrf_headers(victim)
            reg_resp = await victim.post(
                "/api/v1/auth/register",
                json={"email": "race@example.com", "password": "OldPassword123!"},
                headers=victim_pre_headers,
            )
            assert reg_resp.status_code == 201

            # 2. Generate password reset token
            async with adapter.session_maker() as db:
                user = await adapter.get_user_by_email(db, "race@example.com")
                assert user is not None
                reset_token = accounts.service.generate_password_reset_token(
                    user.id, "race@example.com", credential_version=1
                )

            # 3. Intercept create_session to pause attacker's in-flight login after authentication
            original_create_session = accounts.adapter.create_session
            login_paused = asyncio.Event()
            can_resume_login = asyncio.Event()

            async def paused_create_session(*args, **kwargs):
                login_paused.set()
                await can_resume_login.wait()
                return await original_create_session(*args, **kwargs)

            accounts.adapter.create_session = paused_create_session

            # 4. Attacker initiates login with OldPassword123!
            attacker_pre_headers = await get_csrf_headers(attacker)
            attacker_login_task = asyncio.create_task(
                attacker.post(
                    "/api/v1/auth/login",
                    json={"email": "race@example.com", "password": "OldPassword123!"},
                    headers=attacker_pre_headers,
                )
            )

            # 5. Wait until attacker's login is paused inside create_session
            await asyncio.wait_for(login_paused.wait(), timeout=5.0)

            # 6. Victim resets password while attacker's login is in-flight
            victim_reset_headers = await get_csrf_headers(victim)
            reset_resp = await victim.post(
                "/api/v1/auth/reset-password",
                json={"token": reset_token, "new_password": "NewPassword456!"},
                headers=victim_reset_headers,
            )
            assert reset_resp.status_code == 200

            # 7. Unpause attacker's create_session -> must fail atomically due to credential_version mismatch
            can_resume_login.set()
            attacker_login_resp = await attacker_login_task
            assert attacker_login_resp.status_code == 401

            # 8. Restore create_session
            accounts.adapter.create_session = original_create_session

            # 9. Attacker attempt to access /me must fail with 401
            attacker_me_resp = await attacker.get("/api/v1/auth/me")
            assert attacker_me_resp.status_code == 401

            # 10. Subsequent login with old password must fail with 401
            fresh_login_headers = await get_csrf_headers(attacker)
            fresh_old_login_resp = await attacker.post(
                "/api/v1/auth/login",
                json={"email": "race@example.com", "password": "OldPassword123!"},
                headers=fresh_login_headers,
            )
            assert fresh_old_login_resp.status_code == 401

            # 11. Login with new password succeeds
            fresh_new_headers = await get_csrf_headers(victim)
            victim_new_login_resp = await victim.post(
                "/api/v1/auth/login",
                json={"email": "race@example.com", "password": "NewPassword456!"},
                headers=fresh_new_headers,
            )
            assert victim_new_login_resp.status_code == 200

        await engine.dispose()


@pytest.mark.asyncio
async def test_rate_limiter_expired_key_renewal_under_capacity():
    """F4 / P0 #8: Retain window durations when expired keys start a new window under capacity pressure."""
    import time

    from fastapi_accounts.security.rate_limiter import InMemorySlidingWindowLimiter

    limiter = InMemorySlidingWindowLimiter(max_keys=2)

    # 1. Add key1 with 3600s window duration
    ok1, _ = await limiter.check_rate_limit(
        "key_long", max_requests=1, window_seconds=3600
    )
    assert ok1 is True
    assert limiter._window_durations["key_long"] == 3600

    # 2. Simulate time passing so key_long expires
    limiter._windows["key_long"] = [time.monotonic() - 3700]

    # 3. Key_long makes a new request -> cleans expired timestamp, pops metadata, but restores window_duration=3600
    ok_renew, _ = await limiter.check_rate_limit(
        "key_long", max_requests=1, window_seconds=3600
    )
    assert ok_renew is True
    assert limiter._window_durations["key_long"] == 3600

    # 4. Add key_short with 60s window duration
    ok_short, _ = await limiter.check_rate_limit(
        "key_short", max_requests=1, window_seconds=60
    )
    assert ok_short is True

    # 5. Add key_third with 60s window duration after 120s simulated
    limiter._windows["key_short"] = [time.monotonic() - 120]

    # Key_long is at age 120s, which is NOT expired for its 3600s window
    ok_third, _ = await limiter.check_rate_limit(
        "key_third", max_requests=1, window_seconds=60
    )
    assert ok_third is True

    # key_short was expired and cleaned; key_long must still be retained because its 3600s window was preserved
    assert "key_long" in limiter._windows


@pytest.mark.asyncio
async def test_login_reset_adapter_entry_interleaving_race():
    """F1 / High: Concurrency race when session creation is intercepted at the adapter entry boundary after password verification.

    Even if an in-flight login executes after verifying an older credential version,
    the issued session has sessions.credential_version = 1.
    Once password reset commits (bumping credential_version to 2),
    accessing /me with the in-flight login's session MUST return 401 Unauthorized.
    """
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "race_flush.db")
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        adapter = SQLAlchemyAdapter(engine=engine)
        accounts = FastAPIAccounts(
            adapter=adapter,
            secret_key="flush-boundary-race-test-secret-key-32bytes",
            transport=CookieTransport(cookie_secure=False),
        )
        app = FastAPI()
        app.include_router(accounts.router, prefix="/api/v1/auth")
        transport = ASGITransport(app=app)

        original_create_session = adapter.create_session
        reached_insert = asyncio.Event()
        release_insert = asyncio.Event()
        intercept_active = False

        async def paused_create_session(session: AsyncSession, *args, **kwargs):
            if intercept_active:
                reached_insert.set()
                await release_insert.wait()
            return await original_create_session(session, *args, **kwargs)

        adapter.create_session = paused_create_session

        try:
            async with (
                AsyncClient(transport=transport, base_url="http://test") as victim,
                AsyncClient(transport=transport, base_url="http://test") as attacker,
            ):

                async def csrf(client: AsyncClient) -> dict[str, str]:
                    r = await client.get("/api/v1/auth/csrf")
                    return {
                        "Origin": "http://test",
                        "X-CSRF-Token": r.json()["csrf_token"],
                    }

                # 1. Register victim
                reg = await victim.post(
                    "/api/v1/auth/register",
                    json={
                        "email": "flushrace@example.com",
                        "password": "OldPassword123!",
                    },
                    headers=await csrf(victim),
                )
                assert reg.status_code == 201

                # 2. Generate password reset token
                async with adapter.session_maker() as db:
                    user = await adapter.get_user_by_email(db, "flushrace@example.com")
                    assert user is not None
                    token = accounts.service.generate_password_reset_token(
                        user.id, "flushrace@example.com", credential_version=1
                    )

                # 3. Arm session creation interception and start attacker login
                intercept_active = True
                attacker_task = asyncio.create_task(
                    attacker.post(
                        "/api/v1/auth/login",
                        json={
                            "email": "flushrace@example.com",
                            "password": "OldPassword123!",
                        },
                        headers=await csrf(attacker),
                    )
                )

                # 4. Wait until attacker login is paused inside create_session
                await asyncio.wait_for(reached_insert.wait(), timeout=5.0)

                # 5. Victim resets password to NewPassword456! (bumping version to 2)
                reset = await victim.post(
                    "/api/v1/auth/reset-password",
                    json={"token": token, "new_password": "NewPassword456!"},
                    headers=await csrf(victim),
                )
                assert reset.status_code == 200

                # Victim's previous session must be invalidated
                assert (await victim.get("/api/v1/auth/me")).status_code == 401

                # 6. Release attacker's paused create_session
                release_insert.set()
                _attacker_login_resp = await attacker_task

                # 7. Non-negotiable security invariant:
                # Regardless of whether attacker's login HTTP status is 200 or 401,
                # any authenticated request on /me using that issued session MUST BE 401 Unauthorized.
                attacker_me_resp = await attacker.get("/api/v1/auth/me")
                assert attacker_me_resp.status_code == 401

                # 8. Subsequent login with old password fails
                fresh_old_resp = await attacker.post(
                    "/api/v1/auth/login",
                    json={
                        "email": "flushrace@example.com",
                        "password": "OldPassword123!",
                    },
                    headers=await csrf(attacker),
                )
                assert fresh_old_resp.status_code == 401
        finally:
            adapter.create_session = original_create_session
            await engine.dispose()


@pytest.mark.asyncio
async def test_create_session_omitted_version_preserves_active_generation():
    """F1: Calling create_session with expected_credential_version=None dynamically resolves active version."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "omitted_version.db")
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        adapter = SQLAlchemyAdapter(engine=engine)
        accounts = FastAPIAccounts(
            adapter=adapter,
            secret_key="omitted-version-secret-key-32-bytes-long",
            transport=CookieTransport(cookie_secure=False),
        )
        app = FastAPI()
        app.include_router(accounts.router, prefix="/api/v1/auth")
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:

            async def csrf() -> dict[str, str]:
                r = await client.get("/api/v1/auth/csrf")
                return {"Origin": "http://test", "X-CSRF-Token": r.json()["csrf_token"]}

            # 1. Register user (starts at version 1)
            reg = await client.post(
                "/api/v1/auth/register",
                json={"email": "omitted@example.com", "password": "Password123!"},
                headers=await csrf(),
            )
            assert reg.status_code == 201

            # Login to authenticate
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "omitted@example.com", "password": "Password123!"},
                headers=await csrf(),
            )
            assert login_resp.status_code == 200

            # 2. Change password via API to advance credential_version to 2
            change = await client.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "Password123!",
                    "new_password": "NewPassword123!",
                },
                headers=await csrf(),
            )
            assert change.status_code == 200

            # 3. Create a session via service with expected_credential_version=None
            async with adapter.session_maker() as db:
                user = await adapter.get_user_by_email(db, "omitted@example.com")
                assert user is not None
                raw_token, _session_id = await accounts.service.create_session(
                    session=db,
                    user_id=user.id,
                    expected_credential_version=None,
                )
                await db.commit()

            # 4. Authenticate session directly
            async with adapter.session_maker() as db:
                auth_res = await adapter.get_session_and_user(db, raw_token)
                assert auth_res is not None
                sess_rec, user_rec = auth_res
                # Must have resolved user's active version (2), NOT defaulted to 1
                assert sess_rec.credential_version == 2
                assert user_rec.id == user.id

        await engine.dispose()


@pytest.mark.asyncio
async def test_change_password_preserves_current_session_with_generation_bump():
    """F1: change_password increments credential_version on both credentials and the current session."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "change_preserve.db")
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        adapter = SQLAlchemyAdapter(engine=engine)
        accounts = FastAPIAccounts(
            adapter=adapter,
            secret_key="change-preserve-secret-key-32-bytes-long",
            transport=CookieTransport(cookie_secure=False),
        )
        app = FastAPI()
        app.include_router(accounts.router, prefix="/api/v1/auth")
        transport = ASGITransport(app=app)

        async with (
            AsyncClient(transport=transport, base_url="http://test") as active_client,
            AsyncClient(transport=transport, base_url="http://test") as other_client,
        ):

            async def csrf(c: AsyncClient) -> dict[str, str]:
                r = await c.get("/api/v1/auth/csrf")
                return {"Origin": "http://test", "X-CSRF-Token": r.json()["csrf_token"]}

            # 1. Register user
            reg = await active_client.post(
                "/api/v1/auth/register",
                json={"email": "preserve@example.com", "password": "Password123!"},
                headers=await csrf(active_client),
            )
            assert reg.status_code == 201

            # 2. Login active_client
            active_login = await active_client.post(
                "/api/v1/auth/login",
                json={"email": "preserve@example.com", "password": "Password123!"},
                headers=await csrf(active_client),
            )
            assert active_login.status_code == 200

            # 3. Login other_client
            other_login = await other_client.post(
                "/api/v1/auth/login",
                json={"email": "preserve@example.com", "password": "Password123!"},
                headers=await csrf(other_client),
            )
            assert other_login.status_code == 200

            # Both can access /me
            assert (await active_client.get("/api/v1/auth/me")).status_code == 200
            assert (await other_client.get("/api/v1/auth/me")).status_code == 200

            # 4. active_client changes password
            change = await active_client.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "Password123!",
                    "new_password": "NewPassword123!",
                },
                headers=await csrf(active_client),
            )
            assert change.status_code == 200

            # 5. active_client MUST still be authenticated (current session updated to version 2)
            active_me = await active_client.get("/api/v1/auth/me")
            assert active_me.status_code == 200

            # 6. other_client MUST be revoked / unauthorized
            other_me = await other_client.get("/api/v1/auth/me")
            assert other_me.status_code == 401

        await engine.dispose()
