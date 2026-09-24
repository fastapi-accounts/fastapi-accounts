import asyncio
import uuid

import pytest
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from httpx import ASGITransport, AsyncClient

from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.transports.cookie import CookieTransport


# 1. OpenAPI and route semantics tests
def test_openapi_route_semantics(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")
    schema = get_openapi(title="test", version="1", routes=app.routes)

    paths = schema["paths"]

    # Required routes
    assert paths["/api/v1/auth/me"]["get"]["security"] == [{"APIKeyCookie": []}]
    assert paths["/api/v1/auth/change-password"]["post"]["security"] == [
        {"APIKeyCookie": []}
    ]

    # Optional routes
    assert paths["/api/v1/auth/logout"]["post"]["security"] == [
        {"APIKeyCookie": []},
        {},
    ]
    assert paths["/api/v1/auth/csrf"]["get"]["security"] == [{"APIKeyCookie": []}, {}]
    assert paths["/api/v1/auth/verify-email"]["post"]["security"] == [{"APIKeyCookie": []}, {}]
    assert paths["/api/v1/auth/reset-password"]["post"]["security"] == [{"APIKeyCookie": []}, {}]

    # Public routes
    assert "security" not in paths["/api/v1/auth/register"]["post"]
    assert "security" not in paths["/api/v1/auth/login"]["post"]
    assert "security" not in paths["/api/v1/auth/request-password-reset"]["post"]
    assert "security" not in paths["/api/v1/auth/request-verify-email"]["post"]


# 2. SQL queries assertion (no password loaded on /me)
@pytest.mark.asyncio
async def test_no_password_loaded_on_me(cookie_accounts: FastAPIAccounts):
    import sqlalchemy as sa

    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reg = await client.post(
            "/api/v1/auth/register",
            json={"email": "sql@example.com", "password": "SecurePassword123!"},
        )
        assert reg.status_code == 201

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sql@example.com", "password": "SecurePassword123!"},
        )
        assert login.status_code == 200
        cookie = login.cookies.get("fastapi_accounts_session")

        queries = []

        def before_cursor_execute(
            conn, cursor, statement, parameters, context, executemany
        ):
            queries.append(statement)

        engine = cookie_accounts.adapter.engine
        assert engine is not None
        sa.event.listen(
            engine.sync_engine,
            "before_cursor_execute",
            before_cursor_execute,
        )

        try:
            me_resp = await client.get(
                "/api/v1/auth/me",
                cookies={"fastapi_accounts_session": cookie},  # type: ignore
            )
            assert me_resp.status_code == 200
        finally:
            engine = cookie_accounts.adapter.engine
            assert engine is not None
            sa.event.remove(
                engine.sync_engine,
                "before_cursor_execute",
                before_cursor_execute,
            )

        # Assert no queries select from password_credentials
        for q in queries:
            assert (
                "password_credentials" not in q.lower()
                or "hashed_password" not in q.lower()
            )


# 3. Concurrent verification replay
@pytest.mark.asyncio
async def test_concurrent_verification_replay(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        _ = await client.post(
            "/api/v1/auth/register",
            json={"email": "concurrent@example.com", "password": "SecurePassword123!"},
        )

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "concurrent@example.com"
            )
            assert user is not None
            email_id = user.emails[0].id

        token = cookie_accounts.service.generate_email_verification_token(
            user.id, email_id, "concurrent@example.com"
        )

        # Fire 5 concurrent verification requests
        async def do_verify():
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                return await c.post("/api/v1/auth/verify-email", json={"token": token})

        results = await asyncio.gather(*(do_verify() for _ in range(5)))

        successes = sum(1 for r in results if r.status_code == 200)
        failures = sum(1 for r in results if r.status_code == 400)

        assert successes == 1
        assert failures == 4


# 4. Token identity rejection tests
@pytest.mark.asyncio
async def test_verification_token_rejection(cookie_accounts: FastAPIAccounts):
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Forge a token with an invalid email_id
        token = cookie_accounts.service.token_signer.create_token(
            {
                "action": "verify_email",
                "token_v": 2,
                "sub": str(uuid.uuid4()),
                "email_id": "not-a-uuid",
                "email": "x@x.com",
            }
        )
        resp = await client.post("/api/v1/auth/verify-email", json={"token": token})
        assert resp.status_code == 400

        # Create real user to ensure token failure is specifically due to float token_v
        await client.post(
            "/api/v1/auth/register",
            json={"email": "real@example.com", "password": "SecurePassword123!"},
        )
        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "real@example.com"
            )
            assert user is not None
            real_user_id = str(user.id)
            real_email_id = str(user.emails[0].id)

        # Forge a token with token_v=2.0 (float) for real user
        token_float = cookie_accounts.service.token_signer.create_token(
            {
                "action": "verify_email",
                "token_v": 2.0,
                "sub": real_user_id,
                "email_id": real_email_id,
                "email": "real@example.com",
            }
        )
        resp2 = await client.post(
            "/api/v1/auth/verify-email", json={"token": token_float}
        )
        assert resp2.status_code == 400


# 5. Cookie max_age deprecation
def test_cookie_transport_max_age_deprecation():
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        _ = CookieTransport(max_age=3600)
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert "CookieTransport(max_age=...) is deprecated" in str(w[-1].message)

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        _ = CookieTransport()
        assert len(w) == 0


# 6. Read/commit failures and no SQL after commit
@pytest.mark.asyncio
async def test_verify_email_no_sql_after_commit(cookie_accounts: FastAPIAccounts):
    import sqlalchemy as sa

    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        _ = await client.post(
            "/api/v1/auth/register",
            json={"email": "nosql@example.com", "password": "SecurePassword123!"},
        )

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "nosql@example.com"
            )
            assert user is not None
            email_id = user.emails[0].id

        token = cookie_accounts.service.generate_email_verification_token(
            user.id, email_id, "nosql@example.com"
        )

        # We hook into before_cursor_execute to capture exactly when commit happens
        queries = []
        in_commit = False
        post_commit_queries = []

        def after_commit(session):
            nonlocal in_commit
            in_commit = True

        def before_execute(conn, cursor, statement, parameters, context, executemany):
            queries.append(statement)
            if in_commit:
                post_commit_queries.append(statement)

        from sqlalchemy.orm import Session

        sa.event.listen(Session, "after_commit", after_commit)

        engine = cookie_accounts.adapter.engine
        assert engine is not None
        sa.event.listen(engine.sync_engine, "before_cursor_execute", before_execute)

        try:
            resp = await client.post("/api/v1/auth/verify-email", json={"token": token})
            assert resp.status_code == 200
        finally:
            sa.event.remove(Session, "after_commit", after_commit)
            engine = cookie_accounts.adapter.engine
            assert engine is not None
            sa.event.remove(engine.sync_engine, "before_cursor_execute", before_execute)

        # Ensure there were NO queries executed after the COMMIT.
        assert len(post_commit_queries) == 0, (
            f"Queries executed after commit: {post_commit_queries}"
        )


@pytest.mark.asyncio
async def test_expire_on_commit_operations(async_engine):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from fastapi_accounts import CookieTransport, FastAPIAccounts
    from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter

    # Configure session maker with expire_on_commit=True
    session_maker = async_sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=True
    )
    adapter = SQLAlchemyAdapter(session_maker=session_maker, engine=async_engine)
    await adapter.create_all()

    accounts = FastAPIAccounts(
        adapter=adapter,
        secret_key="secret" * 8,
        transport=CookieTransport(cookie_secure=False, csrf_protect=False),
    )

    app = FastAPI()
    app.include_router(accounts.router, prefix="/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test Registration
        res = await client.post(
            "/auth/register",
            json={"email": "expire@example.com", "password": "SecurePassword123!"},
        )
        assert res.status_code == 201, res.text

        # Test Login
        res = await client.post(
            "/auth/login",
            json={"email": "expire@example.com", "password": "SecurePassword123!"},
        )
        assert res.status_code == 200, res.text


def test_csrf_non_ascii_handling():
    from fastapi_accounts.security.csrf import validate_csrf_token

    # Pass non-ASCII values; it should return False instead of raising an exception
    assert not validate_csrf_token("abc🚀", "abc🚀", None, b"secret" * 8)


def test_fastapi_accounts_transport_isolation():
    from fastapi_accounts import CookieTransport, FastAPIAccounts

    shared_transport = CookieTransport(max_age=10)

    from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter

    adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///:memory:")
    accounts_a = FastAPIAccounts(
        adapter=adapter,
        secret_key="secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret",
        allow_legacy_tokens=False,
        transport=shared_transport,
        session_max_age_seconds=61,
    )

    accounts_b = FastAPIAccounts(
        adapter=adapter,
        secret_key="secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret",
        allow_legacy_tokens=False,
        transport=shared_transport,
        session_max_age_seconds=999,
    )

    assert accounts_a.transport.max_age == 61
    assert accounts_b.transport.max_age == 999
    assert accounts_a.transport is not accounts_b.transport
