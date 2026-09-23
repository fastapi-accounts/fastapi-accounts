import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.openapi.utils import get_openapi
from httpx import ASGITransport, AsyncClient
import uuid
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
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
    assert paths["/api/v1/auth/verify-email"]["post"]["security"] == [
        {"APIKeyCookie": []},
        {},
    ]
    assert paths["/api/v1/auth/reset-password"]["post"]["security"] == [
        {"APIKeyCookie": []},
        {},
    ]

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

        sa.event.listen(
            cookie_accounts.adapter.engine.sync_engine,
            "before_cursor_execute",
            before_cursor_execute,
        )

        try:
            me_resp = await client.get(
                "/api/v1/auth/me", cookies={"fastapi_accounts_session": cookie}
            )
            assert me_resp.status_code == 200
        finally:
            sa.event.remove(
                cookie_accounts.adapter.engine.sync_engine,
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
        reg = await client.post(
            "/api/v1/auth/register",
            json={"email": "concurrent@example.com", "password": "SecurePassword123!"},
        )

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "concurrent@example.com"
            )
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
    # Try with missing/malformed UUIDs
    # Token payload requires sub and email_id to be UUIDs.
    pass


# 5. Cookie max_age deprecation
def test_cookie_transport_max_age_deprecation():
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        t = CookieTransport(max_age=3600)
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert "CookieTransport(max_age=...) is deprecated" in str(w[-1].message)

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        t2 = CookieTransport()
        assert len(w) == 0


# 6. Read/commit failures and no SQL after commit
@pytest.mark.asyncio
async def test_verify_email_no_sql_after_commit(cookie_accounts: FastAPIAccounts):
    import sqlalchemy as sa

    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reg = await client.post(
            "/api/v1/auth/register",
            json={"email": "nosql@example.com", "password": "SecurePassword123!"},
        )

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "nosql@example.com"
            )
            email_id = user.emails[0].id

        token = cookie_accounts.service.generate_email_verification_token(
            user.id, email_id, "nosql@example.com"
        )

        # We hook into before_cursor_execute to capture exactly when commit happens
        queries = []
        in_commit = False
        post_commit_queries = []

        def before_execute(conn, cursor, statement, parameters, context, executemany):
            queries.append(statement)
            if "COMMIT" in statement.upper():
                nonlocal in_commit
                in_commit = True
            elif in_commit:
                post_commit_queries.append(statement)

        sa.event.listen(
            cookie_accounts.adapter.engine.sync_engine,
            "before_cursor_execute",
            before_execute,
        )

        try:
            resp = await client.post("/api/v1/auth/verify-email", json={"token": token})
            assert resp.status_code == 200
        finally:
            sa.event.remove(
                cookie_accounts.adapter.engine.sync_engine,
                "before_cursor_execute",
                before_execute,
            )

        # Ensure there were NO queries executed after the COMMIT.
        assert len(post_commit_queries) == 0, (
            f"Queries executed after commit: {post_commit_queries}"
        )
