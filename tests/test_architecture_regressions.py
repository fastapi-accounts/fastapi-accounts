import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.core import FastAPIAccounts, _get_pwd_state_ts
from fastapi_accounts.models.default import EmailAddress, Session, User


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
    """A01: Injected commit failure must abort registration, return 500, and suppress side-effects."""
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
async def test_a01_injected_commit_failure_verify_email(
    cookie_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected commit failure during email verification must return 500 and leave email unverified."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create unverified user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "unverified@example.com", "password": "SecurePassword123!"},
        )
        assert reg_resp.status_code == 201

        token = cookie_accounts.generate_email_verification_token(
            "unverified@example.com"
        )

        # Inject commit failure
        original_commit = AsyncSession.commit

        async def failing_commit(self):
            raise SQLAlchemyError("Simulated database failure during verify commit")

        monkeypatch.setattr(AsyncSession, "commit", failing_commit)

        verify_resp = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": token},
        )
        assert verify_resp.status_code == 500

        # Restore commit and verify email is still unverified in DB
        monkeypatch.setattr(AsyncSession, "commit", original_commit)

        async with cookie_accounts.adapter.session_maker() as session:
            stmt = select(EmailAddress).where(
                EmailAddress.email == "unverified@example.com"
            )
            result = await session.execute(stmt)
            email_rec = result.scalar_one_or_none()
            assert email_rec is not None
            assert email_rec.is_verified is False


@pytest.mark.asyncio
async def test_a01_injected_commit_failure_reset_password(
    cookie_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected commit failure during password reset must return 500 and preserve existing credentials and sessions."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "reset_fail@example.com", "password": "OldPassword123!"},
        )
        assert reg_resp.status_code == 201

        # Login to get active session
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "reset_fail@example.com", "password": "OldPassword123!"},
        )
        assert login_resp.status_code == 200

        # Verify initial session works for /me
        me_pre = await client.get("/api/v1/auth/me")
        assert me_pre.status_code == 200

        # Generate reset token with valid timestamp
        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "reset_fail@example.com"
            )
            assert user is not None
            cred = await cookie_accounts.adapter.get_password_credential(
                session, user.id
            )
            assert cred is not None
            pwd_ts = _get_pwd_state_ts(cred.password_updated_at)
            token = cookie_accounts.generate_password_reset_token(
                user.id, "reset_fail@example.com", pwd_ts=pwd_ts
            )

        # Inject commit failure
        original_commit = AsyncSession.commit

        async def failing_commit(self):
            raise SQLAlchemyError("Simulated database failure during reset commit")

        monkeypatch.setattr(AsyncSession, "commit", failing_commit)

        reset_resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": token, "new_password": "NewPassword123!"},
        )
        assert reset_resp.status_code == 500

        # Restore commit
        monkeypatch.setattr(AsyncSession, "commit", original_commit)

        # Invariant 1: Existing session retained by client remains active and valid
        me_post = await client.get("/api/v1/auth/me")
        assert me_post.status_code == 200
        assert me_post.json()["primary_email"] == "reset_fail@example.com"

        # Invariant 2: Old password still works
        old_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "reset_fail@example.com", "password": "OldPassword123!"},
        )
        assert old_login.status_code == 200

        # Invariant 3: New password does NOT work
        new_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "reset_fail@example.com", "password": "NewPassword123!"},
        )
        assert new_login.status_code == 401


@pytest.mark.asyncio
async def test_a01_injected_commit_failure_login(
    cookie_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected commit failure during login must return 500 and persist zero sessions."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "login_fail@example.com", "password": "SecurePassword123!"},
        )
        assert reg_resp.status_code == 201

        # Inject commit failure
        original_commit = AsyncSession.commit

        async def failing_commit(self):
            raise SQLAlchemyError("Simulated database failure during login commit")

        monkeypatch.setattr(AsyncSession, "commit", failing_commit)

        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "login_fail@example.com", "password": "SecurePassword123!"},
        )
        assert login_resp.status_code == 500
        # Ensure no cookie header was set
        assert "set-cookie" not in login_resp.headers

        # Restore commit and check database
        monkeypatch.setattr(AsyncSession, "commit", original_commit)

        async with cookie_accounts.adapter.session_maker() as session:
            stmt = select(Session)
            result = await session.execute(stmt)
            sessions = result.scalars().all()
            assert len(sessions) == 0


@pytest.mark.asyncio
async def test_a01_injected_commit_failure_change_password(
    cookie_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected commit failure during change_password must return 500 and keep old password and other sessions active."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client1:
        # Register user
        await client1.post(
            "/api/v1/auth/register",
            json={"email": "change_fail@example.com", "password": "OldPassword123!"},
        )
        # Session 1 login
        login1 = await client1.post(
            "/api/v1/auth/login",
            json={"email": "change_fail@example.com", "password": "OldPassword123!"},
        )
        assert login1.status_code == 200

        # Session 2 login from a separate client
        async with AsyncClient(transport=transport, base_url="http://test") as client2:
            login2 = await client2.post(
                "/api/v1/auth/login",
                json={
                    "email": "change_fail@example.com",
                    "password": "OldPassword123!",
                },
            )
            assert login2.status_code == 200

            # Both sessions valid before change
            assert (await client1.get("/api/v1/auth/me")).status_code == 200
            assert (await client2.get("/api/v1/auth/me")).status_code == 200

            # Inject commit failure during change_password with revoke_other_sessions=True
            original_commit = AsyncSession.commit

            async def failing_commit(self):
                raise SQLAlchemyError(
                    "Simulated database failure during change_password commit"
                )

            monkeypatch.setattr(AsyncSession, "commit", failing_commit)

            ch_resp = await client1.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "OldPassword123!",
                    "new_password": "NewPassword123!",
                    "revoke_other_sessions": True,
                },
            )
            assert ch_resp.status_code == 500

            # Restore commit
            monkeypatch.setattr(AsyncSession, "commit", original_commit)

            # Invariant 1: Session 1 remains active
            assert (await client1.get("/api/v1/auth/me")).status_code == 200

            # Invariant 2: Session 2 remains active (other sessions were NOT revoked)
            assert (await client2.get("/api/v1/auth/me")).status_code == 200

            # Invariant 3: Old password still authenticates
            old_login = await client1.post(
                "/api/v1/auth/login",
                json={
                    "email": "change_fail@example.com",
                    "password": "OldPassword123!",
                },
            )
            assert old_login.status_code == 200

            # Invariant 4: New password fails
            new_login = await client1.post(
                "/api/v1/auth/login",
                json={
                    "email": "change_fail@example.com",
                    "password": "NewPassword123!",
                },
            )
            assert new_login.status_code == 401


@pytest.mark.asyncio
async def test_a01_injected_logout_commit_failure_cookie_transport(
    cookie_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected commit failure during logout must return 500, not clear cookie, and preserve active session."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register and login
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "logout_cookie@example.com",
                "password": "SecurePassword123!",
            },
        )
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "logout_cookie@example.com",
                "password": "SecurePassword123!",
            },
        )
        assert login_resp.status_code == 200

        # Check me works
        me_before = await client.get("/api/v1/auth/me")
        assert me_before.status_code == 200

        # Inject commit failure during logout
        original_commit = AsyncSession.commit

        async def failing_commit(self):
            raise SQLAlchemyError("Simulated database failure during logout commit")

        monkeypatch.setattr(AsyncSession, "commit", failing_commit)

        logout_resp = await client.post("/api/v1/auth/logout")
        # Must return 500, never 200
        assert logout_resp.status_code == 500
        # Assert Set-Cookie deletion is NOT returned in the 500 response
        set_cookie = logout_resp.headers.get("set-cookie", "")
        assert (
            "max-age=0" not in set_cookie.lower()
            and "expires=thu, 01 jan 1970" not in set_cookie.lower()
        )

        # Restore commit
        monkeypatch.setattr(AsyncSession, "commit", original_commit)

        # Assert original session remains active and valid
        me_after = await client.get("/api/v1/auth/me")
        assert me_after.status_code == 200
        assert me_after.json()["primary_email"] == "logout_cookie@example.com"


@pytest.mark.asyncio
async def test_a01_injected_logout_adapter_failure_bearer_transport(
    bearer_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected adapter failure during bearer logout must return 500 and preserve active bearer token."""
    app = FastAPI()
    app.include_router(bearer_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register and login
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "logout_bearer@example.com",
                "password": "SecurePassword123!",
            },
        )
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "logout_bearer@example.com",
                "password": "SecurePassword123!",
            },
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        auth_headers = {"Authorization": f"Bearer {token}"}

        # Check me works
        me_before = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert me_before.status_code == 200

        # Inject adapter failure (SQLAlchemyError)
        async def failing_revoke(session, raw_token):
            raise SQLAlchemyError("Simulated database failure during revoke_session")

        monkeypatch.setattr(bearer_accounts.adapter, "revoke_session", failing_revoke)

        logout_resp = await client.post("/api/v1/auth/logout", headers=auth_headers)
        assert logout_resp.status_code == 500

        # Unpatch
        monkeypatch.undo()

        # Assert original bearer token remains valid and session still active
        me_after = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert me_after.status_code == 200
        assert me_after.json()["primary_email"] == "logout_bearer@example.com"


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
