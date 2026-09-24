import uuid
from collections.abc import AsyncGenerator

import pytest
import sqlalchemy as sa
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.models.default import EmailAddress, Session
from fastapi_accounts.schemas.principal import UserPrincipal


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
            cred = await cookie_accounts.adapter.get_password_credential(
                session, user.id
            )
            assert cred is not None


@pytest.mark.asyncio
async def test_a01_injected_commit_failure_prevents_201_response(
    cookie_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected commit failure must abort registration, return 500, and suppress side-effects."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    dispatched: list[str] = []

    async def mock_callback(user, token):
        dispatched.append(user.email)

    cookie_accounts.service.on_after_register = mock_callback

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
        assert resp.status_code == 500

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

        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "unverified@example.com"
            )
            assert user is not None
            email_id = user.emails[0].id

        token = cookie_accounts.service.generate_email_verification_token(
            user.id, email_id, "unverified@example.com"
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

        # Generate reset token with valid credential_version
        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "reset_fail@example.com"
            )
            assert user is not None
            cred = await cookie_accounts.adapter.get_password_credential(
                session, user.id
            )
            assert cred is not None
            token = cookie_accounts.service.generate_password_reset_token(
                user.id, "reset_fail@example.com", cred.credential_version
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

        monkeypatch.setattr(AsyncSession, "commit", original_commit)

        # Invariant 1: Existing session retained by client remains active and valid
        me_post = await client.get("/api/v1/auth/me")
        assert me_post.status_code == 200
        assert me_post.json()["emails"][0]["email"] == "reset_fail@example.com"

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
        assert "set-cookie" not in login_resp.headers

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

            assert (await client1.get("/api/v1/auth/me")).status_code == 200
            assert (await client2.get("/api/v1/auth/me")).status_code == 200

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

            monkeypatch.setattr(AsyncSession, "commit", original_commit)

            assert (await client1.get("/api/v1/auth/me")).status_code == 200
            assert (await client2.get("/api/v1/auth/me")).status_code == 200

            old_login = await client1.post(
                "/api/v1/auth/login",
                json={
                    "email": "change_fail@example.com",
                    "password": "OldPassword123!",
                },
            )
            assert old_login.status_code == 200

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

        me_before = await client.get("/api/v1/auth/me")
        assert me_before.status_code == 200

        original_commit = AsyncSession.commit

        async def failing_commit(self):
            raise SQLAlchemyError("Simulated database failure during logout commit")

        monkeypatch.setattr(AsyncSession, "commit", failing_commit)

        logout_resp = await client.post("/api/v1/auth/logout")
        assert logout_resp.status_code == 500
        set_cookie = logout_resp.headers.get("set-cookie", "")
        assert (
            "max-age=0" not in set_cookie.lower()
            and "expires=thu, 01 jan 1970" not in set_cookie.lower()
        )

        monkeypatch.setattr(AsyncSession, "commit", original_commit)

        me_after = await client.get("/api/v1/auth/me")
        assert me_after.status_code == 200
        assert me_after.json()["emails"][0]["email"] == "logout_cookie@example.com"


@pytest.mark.asyncio
async def test_a01_injected_logout_adapter_failure_bearer_transport(
    bearer_accounts: FastAPIAccounts, monkeypatch: pytest.MonkeyPatch
):
    """A01: Injected adapter failure during bearer logout must return 500 and preserve active bearer token."""
    app = FastAPI()
    app.include_router(bearer_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
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

        me_before = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert me_before.status_code == 200

        async def failing_revoke(session, raw_token):
            raise SQLAlchemyError("Simulated database failure during revoke_session")

        monkeypatch.setattr(bearer_accounts.adapter, "revoke_session", failing_revoke)

        logout_resp = await client.post("/api/v1/auth/logout", headers=auth_headers)
        assert logout_resp.status_code == 500

        monkeypatch.undo()

        me_after = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert me_after.status_code == 200
        assert me_after.json()["emails"][0]["email"] == "logout_bearer@example.com"


@pytest.mark.asyncio
async def test_a03_current_superuser_dependency(cookie_accounts: FastAPIAccounts):
    """A03: current_superuser must grant access to superusers, return 403 for non-superusers, and 401 for unauthenticated."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    @app.get("/admin/dashboard")
    async def admin_dashboard(
        user: UserPrincipal = Depends(cookie_accounts.current_superuser),
    ):
        return {"message": "Welcome Admin", "email": user.email}

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
        reg_resp = await client_regular.post(
            "/api/v1/auth/register",
            json={"email": "regular@example.com", "password": "RegularPassword123!"},
        )
        assert reg_resp.status_code == 201

        login_resp = await client_regular.post(
            "/api/v1/auth/login",
            json={"email": "regular@example.com", "password": "RegularPassword123!"},
        )
        assert login_resp.status_code == 200

        forbidden_resp = await client_regular.get("/admin/dashboard")
        assert forbidden_resp.status_code == 403
        assert "Superuser privileges are required" in forbidden_resp.json()["detail"]

    # 3. Superuser (is_superuser=True) -> 200 OK
    async with AsyncClient(transport=transport, base_url="http://test") as client_admin:
        async with cookie_accounts.adapter.session_maker() as session:
            await cookie_accounts.service.register_user(
                session=session,
                email="admin@example.com",
                password="AdminPassword123!",
                is_superuser=True,
            )

        login_admin = await client_admin.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "AdminPassword123!"},
        )
        assert login_admin.status_code == 200

        admin_resp = await client_admin.get("/admin/dashboard")
        assert admin_resp.status_code == 200
        assert admin_resp.json()["message"] == "Welcome Admin"
        assert admin_resp.json()["email"] == "admin@example.com"


@pytest.mark.asyncio
async def test_request_scoped_db_dependency_override(cookie_accounts: FastAPIAccounts):
    """P0 #11: Request-scoped DB dependency injection honors app.dependency_overrides."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    override_calls = 0

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        nonlocal override_calls
        override_calls += 1
        async with cookie_accounts.adapter.session_maker() as session:
            yield session

    app.dependency_overrides[cookie_accounts.adapter.get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "override_user@example.com", "password": "Password123!"},
        )
        assert reg_resp.status_code == 201
        assert override_calls >= 1

        prev_calls = override_calls
        # 2. Login
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "override_user@example.com", "password": "Password123!"},
        )
        assert login_resp.status_code == 200
        assert override_calls > prev_calls

        prev_calls = override_calls
        # 3. Current user /me
        me_resp = await client.get("/api/v1/auth/me")
        assert me_resp.status_code == 200
        assert me_resp.json()["id"] is not None
        # Strict invariant: override_get_db was invoked during /me
        assert override_calls > prev_calls


@pytest.mark.asyncio
async def test_post_commit_callback_failure_and_delivery_hook(
    cookie_accounts: FastAPIAccounts,
):
    """P0 #3: Callback exceptions are contained; user remains committed and delivery hook called."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    delivery_hook_calls: list[str] = []

    def sync_failing_callback(user, token):
        raise RuntimeError("External email provider connection timeout")

    async def async_delivery_hook(action, user, error):
        delivery_hook_calls.append(f"{action}:{user.email}:{type(error).__name__}")

    cookie_accounts.service.on_after_register = sync_failing_callback
    cookie_accounts.service.on_delivery_failure = async_delivery_hook

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "callback_test@example.com",
                "password": "SecurePassword123!",
            },
        )
        # Invariant: Must return 201 Created even if external notification fails
        assert resp.status_code == 201

    # Invariant: User is safely committed in the database
    async with cookie_accounts.adapter.session_maker() as session:
        user = await cookie_accounts.adapter.get_user_by_email(
            session, "callback_test@example.com"
        )
        assert user is not None

    # Invariant: on_delivery_failure hook was executed
    assert len(delivery_hook_calls) == 1
    assert "register:callback_test@example.com:RuntimeError" in delivery_hook_calls[0]


@pytest.mark.asyncio
async def test_email_id_stability_across_multiple_me_calls(
    cookie_accounts: FastAPIAccounts,
):
    """Verify that email.id in UserRead DTO reflects the true persisted DB id and is stable across multiple /me calls."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register and Login
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "stable_id@example.com", "password": "Password123!"},
        )
        assert reg_resp.status_code == 201
        reg_data = reg_resp.json()
        assert len(reg_data["emails"]) == 1
        reg_email_id = reg_data["emails"][0]["id"]

        await client.post(
            "/api/v1/auth/login",
            json={"email": "stable_id@example.com", "password": "Password123!"},
        )

        me1 = await client.get("/api/v1/auth/me")
        assert me1.status_code == 200
        me1_data = me1.json()
        email_id_1 = me1_data["emails"][0]["id"]

        me2 = await client.get("/api/v1/auth/me")
        assert me2.status_code == 200
        me2_data = me2.json()
        email_id_2 = me2_data["emails"][0]["id"]

        # Invariant: Email ID must match database record and must not be a volatile uuid4()
        assert reg_email_id == email_id_1 == email_id_2

        # Verify against database record
        async with cookie_accounts.adapter.session_maker() as session:
            user = await cookie_accounts.adapter.get_user_by_email(
                session, "stable_id@example.com"
            )
            assert user is not None
            assert str(user.emails[0].id) == email_id_1


@pytest.mark.asyncio
async def test_callable_object_callbacks_and_hook_error_containment(
    cookie_accounts: FastAPIAccounts,
):
    """Verify callable object instances work as callbacks and delivery hook errors are safely contained."""
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/api/v1/auth")

    class CallableNotifier:
        def __init__(self):
            self.invocations: list[str] = []

        async def __call__(self, user, token):
            self.invocations.append(user.email)
            raise RuntimeError("Notifier intentional failure")

    class FailingHook:
        def __init__(self):
            self.invocations: list[str] = []

        def __call__(self, action, user, error):
            self.invocations.append(f"{action}:{user.email}")
            raise RuntimeError("Hook itself failed")

    notifier = CallableNotifier()
    hook = FailingHook()

    cookie_accounts.service.on_after_register = notifier
    cookie_accounts.service.on_delivery_failure = hook

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "callable_hook@example.com",
                "password": "Password123!",
            },
        )
        # Even with notifier failure AND hook failure, registration must succeed with 201
        assert resp.status_code == 201

    assert len(notifier.invocations) == 1
    assert len(hook.invocations) == 1
    assert hook.invocations[0] == "register:callable_hook@example.com"


@pytest.mark.asyncio
async def test_create_session_returns_persistent_orm_instance(
    cookie_accounts: FastAPIAccounts,
):
    """F4 / Architecture: Verify create_session returns persistent ORM instances in identity map across both branches."""
    async with cookie_accounts.adapter.session_maker() as session:
        user, _ = await cookie_accounts.adapter.create_user_with_password(
            session=session,
            email="orm_persist@example.com",
            hashed_password="$argon2id$mockhash",
            is_verified=True,
        )
        await session.commit()
        user_id = user.id

    # 1. Expected credential version branch (explicit generation)
    async with cookie_accounts.adapter.session_maker() as session:
        sess_rec1 = await cookie_accounts.adapter.create_session(
            session=session,
            user_id=user_id,
            raw_token="raw_tok_test_versioned_123",
            expected_credential_version=1,
        )
        insp1 = sa.inspect(sess_rec1)
        assert insp1.persistent is True
        assert insp1.transient is False

        # Verify identity map returns identical object instance
        queried1 = (
            (await session.execute(select(Session).where(Session.id == sess_rec1.id)))
            .scalars()
            .first()
        )
        assert queried1 is sess_rec1

        # Assert version mismatch raises ValueError cleanly
        with pytest.raises(
            ValueError, match="Credential version mismatch during session creation"
        ):
            await cookie_accounts.adapter.create_session(
                session=session,
                user_id=user_id,
                raw_token="raw_tok_test_mismatch_123",
                expected_credential_version=99,
            )

    # 2. Omitted credential version branch (unversioned fallback)
    async with cookie_accounts.adapter.session_maker() as session:
        sess_rec2 = await cookie_accounts.adapter.create_session(
            session=session,
            user_id=user_id,
            raw_token="raw_tok_test_unversioned_456",
            expected_credential_version=None,
        )
        insp2 = sa.inspect(sess_rec2)
        assert insp2.persistent is True
        assert insp2.transient is False

        # Verify identity map returns identical object instance
        queried2 = (
            (await session.execute(select(Session).where(Session.id == sess_rec2.id)))
            .scalars()
            .first()
        )
        assert queried2 is sess_rec2

        # Assert missing user raises ValueError cleanly
        with pytest.raises(ValueError, match="Failed creating session for user"):
            await cookie_accounts.adapter.create_session(
                session=session,
                user_id=uuid.uuid4(),
                raw_token="raw_tok_test_missing_user_789",
                expected_credential_version=None,
            )
