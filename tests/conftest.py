import os
import tempfile

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.models.default import Base
from fastapi_accounts.transports.bearer import BearerTransport
from fastapi_accounts.transports.cookie import CookieTransport


@pytest.fixture
async def async_engine():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{path}",
        connect_args={"timeout": 15.0},
        poolclass=NullPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()
    try:
        os.remove(path)
    except OSError:
        pass


@pytest.fixture
async def session_maker(async_engine):
    return async_sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False
    )


@pytest.fixture
async def adapter(session_maker, async_engine):
    return SQLAlchemyAdapter(session_maker=session_maker, engine=async_engine)


@pytest.fixture
def cookie_accounts(adapter):
    return FastAPIAccounts(
        adapter=adapter,
        secret_key="test-secret-key-at-least-32-characters-long-1234567890",
        transport=CookieTransport(cookie_secure=False, csrf_protect=False),
        allowed_origins=["http://testserver", "http://test", "http://localhost"],
        verify_email_required=False,
    )


@pytest.fixture
def bearer_accounts(adapter):
    return FastAPIAccounts(
        adapter=adapter,
        secret_key="test-secret-key-at-least-32-characters-long-1234567890",
        transport=BearerTransport(),
        allowed_origins=["http://testserver", "http://test", "http://localhost"],
        verify_email_required=False,
    )
