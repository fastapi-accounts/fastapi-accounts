from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.schemas.principal import UserPrincipal
from fastapi_accounts.transports.base import BaseTransport
from fastapi_accounts.transports.bearer import BearerTransport

if TYPE_CHECKING:
    from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
    from fastapi_accounts.services.account import AccountService


def create_current_user_dependency(
    adapter: SQLAlchemyAdapter,
    service: AccountService,
    transport: BaseTransport,
    optional: bool = False,
    superuser_required: bool = False,
) -> Callable[..., Coroutine[Any, Any, UserPrincipal | None]]:
    """Build a closure-based dependency capturing adapter.get_db in parameter default."""

    async def current_user_dependency(
        request: Request,
        db: AsyncSession = Depends(adapter.get_db),
    ) -> UserPrincipal | None:
        raw_token = transport.extract_token(request)
        if not raw_token:
            if optional:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials are required.",
                headers={"WWW-Authenticate": "Bearer"}
                if isinstance(transport, BearerTransport)
                else None,
            )

        res = await service.get_principal_by_token(db, raw_token)
        if not res:
            if optional:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials are invalid or expired.",
                headers={"WWW-Authenticate": "Bearer"}
                if isinstance(transport, BearerTransport)
                else None,
            )

        principal, _ = res
        if not principal.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive.",
            )

        if superuser_required and not principal.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser privileges are required.",
            )

        return principal

    return current_user_dependency
