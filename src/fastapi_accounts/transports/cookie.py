from typing import Literal, Optional

from fastapi import Request, Response

from fastapi_accounts.transports.base import BaseTransport


class CookieTransport(BaseTransport):
    """Transport that stores session tokens in secure HttpOnly browser cookies."""

    def __init__(
        self,
        cookie_name: str = "fastapi_accounts_session",
        max_age: int = 86400 * 14,  # 14 days
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ):
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.path = path
        self.domain = domain
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite

    def extract_token(self, request: Request) -> Optional[str]:
        return request.cookies.get(self.cookie_name)

    def set_login_response(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            max_age=self.max_age,
            path=self.path,
            domain=self.domain,
            secure=self.secure,
            httponly=self.httponly,
            samesite=self.samesite,
        )

    def set_logout_response(self, response: Response) -> None:
        response.delete_cookie(
            key=self.cookie_name,
            path=self.path,
            domain=self.domain,
        )
