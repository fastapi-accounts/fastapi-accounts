from typing import Literal

from fastapi import Request, Response

from fastapi_accounts.transports.base import BaseTransport


class CookieTransport(BaseTransport):
    """Transport that stores session tokens in secure HttpOnly browser cookies."""

    def __init__(
        self,
        cookie_name: str = "fastapi_accounts_session",
        csrf_cookie_name: str = "fastapi_accounts_csrf",
        max_age: int = 86400 * 14,  # 14 days
        path: str = "/",
        domain: str | None = None,
        cookie_secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
        csrf_protect: bool = True,
    ):
        self.cookie_name = cookie_name
        self.csrf_cookie_name = csrf_cookie_name
        self.max_age = max_age
        self.path = path
        self.domain = domain
        self.cookie_secure = cookie_secure
        self.httponly = httponly
        self.samesite = samesite
        self.csrf_protect = csrf_protect

    def extract_token(self, request: Request) -> str | None:
        return request.cookies.get(self.cookie_name)

    def set_login_response(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            max_age=self.max_age,
            path=self.path,
            domain=self.domain,
            secure=self.cookie_secure,
            httponly=self.httponly,
            samesite=self.samesite,
        )

    def set_csrf_cookie(
        self, response: Response, csrf_token: str, max_age: int = 86400 * 14
    ) -> None:
        """Set double-submit CSRF cookie accessible by browser scripts."""
        response.set_cookie(
            key=self.csrf_cookie_name,
            value=csrf_token,
            max_age=max_age,
            path=self.path,
            domain=self.domain,
            secure=self.cookie_secure,
            httponly=False,
            samesite=self.samesite,
        )

    def clear_csrf_cookie(self, response: Response) -> None:
        """Clear CSRF cookie upon logout."""
        response.delete_cookie(
            key=self.csrf_cookie_name,
            path=self.path,
            domain=self.domain,
        )

    def set_logout_response(self, response: Response) -> None:
        response.delete_cookie(
            key=self.cookie_name,
            path=self.path,
            domain=self.domain,
        )
        self.clear_csrf_cookie(response)
