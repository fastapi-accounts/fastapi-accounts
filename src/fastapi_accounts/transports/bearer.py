from typing import Optional

from fastapi import Request, Response

from fastapi_accounts.transports.base import BaseTransport


class BearerTransport(BaseTransport):
    """Transport that extracts tokens from Authorization: Bearer <token> headers."""

    def __init__(self, header_name: str = "Authorization"):
        self.header_name = header_name

    def extract_token(self, request: Request) -> Optional[str]:
        auth_header = request.headers.get(self.header_name)
        if not auth_header:
            return None
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return None

    def set_login_response(self, response: Response, token: str) -> None:
        # Bearer tokens are returned in the response body rather than response headers
        pass

    def set_logout_response(self, response: Response) -> None:
        # Bearer tokens are stateless on client header side; session is revoked in database
        pass
