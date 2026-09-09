from abc import ABC, abstractmethod

from fastapi import Request, Response


class BaseTransport(ABC):
    """Abstract base class for extracting and setting authentication tokens."""

    @abstractmethod
    def extract_token(self, request: Request) -> str | None:
        """Extract the raw session token from the incoming HTTP request."""

    @abstractmethod
    def set_login_response(self, response: Response, token: str) -> None:
        """Modify the outgoing HTTP response upon successful login (e.g. set cookies)."""

    @abstractmethod
    def set_logout_response(self, response: Response) -> None:
        """Modify the outgoing HTTP response upon logout (e.g. clear cookies)."""
