import anyio
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

# Initialize with modern Argon2id hasher
password_hasher = PasswordHash((Argon2Hasher(),))

# Precomputed static valid Argon2id hash constant for timing oracle equalization (zero import crypto)
_STATIC_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$anJ2eGZvdWZ5Z3NkYWFhYQ$Q3n6zXh9n3PqK9bO5g1t7Y/6t7bQ5y0kL8x4s1w9a2A"


def hash_password(password: str) -> str:
    """Hash a plaintext password synchronously using Argon2id."""
    return password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password synchronously against an Argon2id hash."""
    return password_hasher.verify(plain_password, hashed_password)


class PasswordService:
    """Async offloaded password hashing service with bounded concurrency limiter."""

    def __init__(self, argon2_concurrency: int = 4):
        self.argon2_concurrency = argon2_concurrency
        self._limiter = anyio.CapacityLimiter(argon2_concurrency)

    async def async_hash_password(self, password: str) -> str:
        """Hash a plaintext password off-event-loop using worker threads."""
        return await anyio.to_thread.run_sync(
            hash_password, password, limiter=self._limiter
        )

    async def async_verify_password(
        self, plain_password: str, hashed_password: str
    ) -> bool:
        """Verify a password off-event-loop using worker threads."""
        return await anyio.to_thread.run_sync(
            verify_password, plain_password, hashed_password, limiter=self._limiter
        )

    async def async_verify_dummy_password(self, plain_password: str) -> bool:
        """Verify a dummy password off-event-loop to equalize response timing for missing users."""
        await anyio.to_thread.run_sync(
            verify_password, plain_password, _STATIC_DUMMY_HASH, limiter=self._limiter
        )
        return False


# Global default service instance
_default_password_service = PasswordService(argon2_concurrency=4)


async def async_hash_password(password: str) -> str:
    return await _default_password_service.async_hash_password(password)


async def async_verify_password(plain_password: str, hashed_password: str) -> bool:
    return await _default_password_service.async_verify_password(
        plain_password, hashed_password
    )


async def async_verify_dummy_password(plain_password: str) -> bool:
    return await _default_password_service.async_verify_dummy_password(plain_password)
