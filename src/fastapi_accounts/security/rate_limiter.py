from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time
from typing import Protocol

from fastapi import Request

logger = logging.getLogger("fastapi_accounts.rate_limiter")


class BaseRateLimiter(Protocol):
    """Protocol defining rate limiter implementations."""

    async def check_rate_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> tuple[bool, int]:
        """Check rate limit for a key. Returns (allowed, retry_after_seconds)."""
        ...


class InMemorySlidingWindowLimiter:
    """In-memory sliding-window rate limiter with bounded memory and LRU eviction.

    Suitable for single-process instances and test environments. Multi-worker deployments
    should configure a shared distributed limiter (e.g. Redis sliding window) or API Gateway.
    """

    def __init__(self, max_keys: int = 10000):
        self.max_keys = max_keys
        self._windows: dict[str, list[float]] = {}
        self._last_accessed: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def check_rate_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> tuple[bool, int]:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - window_seconds

            # Clean active key timestamps
            if key in self._windows:
                self._windows[key] = [t for t in self._windows[key] if t > cutoff]
                if not self._windows[key]:
                    del self._windows[key]
                    self._last_accessed.pop(key, None)

            # Eviction when size exceeds limit
            if len(self._windows) >= self.max_keys:
                # 1. Purge all expired entries across all keys
                expired_keys = [
                    k
                    for k, timestamps in self._windows.items()
                    if not [t for t in timestamps if t > cutoff]
                ]
                for exp_k in expired_keys:
                    self._windows.pop(exp_k, None)
                    self._last_accessed.pop(exp_k, None)

                # 2. If still full, evict oldest 10% keys by access time (LRU)
                if len(self._windows) >= self.max_keys:
                    logger.warning(
                        "InMemorySlidingWindowLimiter saturated (max_keys=%d). Performing LRU eviction.",
                        self.max_keys,
                    )
                    sorted_keys = sorted(
                        self._last_accessed.items(), key=lambda item: item[1]
                    )
                    evict_count = max(1, len(sorted_keys) // 10)
                    for evict_k, _ in sorted_keys[:evict_count]:
                        self._windows.pop(evict_k, None)
                        self._last_accessed.pop(evict_k, None)

            timestamps = self._windows.get(key, [])
            if len(timestamps) >= max_requests:
                earliest = timestamps[0]
                retry_after = max(1, int(earliest + window_seconds - now))
                return False, retry_after

            timestamps.append(now)
            self._windows[key] = timestamps
            self._last_accessed[key] = now
            return True, 0


def build_rate_limit_key(
    action: str,
    identity: str | None,
    client_ip: str | None,
    hmac_key: bytes,
) -> str:
    """Generate a PII-safe HMAC-SHA256 key without storing raw emails or IP addresses."""
    clean_id = (identity or "").strip().lower()
    clean_ip = (client_ip or "").strip()
    raw = f"{action}:{clean_id}:{clean_ip}".encode()
    digest = hmac.new(hmac_key, raw, hashlib.sha256).hexdigest()[:32]
    return f"ratelimit:{action}:{digest}"


def resolve_client_ip(
    request: Request, trusted_proxies: list[str] | None = None
) -> str:
    """Extract client IP address, honoring X-Forwarded-For only from trusted proxies."""
    direct_ip = request.client.host if request.client else "unknown"
    if trusted_proxies and direct_ip in trusted_proxies:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[-1]
    return direct_ip
