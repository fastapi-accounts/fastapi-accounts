from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import time
from collections.abc import Sequence
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
    or environments with high adversarial key churn should configure a shared distributed limiter
    (e.g. Redis sliding window) or upstream API Gateway.
    """

    def __init__(self, max_keys: int = 10000):
        self.max_keys = max_keys
        self._windows: dict[str, list[float]] = {}
        self._window_durations: dict[str, int] = {}
        self._last_accessed: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def check_rate_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> tuple[bool, int]:
        async with self._lock:
            now = time.monotonic()
            self._window_durations[key] = window_seconds
            self._last_accessed[key] = now
            cutoff = now - window_seconds

            # Clean active key timestamps
            if key in self._windows:
                self._windows[key] = [t for t in self._windows[key] if t > cutoff]
                if not self._windows[key]:
                    self._windows.pop(key, None)
                    self._window_durations.pop(key, None)
                    self._last_accessed.pop(key, None)

            # Capacity check for admission of a NEW key
            if key not in self._windows and len(self._windows) >= self.max_keys:
                # 1. Purge genuinely expired entries across all keys using their respective window durations
                expired_keys = [
                    k
                    for k, timestamps in self._windows.items()
                    if not [
                        t
                        for t in timestamps
                        if t > (now - self._window_durations.get(k, window_seconds))
                    ]
                ]
                for exp_k in expired_keys:
                    self._windows.pop(exp_k, None)
                    self._window_durations.pop(exp_k, None)
                    self._last_accessed.pop(exp_k, None)

                # 2. If still full, evict the least-recently-accessed (LRU) key from all structures
                if len(self._windows) >= self.max_keys:
                    logger.warning(
                        "InMemorySlidingWindowLimiter saturated (max_keys=%d). Evicting least-recently-used key.",
                        self.max_keys,
                    )
                    sorted_keys = sorted(
                        self._last_accessed.items(), key=lambda item: item[1]
                    )
                    if sorted_keys:
                        lru_key = sorted_keys[0][0]
                        self._windows.pop(lru_key, None)
                        self._window_durations.pop(lru_key, None)
                        self._last_accessed.pop(lru_key, None)

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
    request: Request,
    trusted_proxies: Sequence[str] | None = None,
    trusted_proxy_count: int = 0,
) -> str:
    """Extract client IP address, honoring X-Forwarded-For right-to-left only from trusted proxies."""
    peer_ip = request.client.host if request.client else "127.0.0.1"

    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer_ip

    hops = [h.strip() for h in xff.split(",") if h.strip()]
    if not hops:
        return peer_ip

    if trusted_proxy_count > 0:
        if len(hops) >= trusted_proxy_count:
            return hops[-trusted_proxy_count]
        return hops[0]

    if not trusted_proxies or peer_ip not in trusted_proxies:
        return peer_ip

    # Right-to-left traversal: most recent hop to earliest hop
    for hop in reversed(hops):
        try:
            # Validate IP address syntax
            ipaddress.ip_address(hop)
        except ValueError:
            return peer_ip

        if hop not in trusted_proxies:
            return hop

    # If all hops in chain are in trusted_proxies, return leftmost valid IP
    return hops[0]
