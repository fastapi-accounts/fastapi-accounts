# Security Policy

## Supported Versions

| Version | Supported          | Security Status                                      |
| :------ | :----------------- | :--------------------------------------------------- |
| 0.1.0a5 | :white_check_mark: | Active pre-release with Phase 1 security hardening   |
| < 0.1.0a5 | :x:              | Deprecated pre-alpha releases with known limitations |

## Reporting a Vulnerability

We take the security of `fastapi-accounts` seriously. If you discover a vulnerability or security defect, please report it responsibly through private channels.

### Coordinated Disclosure Channels:
1. **Security Email Channel (Primary):**  
   Email `security@fastapi-accounts.org` with vulnerability details and reproduction steps.
2. **GitHub Private Vulnerability Reporting:**  
   GitHub Private Vulnerability Reporting will be enabled under the repository "Security" tab upon public repository provisioning.

Please do not open public GitHub issues or discussions for undisclosed vulnerabilities. You will receive an initial response within 48 hours.

---

## Threat Model & Invariant Guarantees

`fastapi-accounts` is engineered around strict security invariants:

1. **Replay-Immune Monotonic Credential Versioning (P0 #2):**
   - Password state is tracked via a monotonically increasing `credential_version: int` column in the database with a database check constraint (`credential_version >= 1`).
   - Reset tokens embed `token_v: 2` and `cred_v: int`.
   - All password mutations execute an atomic SQL Compare-And-Swap (CAS) `WHERE credential_version = expected_cred_v` setting `credential_version = credential_version + 1`.
   - Replay is impossible even under frozen, backwards, or skewed system clocks.

2. **Off-Loop Bounded Password Hashing & Timing Oracle Equalization (P0 #9):**
   - Password hashing and verification are offloaded from the asyncio event loop to worker threads via `anyio.to_thread.run_sync`.
   - Concurrency is bounded by `anyio.CapacityLimiter` to prevent thread-pool starvation and CPU-exhaustion DoS.
   - All password input schemas enforce a strict byte-length bound (`len(v.encode('utf-8')) <= 128`).
   - Missing-user login attempts execute `async_verify_dummy_password` against a precomputed static Argon2id hash, eliminating timing oracle enumeration.

3. **Session-Bound Double-Submit CSRF & Origin Enforcement (P0 #7):**
   - Mutating cookie-authenticated endpoints require strict `Origin` / `Referer` validation against `request.base_url` or configured `allowed_origins` (scheme, host, and port must match exactly).
   - Double-submit CSRF cookie (`fastapi_accounts_csrf`) and `X-CSRF-Token` header are validated in constant time.
   - Authenticated CSRF tokens are cryptographically bound to the active session ID; login rotates to a fresh session-bound token; logout clears both session and CSRF cookies. Bearer transport is exempt.

4. **Abuse & Rate Limiting with PII-Safe Hashed Keys (P0 #8):**
   - Sensitive flows (`/login`, `/register`, `/request-password-reset`, `/reset-password`, `/request-verify-email`, `/verify-email`, `/change-password`) are protected by a configurable `BaseRateLimiter`.
   - Rate limit keys use HMAC-SHA256 digests over `action`, normalized identity, and resolved client IP, preventing plaintext PII or IP leakage in storage.
   - The default `InMemorySlidingWindowLimiter` is single-process and bounds memory up to `max_keys=10000` entries via LRU and window expiration purge. Under adversarial key churn exceeding capacity, it evicts least-recently-used records. For distributed/multi-worker deployments or adversarial internet scale, configure a distributed rate limiter (e.g. Redis) or reverse proxy / API gateway.

5. **Request-Scoped Session & Principal Isolation (P0 #11):**
   - Current user dependencies capture `db: AsyncSession = Depends(adapter.get_db)`, strictly honoring FastAPI's `app.dependency_overrides`.
   - Dependencies return immutable `UserPrincipal` DTOs, completely isolating database entities and preventing lazy-loading / detached session hazards.

6. **Transaction Atomicity & Observable Post-Commit Callbacks (P0 #3, P0 #10):**
   - `AccountService` strictly owns database transactions (`begin`, `commit`, `rollback`). Stores execute queries and flushes without committing; routers never touch transactions.
   - External notification callbacks (`on_after_register`, `on_after_request_password_reset`) and `on_delivery_failure` execute strictly after `await session.commit()`. Callback exceptions are contained and logged without rolling back committed records or returning false HTTP 500 errors.

7. **Cryptographic Domain Separation & Secret Rotation (P0 #4):**
   - Production secrets require $\ge 32$ cryptographically random bytes (256 bits entropy, e.g. via `secrets.token_urlsafe(32)`).
   - Domain keys are derived via HMAC-SHA256 for auth tokens, CSRF tokens, and rate-limit hashing.
   - `TimedTokenSigner` supports zero-downtime key rotation using `Sequence[str]`.
   - Legacy raw fallback tokens (`token_v=1`) are disabled by default and restricted exclusively to `verify_email` via explicit opt-in (`allow_legacy_tokens=True`). Legacy token support is deprecated and scheduled for complete removal in `v0.2.0` (sunset date: 2026-12-31). Password reset tokens strictly reject legacy raw tokens under all configurations.
