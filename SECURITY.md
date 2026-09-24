# Security Policy

## Supported Versions
Only the latest released version of FastAPIAccounts is supported for security updates. 

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

Please **do not report security vulnerabilities through public GitHub issues, discussions, or pull requests**.

If you believe you have found a security vulnerability, please send an email to security@fastapi-accounts.example.com privately.

In your email, include:
- A description of the vulnerability and its impact.
- Steps to reproduce the issue.
- Any potential mitigation you suggest.

You should expect a response within 48 hours. If the vulnerability is confirmed, we will coordinate a fix and an advisory before any public disclosure.

## Known Limitations (Alpha / Phase 1)
As an Alpha release, FastAPIAccounts defers certain complex architectural security constraints (like full multi-tenant read-replica isolation and zero-downtime key rotation pipelines) to later phases. Standard endpoint protections, token bindings, and CAS verifications are active.

## Threat Model & Runbooks

### Threat Model
- **Token Leakage:** Mitigation via HTTPOnly/Secure cookies, anti-CSRF token synchronization, and short-lived stateless tokens.
- **Database Compromise:** Passwords protected via tunable Argon2id. Active sessions bound by generation identifiers, allowing instant invalidation on password change or explicit revocation.
- **Brute Force & Enumeration:** Hardened endpoints with sliding-window rate limiting; constant-time string comparisons used for token validation.

### Deployment & Compromise Runbook
1. **Secret Compromise:** If `FASTAPI_ACCOUNTS_SECRET_KEY` is compromised, deploy a new key immediately. The library will gracefully invalidate all existing pre-auth tokens, CSRF tokens, and active sessions (requiring users to log in again).
2. **Database Leak:** Enforce a global password reset and cycle all secrets. `password_updated_at` timestamps will track recovery.
3. **Key Rotation:** For zero-downtime key rotation, configure a multi-key strategy or rely on the `token_v` evolution planned for Phase 2. Currently, changing the key instantly rotates all cryptographic trust boundaries.
