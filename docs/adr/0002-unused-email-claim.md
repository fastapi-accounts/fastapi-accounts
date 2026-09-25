# ADR 002: Unused Email Claim in Reset Tokens

**Date:** 2026-09-25
**Status:** Tracked as Design Debt

## Context
During the Phase 1 security audit, it was discovered that while the password reset route successfully validates the user ID (`sub`), the token `action`, the token `version`, and the `credential_generation` against the database, it **does not strictly enforce the `email` claim** embedded inside the signed token payload.

A signed token with the correct user/version but an unrelated email will successfully reset the password. 

## Decision
Because the token is cryptographically signed, an attacker cannot arbitrarily forge a token with a mismatched email unless they already possess the signing key or another issuance flaw exists. Furthermore, once used, the token is instantly invalidated because the credential generation is incremented.

Therefore, this is not an exploitable vulnerability in the current default routes. We are formally tracking this as a design concern to be addressed before any future "email-change" or "account-linking" APIs are introduced, as those features would rely heavily on strict token-to-email bindings.
