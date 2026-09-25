# ADR 003: Credential-Removal Session Semantics

**Date:** 2026-09-25
**Status:** Tracked as Design Debt

## Context
During the Phase 1 security audit, it was noted that deleting a user's password credential row directly from the database leaves their existing opaque session usable. The current built-in library routes do not expose any stock endpoint for credential deletion or "passwordless" account conversion.

## Decision
Because there is no reachable built-in flow to trigger this behavior, this does not represent an exploitable account-takeover vulnerability in the current release. 

However, before introducing future passwordless authentication APIs or allowing users to explicitly remove credential sets, we must strictly define and enforce the session lifecycle semantics. Specifically, we must establish a clear contract on whether removing a credential set should actively revoke or invalidate all active sessions bound to that credential generation. 

This design work is explicitly tracked as a required prerequisite for any such future feature expansions.
