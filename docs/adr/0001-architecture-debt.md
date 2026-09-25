# ADR 001: Deferred Domain/Router Separation

**Date:** 2026-09-25
**Status:** Accepted (Pre-1.0 Technical Debt)

## Context
The original P0 requirements (item #10) mandated a strict separation between domain services, the HTTP router, and the persistence store. While the persistence and service layers have been successfully isolated (`AccountService` and `SQLAlchemyAdapter`), the HTTP layer (`FastAPIAccounts._build_router`) remains a large, monolithic factory method that owns policy, dependency injection, and HTTP route definitions.

## Decision
We are formally amending the P0 acceptance criteria for the alpha releases. The monolithic router structure is officially accepted as **deferred pre-1.0 technical debt**. 

Because this structural coupling does not represent a runtime security vulnerability, it will not block the `v0.1.0` alpha series. A full refactoring of the router into smaller, composable extension contracts is planned for a subsequent phase prior to the stable `1.0.0` release.
