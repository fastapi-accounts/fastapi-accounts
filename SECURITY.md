# Security Policy

## Supported Versions
Only the latest released version of FastAPIAccounts is supported for security updates. 

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

Please **do not report security vulnerabilities through public GitHub issues, discussions, or pull requests**.

If you believe you have found a security vulnerability, please send an email to the project maintainers privately.

In your email, include:
- A description of the vulnerability and its impact.
- Steps to reproduce the issue.
- Any potential mitigation you suggest.

You should expect a response within 48 hours. If the vulnerability is confirmed, we will coordinate a fix and an advisory before any public disclosure.

## Known Limitations (Alpha / Phase 1)
As an Alpha release, FastAPIAccounts defers certain complex architectural security constraints (like full multi-tenant read-replica isolation and zero-downtime key rotation pipelines) to later phases. Standard endpoint protections, token bindings, and CAS verifications are active.
