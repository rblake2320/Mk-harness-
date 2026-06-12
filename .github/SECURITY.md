# Security Policy

This codebase stores encrypted third-party API keys and customer PII for
beauty consultants. Treat every report seriously.

## Reporting
Open a private report via GitHub Security Advisories on this repository
(Security tab → Report a vulnerability). Do not open public issues for
vulnerabilities.

## Hard rules for contributors
- No plaintext secrets in code, tests, fixtures, or CI logs
- Provider keys: AES-256-GCM only, AAD-bound to tenant:user:provider
- Every new endpoint must enforce tenant isolation and have a cross-tenant test
- Skin-analysis output must pass the server-side compliance scan; never
  weaken `SKIN_FORBIDDEN_TERMS` without legal review
