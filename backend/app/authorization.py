"""Explicit application role policy; unknown roles never inherit authority."""
from fastapi import HTTPException

APP_ROLES = frozenset({'admin', 'manager', 'consultant', 'auditor'})
TEAM_REVIEWERS = frozenset({'admin', 'manager'})
AUDIT_READERS = frozenset({'admin', 'auditor'})

# Auditors can read tenant audit evidence and manage only their own account's
# authentication/privacy. They cannot access customer books, models or the
# action-kernel proxy, even via endpoints added later.
AUDITOR_ROUTES = frozenset({
    ('GET', '/api/audit/export.jsonl'), ('GET', '/api/auth/me'),
    ('GET', '/api/auth/sessions'), ('POST', '/api/auth/sessions/{sid}/revoke'),
    ('POST', '/api/auth/change-password'), ('POST', '/api/auth/step-up'),
    ('GET', '/api/auth/mfa/status'), ('POST', '/api/auth/mfa/recovery-codes'),
    ('GET', '/api/account/export'), ('DELETE', '/api/account'),
})


def require_known_role(role: str) -> None:
    if role not in APP_ROLES:
        raise HTTPException(403, {'code': 'ROLE_INVALID', 'message': 'Account role is not recognized. Contact a tenant administrator.'})


def authorize_route(role: str, method: str, path: str) -> None:
    require_known_role(role)
    if role == 'auditor' and (method, path) not in AUDITOR_ROUTES:
        raise HTTPException(403, {'code': 'ROLE_FORBIDDEN', 'message': 'The auditor role cannot perform this operation.'})
