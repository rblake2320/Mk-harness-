"""Password hashing (argon2id) and JWT access/refresh tokens.

Tokens carry a `pv` (password version) claim — a short fingerprint of the
user's current password hash. Changing the password changes the fingerprint,
which immediately invalidates every previously issued access AND refresh
token. A persistent session row additionally governs access, revocation and
single-use refresh rotation; a JWT signature alone is never session authority.
"""
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import AuthSession, User
from .authorization import AUDIT_READERS, TEAM_REVIEWERS, authorize_route, require_known_role

_ph = PasswordHasher()

# Static hash used to equalise timing when the email does not exist —
# prevents user enumeration via the argon2-verify timing oracle.
_DUMMY_HASH = PasswordHasher().hash("timing-equalizer-not-a-real-password")


def password_fingerprint(password_hash: str) -> str:
    """Short, non-reversible fingerprint of the stored hash for the `pv` claim."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:12]


def dummy_verify() -> None:
    """Burn the same time as a real argon2 verification (constant-time login path)."""
    try:
        _ph.verify(_DUMMY_HASH, "wrong-password")
    except VerifyMismatchError:
        pass


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except VerifyMismatchError:
        return False


def _make_token(sub: str, tenant_id: str, role: str, kind: str, minutes: int,
                pv: str, session_id: str, nonce: str) -> str:
    s = get_settings()
    payload = {
        "sub": sub, "tid": tenant_id, "role": role, "kind": kind, "pv": pv,
        "sid": session_id, "jti": nonce,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256")


def make_access_token(user: User, session: AuthSession) -> str:
    return _make_token(user.id, user.tenant_id, user.role, "access",
                       get_settings().access_token_minutes,
                       pv=password_fingerprint(user.password_hash), session_id=session.id, nonce=uuid.uuid4().hex)


def make_refresh_token(user: User, session: AuthSession, nonce: str) -> str:
    return _make_token(user.id, user.tenant_id, user.role, "refresh",
                       get_settings().refresh_token_days * 24 * 60,
                       pv=password_fingerprint(user.password_hash), session_id=session.id, nonce=nonce)


def decode_token(token: str, expected_kind: str) -> dict:
    s = get_settings()
    try:
        payload = jwt.decode(token, s.jwt_secret, algorithms=["HS256"],
                             options={"require": ["sub", "tid", "sid", "pv", "kind", "jti", "iat", "exp"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    if payload.get("kind") != expected_kind:
        raise HTTPException(401, "Wrong token type")
    if any(not isinstance(payload.get(k), str) or not payload[k] for k in ("sub", "tid", "sid", "pv", "jti")):
        raise HTTPException(401, "Invalid token claims")
    return payload


def session_for(db: Session, payload: dict, user: User) -> AuthSession:
    session = db.get(AuthSession, payload["sid"])
    if (not session or session.user_id != user.id or session.tenant_id != user.tenant_id
            or payload["tid"] != user.tenant_id or session.revoked_at is not None
            or session.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)):
        raise HTTPException(401, "Session expired or revoked")
    return session


def get_authenticated_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    payload = decode_token(auth[7:], "access")
    user = db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or deactivated")
    require_known_role(user.role)
    # Reject tokens minted before the most recent password change.
    # compare_digest: constant-time — no oracle on how many chars matched.
    if not hmac.compare_digest(str(payload.get("pv") or ""),
                               password_fingerprint(user.password_hash)):
        raise HTTPException(401, "Session expired — please sign in again")
    request.state.auth_session = session_for(db, payload, user)
    return user


def mfa_required() -> bool:
    """Mandatory in every runtime; no environment flag can disable MFA.

    Feature-unit tests replace this function explicitly. MFA acceptance tests
    and actual app/CI entrypoints exercise the unchanged mandatory policy.
    """
    return True


# Exact matched route templates, not substring checks on caller-controlled URLs.
# Revoking one's own session, stopping sending and rejecting approvals remain
# immediate safety controls. Enabling sending gets its handler-level step-up.
SENSITIVE_ROUTES = frozenset({
    ('POST', '/api/auth/members'), ('POST', '/api/auth/change-password'),
    ('PATCH', '/api/auth/members/{member_id}'),
    ('GET', '/api/account/export'), ('DELETE', '/api/account'),
    ('DELETE', '/api/customers/{cid}'),
    ('GET', '/api/customers/export.csv'), ('GET', '/api/audit/export.jsonl'),
    ('GET', '/api/me/skin-data/export'), ('DELETE', '/api/me/skin-data'),
    ('POST', '/api/billing/checkout'), ('POST', '/api/billing/portal'),
    ('PUT', '/api/keys/mine'), ('PUT', '/api/keys/tenant'), ('DELETE', '/api/keys/mine/{provider}'),
    ('POST', '/api/customers/{cid}/consent'), ('POST', '/api/customers/{cid}/consent/{eid}/revoke'),
    ('POST', '/api/consent/skin'), ('DELETE', '/api/consent/skin'),
    ('POST', '/api/agent-ops/approval-credentials/register/begin'),
    ('POST', '/api/agent-ops/approval-credentials/register/finish'),
    ('POST', '/api/agent-ops/approval-credentials/{row_id}/revoke'),
    ('POST', '/api/agent-ops/senders'), ('POST', '/api/agent-ops/senders/{sender_id}/registration'),
    ('POST', '/api/agent-ops/contacts/{contact_id}/permissions'),
    ('POST', '/api/agent-ops/contacts/{contact_id}/permissions/{permission_id}/revoke'),
    ('DELETE', '/api/agent-ops/suppressions/{suppression_id}'),
    ('POST', '/api/agent-ops/adapters'), ('POST', '/api/agent-ops/adapters/{adapter_id}/rotate'),
    ('POST', '/api/agent-ops/adapters/{adapter_id}/revoke'), ('POST', '/api/agent-ops/inbound/resume'),
})


def enforce_step_up(session: AuthSession) -> None:
    if not mfa_required():
        return
    stamp = session.step_up_at
    now = datetime.now(timezone.utc)
    if stamp is None or not timedelta(0) <= now - stamp.replace(tzinfo=timezone.utc) <= timedelta(minutes=5):
        raise HTTPException(403, {'code': 'STEP_UP_REQUIRED', 'message': 'Confirm your password and a fresh second factor before this change.'})


def get_current_user(request: Request, user: User = Depends(get_authenticated_user)) -> User:
    from .route_policy import matched_route_template
    path = matched_route_template(request.scope)
    authorize_route(user.role, request.method, path)
    if mfa_required():
        session = request.state.auth_session
        if session.mfa_verified_at is None:
            raise HTTPException(403, {'code': 'MFA_REQUIRED', 'message': 'Complete second-factor verification before using the app.'})
        if (request.method, path) in SENSITIVE_ROUTES:
            enforce_step_up(session)
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return user


def require_team_reviewer(user: User = Depends(get_current_user)) -> User:
    if user.role not in TEAM_REVIEWERS:
        raise HTTPException(403, 'Manager or admin role required')
    return user


def require_audit_reader(user: User = Depends(get_current_user)) -> User:
    if user.role not in AUDIT_READERS:
        raise HTTPException(403, 'Auditor or admin role required')
    return user
