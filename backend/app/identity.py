"""Sessions, second factors, step-up and break-glass (S2, S9; H9 cascade).

* Every access/refresh token names a server-side session row (`sid`). The row is
  the authority: revoking it ends every token minted for it at the next request,
  and the revocation is propagated to the kernel (H9) through an outbox written
  in the same transaction, so a revoked session can neither approve nor have its
  pending approvals dispatched.
* Refresh tokens rotate; presenting an already-used refresh token (theft signal)
  revokes the whole session.
* Second factors: TOTP (RFC 6238, replay barrier per factor), passkeys (WebAuthn,
  user verification required, counter regression refused) and single-use
  recovery codes (argon2id). Five failed second-factor attempts kill the session.
* Step-up: sender, permission, export and security changes need a second factor
  verified within STEP_UP_WINDOW on the same session (rbac.ROUTE_POLICY marks them).
* Break-glass: platform support reads a tenant only through an approved,
  unexpired grant; it acts as itself (never as the tenant's user) and every
  request is audited in the target tenant.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .foundation import audit, seal, unseal, utcnow
from .models import (
    AuditLog, AuthSession, BreakGlassGrant, KernelRevocationOutbox, MfaFactor, MfaRecoveryCode,
    User, WebAuthnChallenge,
)

MAX_FACTOR_FAILURES = 5
RECOVERY_CODE_COUNT = 10
_ph = PasswordHasher()


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; every comparison here is in UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Principals
# --------------------------------------------------------------------------- #
@dataclass
class SupportPrincipal:
    """Platform support acting under a break-glass grant. Not an ORM object:
    nothing a handler does to it can be persisted as a tenant user."""
    id: str
    tenant_id: str            # the TARGET tenant
    works_for: str            # the consultant whose book the grant covers
    email: str
    display_name: str
    role: str = "support"
    is_active: bool = True
    password_hash: str = ""


def client_label(user_agent: str) -> str:
    """Coarse device label for the sessions list (never the raw user agent or IP)."""
    ua = (user_agent or "").lower()
    browser = next((b for k, b in (("edg/", "Edge"), ("firefox", "Firefox"), ("chrome", "Chrome"),
                                   ("safari", "Safari"), ("expo", "Mobile app"), ("okhttp", "Mobile app"))
                    if k in ua), "Browser")
    osys = next((o for k, o in (("iphone", "iPhone"), ("ipad", "iPad"), ("android", "Android"),
                                ("windows", "Windows"), ("mac os", "Mac"), ("linux", "Linux")) if k in ua), "")
    return f"{browser} on {osys}" if osys else browser


# --------------------------------------------------------------------------- #
# Sessions and tokens
# --------------------------------------------------------------------------- #
def new_session(db: Session, user: User, request: Request | None, *, kind: str = "user",
                tenant_id: str | None = None, grant: BreakGlassGrant | None = None,
                expires_at: datetime | None = None) -> AuthSession:
    now = utcnow()
    s = AuthSession(
        tenant_id=tenant_id or user.tenant_id, user_id=user.id, kind=kind,
        breakglass_grant_id=grant.id if grant else None,
        created_at=now, last_seen_at=now,
        expires_at=expires_at or now + timedelta(days=get_settings().session_max_days),
        client_label=client_label(request.headers.get("user-agent", "") if request else ""),
    )
    db.add(s)
    db.flush()
    return s


def _jwt(payload: dict) -> str:
    import jwt as pyjwt
    return pyjwt.encode(payload, get_settings().jwt_secret, algorithm="HS256")


def _decode(token: str, kind: str) -> dict:
    import jwt as pyjwt
    try:
        payload = pyjwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"],
                               options={"require": ["exp", "iat", "sub", "kind"]})
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    if payload.get("kind") != kind:
        raise HTTPException(401, "Wrong token type")
    return payload


def _pv(user) -> str:
    from .security import password_fingerprint
    return password_fingerprint(user.password_hash) if getattr(user, "password_hash", "") else ""


def _wall() -> datetime:
    """JWT iat/exp are validated by PyJWT against the real clock, never the test seam."""
    return datetime.now(timezone.utc)


def token_pair(user, session: AuthSession, *, role: str | None = None) -> dict:
    s = get_settings()
    now = _wall()
    base = {"sub": user.id, "tid": session.tenant_id, "role": role or user.role, "sid": session.id,
            "pv": _pv(user), "iat": now}
    access_exp = now + timedelta(minutes=s.access_token_minutes)
    if session.kind == "breakglass":
        # Ends when the grant ends (session expiry is in app time; convert the remaining span).
        remaining = _aware(session.expires_at) - utcnow()
        access_exp = min(access_exp, now + max(remaining, timedelta(0)))
    access = _jwt({**base, "kind": "access", "exp": access_exp})
    out = {"access_token": access, "role": role or user.role, "display_name": user.display_name,
           "tenant_id": session.tenant_id, "session_id": session.id}
    if session.kind == "user":
        remaining = _aware(session.expires_at) - utcnow()
        refresh_exp = min(now + timedelta(days=s.refresh_token_days), now + max(remaining, timedelta(0)))
        out["refresh_token"] = _jwt({**base, "kind": "refresh", "rc": session.refresh_counter, "exp": refresh_exp})
    else:
        out["refresh_token"] = ""   # break-glass access cannot be refreshed; ask for a new session
    return out


def mfa_token(session: AuthSession, user: User) -> str:
    now = _wall()
    return _jwt({"sub": user.id, "tid": session.tenant_id, "sid": session.id, "kind": "mfa", "pv": _pv(user),
                 "iat": now, "exp": now + timedelta(minutes=get_settings().mfa_challenge_minutes)})


def _live_session(db: Session, payload: dict) -> AuthSession:
    sid = payload.get("sid")
    sess = db.get(AuthSession, sid) if isinstance(sid, str) else None
    if (sess is None or sess.user_id != payload.get("sub") or sess.tenant_id != payload.get("tid")
            or sess.revoked_at is not None or _aware(sess.expires_at) <= utcnow()):
        raise HTTPException(401, "Session expired — please sign in again")
    return sess


def authenticate(request: Request, db: Session):
    """Resolve the bearer token to (principal, session). Cached on request.state."""
    if getattr(request.state, "principal", None) is not None:
        return request.state.principal
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    payload = _decode(auth[7:], "access")
    sess = _live_session(db, payload)
    user = db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or deactivated")
    if not hmac.compare_digest(str(payload.get("pv") or ""), _pv(user)):
        raise HTTPException(401, "Session expired — please sign in again")
    if sess.kind == "user" and sess.tenant_id != user.tenant_id:
        raise HTTPException(401, "Session expired — please sign in again")
    request.state.auth_session = sess
    request.state.breakglass = None
    principal = user
    if sess.kind == "breakglass":
        grant = db.get(BreakGlassGrant, sess.breakglass_grant_id or "")
        now = utcnow()
        if (grant is None or grant.status != "approved" or grant.revoked_at is not None
                or grant.expires_at is None or _aware(grant.expires_at) <= now
                or user.id not in get_settings().platform_support_ids or grant.requested_by != user.id
                or grant.tenant_id != sess.tenant_id):
            raise HTTPException(401, {"code": "BREAKGLASS_ENDED", "detail": "break-glass access has ended"})
        request.state.breakglass = grant
        principal = SupportPrincipal(id=user.id, tenant_id=grant.tenant_id, works_for=grant.subject_user_id,
                                     email=user.email, display_name=f"Support: {user.display_name}")
    now = utcnow()
    if (now - _aware(sess.last_seen_at)).total_seconds() > 60:
        sess.last_seen_at = now
        db.commit()
    request.state.principal = principal
    request.state.user = principal
    return principal


def has_confirmed_factor(db: Session, user_id: str) -> bool:
    return db.scalar(select(MfaFactor.id).where(
        MfaFactor.user_id == user_id, MfaFactor.confirmed_at.is_not(None),
        MfaFactor.revoked_at.is_(None)).limit(1)) is not None


def mfa_blocks(db: Session, user, session: AuthSession) -> bool:
    """True when this session may only reach MFA enrollment routes."""
    return get_settings().mfa_required and session.kind == "user" and session.mfa_at is None


def methods_for(db: Session, user) -> list[str]:
    rows = db.scalars(select(MfaFactor.kind).where(
        MfaFactor.user_id == user.id, MfaFactor.confirmed_at.is_not(None), MfaFactor.revoked_at.is_(None))).all()
    methods = sorted(set(rows))
    if methods and db.scalar(select(MfaRecoveryCode.id).where(
            MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None)).limit(1)):
        methods.append("recovery")
    if not methods and not get_settings().mfa_required:
        methods = ["password"]   # development/test only; pre-flight refuses MFA_REQUIRED=false
    return methods


def require_step_up(db: Session, user, session: AuthSession) -> None:
    window = timedelta(minutes=min(max(get_settings().step_up_window_minutes, 1), 15))
    now = utcnow()
    for t in (session.step_up_at, session.mfa_at):
        t = _aware(t)
        if t is not None and timedelta(0) <= now - t <= window:
            return
    # 403, not 401: the caller IS authenticated. A 401 here made clients refresh the
    # token, retry, fail again and sign the user out instead of prompting for step-up.
    raise HTTPException(403, {"code": "STEP_UP_REQUIRED",
                              "detail": "confirm it's you with your second factor to make this change",
                              "methods": [m for m in methods_for(db, user) if m != "recovery"]})


def step_up_fresh(db: Session, request: Request) -> None:
    """For handlers whose step-up depends on the body (e.g. enabling vs disabling)."""
    require_step_up(db, request.state.principal, request.state.auth_session)


# --------------------------------------------------------------------------- #
# Revocation (+ kernel outbox, H9)
# --------------------------------------------------------------------------- #
def kernel_session_id(session_id: str) -> str:
    return "app:" + session_id


def revoke_session(db: Session, session: AuthSession, *, by: str, reason: str, actor=None) -> None:
    if session.revoked_at is not None:
        return
    session.revoked_at, session.revoked_by, session.revoked_reason = utcnow(), by, reason[:40]
    if session.kind != "user":
        return   # break-glass sessions never reach the kernel (agent-ops is outside their scope)
    actor = actor or db.get(User, session.user_id)
    db.add(KernelRevocationOutbox(
        tenant_id=session.tenant_id, actor_user_id=actor.id, actor_role=actor.role,
        target_user_id=session.user_id, session_id=kernel_session_id(session.id), reason=reason[:120]))


def revoke_user_sessions(db: Session, user: User, *, by: str, reason: str, except_sid: str | None = None,
                         actor=None) -> int:
    n = 0
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id,
                                                  AuthSession.revoked_at.is_(None))).all():
        if s.id != except_sid:
            revoke_session(db, s, by=by, reason=reason, actor=actor or user)
            n += 1
    return n


def revoke_user_in_kernel(db: Session, target: User, *, actor: User, reason: str) -> None:
    db.add(KernelRevocationOutbox(tenant_id=target.tenant_id, actor_user_id=actor.id, actor_role=actor.role,
                                  target_user_id=target.id, session_id="", reason=reason[:120]))


def deliver_kernel_revocations(db: Session, *, tenant_id: str | None = None, limit: int = 50) -> dict:
    """Send pending revocations to the kernel. Idempotent on the kernel side (a
    repeated revocation is a no-op); an outbox row is marked delivered only on 2xx."""
    from .kernel.client import KernelUnavailable, get_kernel_client
    from .rbac import kernel_roles

    client = get_kernel_client()
    q = select(KernelRevocationOutbox).where(KernelRevocationOutbox.delivered_at.is_(None))
    if tenant_id:
        q = q.where(KernelRevocationOutbox.tenant_id == tenant_id)
    rows = db.scalars(q.order_by(KernelRevocationOutbox.created_at).limit(limit)).all()
    out = {"delivered": 0, "pending": 0, "not_configured": False}
    if not client.configured:
        out["pending"] = len(rows)
        out["not_configured"] = True
        return out
    for row in rows:
        body: dict = {"reason": row.reason or "revoked"}
        if row.session_id:
            body["session_id"] = row.session_id
            if row.target_user_id != row.actor_user_id:
                body["user_id"] = str(_uuid(row.target_user_id))
        else:
            body["user_id"] = str(_uuid(row.target_user_id))
        row.attempts += 1
        try:
            r = client.call_sync("POST", "/revocations", user_id=row.actor_user_id, tenant_id=row.tenant_id,
                                 roles=kernel_roles(row.actor_role) if kernel_roles(row.actor_role) != ["agent"]
                                 else ["consultant"],
                                 session_id=row.session_id or "app:system", json=body)
        except KernelUnavailable as e:
            row.last_error = e.code[:200]
            out["pending"] += 1
            continue
        if 200 <= r.status_code < 300:
            row.delivered_at = utcnow()
            out["delivered"] += 1
        else:
            row.last_error = f"HTTP {r.status_code} {str(r.body)[:150]}"
            out["pending"] += 1
    db.commit()
    return out


def _uuid(hex_id: str):
    import uuid
    return uuid.UUID(hex_id)


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238)
# --------------------------------------------------------------------------- #
TOTP_STEP = 30
TOTP_DIGITS = 6


def totp_code(secret: bytes, step: int, digits: int = TOTP_DIGITS) -> str:
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_step(at: datetime) -> int:
    return int(at.timestamp()) // TOTP_STEP


def _b32(secret: bytes) -> str:
    return base64.b32encode(secret).decode().rstrip("=")


def _unb32(s: str) -> bytes:
    s = s.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def begin_totp(db: Session, user: User) -> tuple[MfaFactor, str, str]:
    # Unconfirmed TOTP enrollments never accumulate: a new begin replaces them.
    for f in db.scalars(select(MfaFactor).where(MfaFactor.user_id == user.id, MfaFactor.kind == "totp",
                                                MfaFactor.confirmed_at.is_(None), MfaFactor.revoked_at.is_(None))):
        f.revoked_at = utcnow()
    secret = os.urandom(20)
    f = MfaFactor(tenant_id=user.tenant_id, user_id=user.id, kind="totp", label="Authenticator app")
    db.add(f)
    db.flush()
    f.secret_enc = seal(user.tenant_id, f"totp:{user.id}:{f.id}", _b32(secret))
    uri = (f"otpauth://totp/{quote('Consultant Studio')}:{quote(user.email)}?secret={_b32(secret)}"
           f"&issuer={quote('Consultant Studio')}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")
    return f, _b32(secret), uri


def _clean_code(code: str, digits: int) -> str | None:
    c = "".join(ch for ch in (code or "") if not ch.isspace())
    # ASCII digits only: str.isdigit() also accepts e.g. Arabic-Indic digits, which
    # hmac.compare_digest refuses to compare (TypeError → 500).
    return c if len(c) == digits and c.isascii() and c.isdigit() else None


def check_totp(db: Session, factor: MfaFactor, code: str, at: datetime | None = None) -> bool:
    """Accept the current step ±1; never a step at or before the last accepted one."""
    c = _clean_code(code, TOTP_DIGITS)
    if c is None or factor.revoked_at is not None:
        return False
    secret = _unb32(unseal(factor.tenant_id, f"totp:{factor.user_id}:{factor.id}", factor.secret_enc))
    now_step = totp_step(at or utcnow())
    for step in (now_step - 1, now_step, now_step + 1):
        if step > factor.last_used_step and hmac.compare_digest(totp_code(secret, step), c):
            factor.last_used_step = step
            factor.last_used_at = utcnow()
            return True
    return False


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #
_RC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I


def new_recovery_codes(db: Session, user: User) -> list[str]:
    for rc in db.scalars(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id,
                                                       MfaRecoveryCode.used_at.is_(None))):
        rc.used_at = utcnow()   # regenerating invalidates the old set
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_RC_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=_ph.hash(raw)))
    return codes


def check_recovery(db: Session, user: User, code: str) -> bool:
    raw = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    if len(raw) != 10:
        return False
    for rc in db.scalars(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id,
                                                       MfaRecoveryCode.used_at.is_(None))).all():
        try:
            if _ph.verify(rc.code_hash, raw):
                rc.used_at = utcnow()
                return True
        except VerifyMismatchError:
            continue
    return False


# --------------------------------------------------------------------------- #
# Passkeys (WebAuthn) for sign-in second factor and step-up
# --------------------------------------------------------------------------- #
def _rp():
    s = get_settings()
    if not s.app_webauthn_rp_id or not s.app_webauthn_origin_list:
        raise HTTPException(409, {"code": "PASSKEYS_NOT_CONFIGURED",
                                  "detail": "passkeys are not configured for this deployment"})
    return s.app_webauthn_rp_id, s.app_webauthn_rp_name, s.app_webauthn_origin_list


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _store_challenge(db: Session, user: User, session: AuthSession, purpose: str, challenge: bytes) -> None:
    for c in db.scalars(select(WebAuthnChallenge).where(WebAuthnChallenge.session_id == session.id,
                                                        WebAuthnChallenge.purpose == purpose,
                                                        WebAuthnChallenge.used_at.is_(None))):
        c.used_at = utcnow()   # one live challenge per purpose per session
    db.add(WebAuthnChallenge(user_id=user.id, session_id=session.id, purpose=purpose, challenge=_b64u(challenge),
                             expires_at=utcnow() + timedelta(minutes=5)))


def _take_challenge(db: Session, session: AuthSession, purpose: str) -> bytes:
    c = db.scalar(select(WebAuthnChallenge).where(
        WebAuthnChallenge.session_id == session.id, WebAuthnChallenge.purpose == purpose,
        WebAuthnChallenge.used_at.is_(None)).order_by(WebAuthnChallenge.expires_at.desc()))
    if c is None or _aware(c.expires_at) <= utcnow():
        raise HTTPException(409, {"code": "CHALLENGE_EXPIRED", "detail": "start the passkey step again"})
    c.used_at = utcnow()   # burned whether or not verification succeeds
    return _unb64u(c.challenge)


def passkey_registration_options(db: Session, user: User, session: AuthSession) -> dict:
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    rp_id, rp_name, _ = _rp()
    existing = db.scalars(select(MfaFactor).where(MfaFactor.user_id == user.id, MfaFactor.kind == "webauthn",
                                                  MfaFactor.revoked_at.is_(None))).all()
    opts = generate_registration_options(
        rp_id=rp_id, rp_name=rp_name, user_id=user.id.encode(), user_name=user.email,
        user_display_name=user.display_name or user.email,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=_unb64u(f.credential_id)) for f in existing],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED),
    )
    _store_challenge(db, user, session, "register", opts.challenge)
    return json.loads(options_to_json(opts))


def passkey_register(db: Session, user: User, session: AuthSession, credential: dict, label: str) -> MfaFactor:
    from webauthn import verify_registration_response
    rp_id, _, origins = _rp()
    challenge = _take_challenge(db, session, "register")
    try:
        v = verify_registration_response(credential=credential, expected_challenge=challenge,
                                         expected_rp_id=rp_id, expected_origin=origins,
                                         require_user_verification=True)
    except Exception as e:  # noqa: BLE001 — the library raises several types; all mean "refused"
        db.commit()   # keep the burned challenge
        raise HTTPException(400, {"code": "PASSKEY_REJECTED", "detail": str(e)[:200]})
    cred_id = _b64u(v.credential_id)
    if db.scalar(select(MfaFactor.id).where(MfaFactor.credential_id == cred_id, MfaFactor.revoked_at.is_(None))):
        raise HTTPException(409, {"code": "PASSKEY_ALREADY_REGISTERED"})
    f = MfaFactor(tenant_id=user.tenant_id, user_id=user.id, kind="webauthn", label=(label or "Passkey")[:60],
                  credential_id=cred_id, public_key=_b64u(v.credential_public_key), sign_count=v.sign_count,
                  confirmed_at=utcnow())
    db.add(f)
    return f


def passkey_auth_options(db: Session, user: User, session: AuthSession, purpose: str) -> dict:
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
    rp_id, _, _ = _rp()
    creds = db.scalars(select(MfaFactor).where(MfaFactor.user_id == user.id, MfaFactor.kind == "webauthn",
                                               MfaFactor.confirmed_at.is_not(None),
                                               MfaFactor.revoked_at.is_(None))).all()
    if not creds:
        raise HTTPException(409, {"code": "NO_PASSKEY", "detail": "no passkey is registered for this account"})
    opts = generate_authentication_options(
        rp_id=rp_id, allow_credentials=[PublicKeyCredentialDescriptor(id=_unb64u(f.credential_id)) for f in creds],
        user_verification=UserVerificationRequirement.REQUIRED)
    _store_challenge(db, user, session, purpose, opts.challenge)
    return json.loads(options_to_json(opts))


def check_passkey(db: Session, user: User, session: AuthSession, credential: dict, purpose: str) -> bool:
    from webauthn import verify_authentication_response
    rp_id, _, origins = _rp()
    challenge = _take_challenge(db, session, purpose)
    cred_id = credential.get("id") or credential.get("rawId") if isinstance(credential, dict) else None
    f = db.scalar(select(MfaFactor).where(MfaFactor.user_id == user.id, MfaFactor.kind == "webauthn",
                                          MfaFactor.credential_id == str(cred_id or ""),
                                          MfaFactor.revoked_at.is_(None)))
    if f is None:
        return False
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=challenge,
                                           expected_rp_id=rp_id, expected_origin=origins,
                                           credential_public_key=_unb64u(f.public_key),
                                           credential_current_sign_count=f.sign_count,
                                           require_user_verification=True)
    except Exception:  # noqa: BLE001 — signature, origin, rp, flags, counter regression
        return False
    f.sign_count, f.last_used_at = v.new_sign_count, utcnow()
    return True


# --------------------------------------------------------------------------- #
# One verifier for login MFA and step-up
# --------------------------------------------------------------------------- #
def verify_second_factor(db: Session, user: User, session: AuthSession, *, method: str, code: str = "",
                         credential: dict | None = None, password: str = "", purpose: str) -> str:
    """Returns the method used; 401 on failure. Failures count per session; the fifth
    kills the session (the attacker must start over with the password)."""
    ok = False
    if method == "totp":
        for f in db.scalars(select(MfaFactor).where(MfaFactor.user_id == user.id, MfaFactor.kind == "totp",
                                                    MfaFactor.confirmed_at.is_not(None),
                                                    MfaFactor.revoked_at.is_(None))).all():
            if check_totp(db, f, code):
                ok = True
                break
    elif method == "webauthn" and credential is not None:
        ok = check_passkey(db, user, session, credential, purpose)
    elif method == "recovery" and purpose == "login":
        ok = check_recovery(db, user, code)
    elif method == "password" and "password" in methods_for(db, user):
        from .security import verify_password
        ok = verify_password(password, user.password_hash)
    if not ok:
        session.mfa_failures += 1
        if session.mfa_failures >= MAX_FACTOR_FAILURES:
            revoke_session(db, session, by="system", reason="second_factor_failures")
            db.add(AuditLog(tenant_id=session.tenant_id, user_id=user.id, action="auth.mfa_lockout", detail=""))
            db.commit()
            raise HTTPException(401, {"code": "SESSION_ENDED", "detail": "too many failed attempts — sign in again"})
        db.commit()
        # Login challenge (no session token yet) → 401; inside an authenticated session
        # (step-up) → 403 so clients do not treat a mistyped code as an expired token.
        raise HTTPException(401 if purpose == "login" else 403,
                            {"code": "SECOND_FACTOR_INVALID", "detail": "that code or passkey was not accepted",
                                  "attempts_left": MAX_FACTOR_FAILURES - session.mfa_failures})
    session.mfa_failures = 0
    now = utcnow()
    if purpose == "login":
        session.mfa_at = now
    session.step_up_at = now
    methods = set(filter(None, session.methods.split(",")))
    methods.add(method)
    session.methods = ",".join(sorted(methods))[:64]
    return method


# --------------------------------------------------------------------------- #
# Break-glass
# --------------------------------------------------------------------------- #
def audit_breakglass(db: Session, request: Request, *, allowed: bool) -> None:
    grant: BreakGlassGrant = request.state.breakglass
    principal = request.state.principal
    method, path = request.method, getattr(request.scope.get("route"), "path", request.url.path)
    grant.access_count += 1
    audit(db, grant.tenant_id, principal.id, "breakglass.access" if allowed else "breakglass.denied",
          {"grant": grant.id, "method": method, "route": path, "ticket": grant.ticket_ref})
    db.commit()
