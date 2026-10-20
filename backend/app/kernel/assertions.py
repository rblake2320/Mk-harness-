"""Ed25519 actor assertions, minted per request for the Rust action kernel.

Wire format (must match `rust/crates/mk-crypto/src/assertion.rs` exactly):

    b64url(header) "." b64url(payload) "." b64url(signature)

    header  = {"alg":"EdDSA","typ":"mk-assertion+v1","kid":"<key id>"}
    payload = {iss, aud, sub, tenant_id, roles, session_id, request_id,
               iat, exp, jti}            (no other fields — kernel denies unknown)

Invariants the kernel enforces and this module therefore guarantees:
* iss == "mk-fastapi", aud == "mk-action-kernel"
* exp - iat <= 60 s; this minter uses 30 s so clock skew never matters
* sub / tenant_id / jti are UUIDs (never nil); jti is fresh per assertion and
  single-use for every non-GET request (the kernel records it durably)
* roles non-empty

The private key never leaves this process; the kernel holds only the public
half (``MK_ASSERTION_KEYS=<kid>=<b64url pubkey>``).
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISSUER = "mk-fastapi"
AUDIENCE = "mk-action-kernel"
TYP = "mk-assertion+v1"
LIFETIME_SECONDS = 30  # kernel max is 60; keep headroom for skew

# Role vocabulary understood by the kernel. Approver roles are exactly
# rust/crates/mk-policy/src/approval.rs::APPROVER_ROLES = consultant | manager |
# tenant_admin; `agent` (alone) marks an autonomous principal; `platform_operator`
# unlocks the global kill switch. Anything else is ignored by the kernel.
ROLE_CONSULTANT = "consultant"
ROLE_TENANT_ADMIN = "tenant_admin"
ROLE_AGENT = "agent"
ROLE_PLATFORM_OPERATOR = "platform_operator"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def to_uuid(hex_or_uuid: str) -> uuid.UUID:
    """Application ids are uuid4().hex (32 chars); the kernel wants RFC 4122 text."""
    return uuid.UUID(hex_or_uuid)


class AssertionConfigError(RuntimeError):
    """Raised when the signing key is missing or malformed."""


@dataclass(frozen=True)
class AssertionMinter:
    kid: str
    _key: Ed25519PrivateKey

    @classmethod
    def from_seed_b64url(cls, kid: str, seed_b64url: str) -> "AssertionMinter":
        if not kid or not kid.strip():
            raise AssertionConfigError("KERNEL_ASSERTION_KID is empty")
        try:
            seed = _b64url_decode(seed_b64url.strip())
        except Exception as e:  # noqa: BLE001 — any decode failure is a config error
            raise AssertionConfigError("KERNEL_ASSERTION_PRIVATE_KEY is not base64url") from e
        if len(seed) != 32:
            raise AssertionConfigError("KERNEL_ASSERTION_PRIVATE_KEY must decode to 32 bytes")
        return cls(kid=kid.strip(), _key=Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def generate(cls, kid: str = "k1") -> "AssertionMinter":
        """Test/dev helper. Production keys come from env, never generated here."""
        return cls(kid=kid, _key=Ed25519PrivateKey.generate())

    def public_key_b64url(self) -> str:
        raw = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return _b64url(raw)

    def mint(
        self,
        *,
        user_id: str,
        tenant_id: str,
        roles: list[str],
        session_id: str,
        request_id: str,
        now: int | None = None,
    ) -> str:
        if not roles:
            raise ValueError("roles must be non-empty")
        if not session_id or not request_id:
            raise ValueError("session_id and request_id are required")
        iat = int(time.time()) if now is None else int(now)
        payload = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": str(to_uuid(user_id)),
            "tenant_id": str(to_uuid(tenant_id)),
            "roles": list(roles),
            "session_id": session_id,
            "request_id": request_id,
            "iat": iat,
            "exp": iat + LIFETIME_SECONDS,
            "jti": str(uuid.uuid4()),
        }
        header = {"alg": "EdDSA", "typ": TYP, "kid": self.kid}
        h = _b64url(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode("ascii")
        sig = self._key.sign(signing_input)
        return f"{h}.{p}.{_b64url(sig)}"


def roles_for(app_role: str, *, as_agent: bool = False) -> list[str]:
    """Map the application's role to the kernel's role vocabulary.

    ``as_agent`` mints an *agent-only* principal: the kernel treats such a
    caller as autonomous (origin=agent, cannot approve, cannot self-approve,
    cannot touch consent). It is used only for proposals raised by the AI
    layer on the user's behalf.
    """
    if as_agent:
        return [ROLE_AGENT]
    if app_role == "admin":
        return [ROLE_CONSULTANT, ROLE_TENANT_ADMIN]
    return [ROLE_CONSULTANT]


def build_minter(kid: str, seed_b64url: str) -> AssertionMinter | None:
    """Return a minter or None when the key is not configured."""
    if not seed_b64url:
        return None
    return AssertionMinter.from_seed_b64url(kid, seed_b64url)
