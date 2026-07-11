"""Device-secret storage, request signing, replay bounds, and webhook policy."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import time
from urllib.parse import urlsplit

from ..crypto import decrypt_secret, encrypt_secret

SIGNATURE_TTL_SECONDS = 300


def agent_aad(tenant_id: str, agent_id: str) -> str:
    return f"call-center-agent:{tenant_id}:{agent_id}"


def new_agent_token() -> str:
    return secrets.token_urlsafe(32)


def encrypt_agent_token(
    master_key: bytes, token: str, tenant_id: str, agent_id: str
) -> str:
    return encrypt_secret(master_key, token, agent_aad(tenant_id, agent_id))


def decrypt_agent_token(
    master_key: bytes, ciphertext: str, tenant_id: str, agent_id: str
) -> str:
    return decrypt_secret(master_key, ciphertext, agent_aad(tenant_id, agent_id))


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def destination_fingerprint(
    master_key: bytes, tenant_id: str, channel: str, destination: str
) -> str:
    normalized = "|".join(
        [tenant_id, channel.strip().lower(), destination.strip().lower()]
    )
    return hmac.new(master_key, normalized.encode(), hashlib.sha256).hexdigest()


def signature_payload(
    method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    return "\n".join(
        [method.upper(), path, timestamp, nonce, body_digest(body)]
    ).encode()


def sign_request(
    secret: str,
    method: str,
    path: str,
    body: bytes,
    *,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    nonce = nonce or secrets.token_urlsafe(18)
    signature = hmac.new(
        secret.encode(),
        signature_payload(method, path, timestamp, nonce, body),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Claw-Timestamp": timestamp,
        "X-Claw-Nonce": nonce,
        "X-Claw-Signature": signature,
    }


def verify_request(
    secret: str,
    method: str,
    path: str,
    body: bytes,
    *,
    timestamp: str,
    nonce: str,
    signature: str,
    now_seconds: int | None = None,
) -> bool:
    if not timestamp.isdigit() or not nonce or len(nonce) > 80:
        return False
    now_seconds = int(time.time()) if now_seconds is None else now_seconds
    if abs(now_seconds - int(timestamp)) > SIGNATURE_TTL_SECONDS:
        return False
    expected = sign_request(
        secret,
        method,
        path,
        body,
        timestamp=timestamp,
        nonce=nonce,
    )["X-Claw-Signature"]
    return hmac.compare_digest(expected, signature)


def validate_webhook_url(url: str, allowed_authorities: set[str]) -> str:
    """Allow only explicitly configured HTTPS adapter authorities."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("webhook URL must be HTTPS and contain no credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("webhook URL must not contain a query string or fragment")
    authority = parsed.netloc.lower().rstrip(".")
    if authority not in allowed_authorities:
        raise ValueError("webhook authority is not in AGENT_OPERATIONS_WEBHOOK_HOSTS")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise ValueError(
            "private, loopback, link-local, and reserved webhook IPs are refused"
        )
    return parsed.geturl()
