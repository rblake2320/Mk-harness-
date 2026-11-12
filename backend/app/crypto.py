"""AES-256-GCM envelope encryption for stored provider API keys.

Keys are never stored or logged in plaintext. Ciphertext layout:
base64( nonce[12] || gcm_ciphertext+tag ). AAD binds ciphertext to its scope
so a row copied between tenants/users fails to decrypt.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_secret(master_key: bytes, plaintext: str, aad: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(master_key).encrypt(nonce, plaintext.encode(), aad.encode())
    return base64.b64encode(nonce + ct).decode()


def decrypt_secret(master_key: bytes, ciphertext_b64: str, aad: str) -> str:
    raw = base64.b64decode(ciphertext_b64)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(master_key).decrypt(nonce, ct, aad.encode()).decode()


# ----------------------------------------------------------------- versioned (S10)
# Stored form: "mk1:<kid>:" + base64(nonce || ct+tag). Unprefixed ciphertext is the
# pre-versioning format and belongs to kid "m0" (MASTER_KEY).
PREFIX = "mk1:"


def seal_value(plaintext: str, aad: str) -> str:
    from .config import get_settings
    kid, key = get_settings().sealing_key_list[0]
    return f"{PREFIX}{kid}:" + encrypt_secret(key, plaintext, aad)


def key_id_of(ciphertext: str) -> str:
    if ciphertext.startswith(PREFIX):
        return ciphertext[len(PREFIX):].split(":", 1)[0]
    return "m0"


def open_value(ciphertext: str, aad: str) -> str:
    """Decrypt with the key the ciphertext names. A kid that is not configured is an
    error (never a silent fallback to another key)."""
    from .config import get_settings
    kid = key_id_of(ciphertext)
    body = ciphertext.split(":", 2)[2] if ciphertext.startswith(PREFIX) else ciphertext
    keys = dict(get_settings().sealing_key_list)
    if kid not in keys:
        raise KeyError(f"sealing key {kid!r} is not configured")
    return decrypt_secret(keys[kid], body, aad)


def key_aad(tenant_id: str, user_id: str | None, provider: str) -> str:
    return f"{tenant_id}:{user_id or 'tenant'}:{provider}"
