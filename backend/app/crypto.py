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
    raw = base64.b64decode(ciphertext_b64, validate=True)
    if len(raw) < 28:
        raise ValueError("Malformed encrypted value")
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(master_key).decrypt(nonce, ct, aad.encode()).decode()


def key_aad(tenant_id: str, user_id: str | None, provider: str) -> str:
    return f"{tenant_id}:{user_id or 'tenant'}:{provider}"


def ciphertext_kid(ciphertext: str) -> str:
    import re
    if ":" not in ciphertext:
        return "legacy"
    parts = ciphertext.split(":")
    if len(parts) != 3 or parts[0] != "mk1" or not re.fullmatch(r"[a-z0-9_-]{1,16}", parts[1]):
        raise ValueError("Malformed encrypted envelope")
    return parts[1]


def seal_secret(plaintext: str, aad: str, *, keys=None) -> str:
    from .config import get_settings
    key_list = keys if keys is not None else get_settings().seal_key_list
    kid, key = key_list[0]
    prefix = f"mk1:{kid}:"
    return prefix + encrypt_secret(key, plaintext, "mk-app-seal:" + prefix + aad)


def unseal_secret(ciphertext: str, aad: str, *, keys=None) -> str:
    from .config import get_settings
    key_map = dict(keys if keys is not None else get_settings().seal_key_list)
    kid = ciphertext_kid(ciphertext)
    lookup = "m0" if kid == "legacy" else kid
    if lookup not in key_map:
        raise ValueError("Encrypted value key is unavailable")
    if kid == "legacy":
        return decrypt_secret(key_map[lookup], ciphertext, aad)
    prefix = f"mk1:{kid}:"
    return decrypt_secret(key_map[lookup], ciphertext[len(prefix):], "mk-app-seal:" + prefix + aad)
