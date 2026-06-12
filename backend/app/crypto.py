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


def key_aad(tenant_id: str, user_id: str | None, provider: str) -> str:
    return f"{tenant_id}:{user_id or 'tenant'}:{provider}"
