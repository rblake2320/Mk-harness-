"""Software WebAuthn authenticator (ES256, attestation "none") — test equipment only.

Produces the JSON shapes `navigator.credentials.create()/get()` return, so the
server-side verifier (py_webauthn) is exercised end to end, including the
negative cases a real authenticator would never produce (wrong origin, missing
user verification, tampered signature, counter regression).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id, self.origin = rp_id, origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _rp_hash(self, rp_id: str | None) -> bytes:
        return hashlib.sha256((rp_id or self.rp_id).encode()).digest()

    def register(self, options: dict, *, origin: str | None = None, uv: bool = True,
                 rp_id: str | None = None) -> dict:
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"],
                             "origin": origin or self.origin, "crossOrigin": False}).encode()
        flags = 0x01 | (0x04 if uv else 0) | 0x40
        auth = (self._rp_hash(rp_id) + bytes([flags]) + struct.pack(">I", self.count) + b"\x00" * 16
                + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose())
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "attestationObject": b64u(att)}}

    def get(self, options: dict, *, origin: str | None = None, uv: bool = True, count: int | None = None,
            tamper: bool = False, challenge: str | None = None) -> dict:
        self.count = self.count + 1 if count is None else count
        client = json.dumps({"type": "webauthn.get", "challenge": challenge or options["challenge"],
                             "origin": origin or self.origin, "crossOrigin": False}).encode()
        flags = 0x01 | (0x04 if uv else 0)
        auth = self._rp_hash(None) + bytes([flags]) + struct.pack(">I", self.count)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper:
            sig = sig[:-2] + bytes([sig[-2] ^ 0x01]) + sig[-1:]
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "authenticatorData": b64u(auth),
                             "signature": b64u(sig), "userHandle": None}}
