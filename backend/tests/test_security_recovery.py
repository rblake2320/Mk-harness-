"""Encrypted recovery inputs fail closed before any recovery mutation."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models import Base, Tenant, User, AuthSession
from app.security import hash_password
from app.tools import security_ledger as ledger
from app.tools.privacy_ledger import export_ledger
from app.tools.security_restore import restore


def archive():
    key = X25519PrivateKey.generate()
    cutoff = datetime.now(timezone.utc)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            tenant = Tenant(name="Synthetic encryption fixture")
            db.add(tenant); db.flush()
            user = User(tenant_id=tenant.id,email="admin@example.com",password_hash=hash_password("SyntheticPassword123!"))
            db.add(user); db.flush()
            db.add(AuthSession(tenant_id=tenant.id,user_id=user.id,refresh_digest="0"*64,
                expires_at=datetime.now(timezone.utc)+timedelta(hours=1)))
            db.commit()
            privacy = export_ledger(db)
            raw = ledger.export_encrypted(db, key.public_key().public_bytes_raw().hex(), ledger.sha256(privacy))
    finally: engine.dispose()
    return key, cutoff, privacy, raw


def test_security_archive_roundtrip_never_exposes_credentials():
    key, cutoff, privacy, raw = archive()
    assert b"admin@example.com" not in raw and b"argon2" not in raw
    checked = ledger.load_encrypted(raw, ledger.sha256(raw), cutoff,
        key.private_bytes_raw().hex(), ledger.sha256(privacy))
    assert checked.value["users"][0]["email"] == "admin@example.com"
    assert checked.value["users"][0]["password_hash"].startswith("$argon2id$")
    assert "password_hash" not in repr(checked)
    with pytest.raises(ValueError, match="Authenticated"):
        restore(None, checked.value, privacy, cutoff, "a"*32, apply=True)
    forged = ledger.AuthenticatedSnapshot(checked.value, checked.digest, checked.privacy_digest)
    with pytest.raises(ValueError, match="Authenticated"):
        restore(None, forged, privacy, cutoff, "a"*32, apply=True)


@pytest.mark.parametrize("attack", ["digest", "privacy", "key", "ciphertext", "nonce", "ephemeral",
    "schema", "format", "unknown", "duplicate", "future", "stale", "oversized"])
def test_encrypted_recovery_tampering_is_rejected(monkeypatch, attack):
    key, cutoff, privacy, raw = archive()
    value = json.loads(raw)
    digest = ledger.sha256(raw)
    private = key.private_bytes_raw().hex()
    privacy_digest = ledger.sha256(privacy)
    if attack == "digest": digest = "0"*64
    elif attack == "privacy": privacy_digest = "0"*64
    elif attack == "key": private = X25519PrivateKey.generate().private_bytes_raw().hex()
    elif attack == "stale": cutoff = datetime.now(timezone.utc)+timedelta(seconds=1)
    elif attack == "oversized": monkeypatch.setattr(ledger, "MAX_ENVELOPE", 1)
    else:
        if attack == "ciphertext": value["ciphertext"] = "A"+value["ciphertext"][1:]
        elif attack == "nonce": value["nonce"] = "0"*24
        elif attack == "ephemeral": value["ephemeral_public_key"] = "0"*64
        elif attack == "schema": value["schema_sha256"] = "0"*64
        elif attack == "format": value["format"] = "mk-application-security-v0"
        elif attack == "unknown": value["bypass"] = True
        elif attack == "future": value["exported_at"] = (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
        raw = ledger.canonical(value)
        if attack == "duplicate": raw = raw[:-1]+b',"format":"mk-application-security-v1"}'
        digest = ledger.sha256(raw)
    with pytest.raises((ValueError, TypeError)):
        ledger.load_encrypted(raw, digest, cutoff, private, privacy_digest)


@pytest.mark.parametrize("attack", ["owner", "role", "argon", "argon_cost", "duplicate_user", "factor_owner",
    "recovery_digest", "session_owner", "unknown", "boolean_int", "future", "naive", "missing_tenant"])
def test_decrypted_security_records_are_closed_and_typed(attack):
    key, cutoff, privacy, raw = archive()
    checked = ledger.load_encrypted(raw, ledger.sha256(raw), cutoff, key.private_bytes_raw().hex(), ledger.sha256(privacy))
    value = checked.value
    user = value["users"][0]
    if attack == "owner": user["tenant_id"] = "0"*32
    elif attack == "role": user["role"] = "root"
    elif attack == "argon": user["password_hash"] = "plaintext"
    elif attack == "argon_cost": user["password_hash"] = user["password_hash"].replace("m=65536", "m=999999999")
    elif attack == "duplicate_user": value["users"].append(dict(user))
    elif attack == "unknown": user["bypass"] = True
    elif attack == "boolean_int": user["is_active"] = 1
    elif attack == "future": user["created_at"] = (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
    elif attack == "naive": user["created_at"] = datetime.now().isoformat()
    elif attack == "missing_tenant": value["tenants"] = []
    elif attack == "session_owner": value["sessions"][0]["user_id"] = "0"*32
    elif attack == "factor_owner":
        value["factors"] = [{"user_id":"0"*32,"tenant_id":user["tenant_id"],"secret_enc":None,
            "confirmed_at":None,"last_counter":-1,"failed_attempts":0,"locked_until":None}]
    elif attack == "recovery_digest":
        value["recovery_codes"] = [{"id":"1"*32,"user_id":user["id"],"tenant_id":user["tenant_id"],"digest":"x","consumed_at":None}]
    with pytest.raises(ValueError): ledger.validate_snapshot(value)
