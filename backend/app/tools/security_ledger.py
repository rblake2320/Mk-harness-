"""Encrypted, independently pinned account-security snapshot (not a public ledger).

The public recipient key is sufficient for export. Only the separately held
private recovery key can open it. A digest from independent custody is mandatory:
encryption to a public key by itself does not authenticate the exporter.
"""
import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select

from ..models import (Tenant, User, AuthFactor, AuthRecoveryCode, AuthSession,
                      AuthRevocation, RecoveredSessionRevocation)
from ..database_policy import migration_files

FORMAT = "mk-application-security-v1"
DOMAIN = b"mk-application-security-recovery-v1"
MAX_PLAIN = 64 * 1024 * 1024
MAX_ENVELOPE = 96 * 1024 * 1024
_AUTHENTICATED = object()
GROUPS = {
    "tenants": (Tenant, ("id","name","key_policy","brand","created_at")),
    "users": (User, ("id","tenant_id","email","password_hash","display_name","role","is_active",
                     "referral_code","referred_by","created_at")),
    "factors": (AuthFactor, ("user_id","tenant_id","secret_enc","confirmed_at","last_counter","failed_attempts","locked_until")),
    "recovery_codes": (AuthRecoveryCode, ("id","user_id","tenant_id","digest","consumed_at")),
}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def strict_object(pairs):
    value=dict(pairs)
    if len(value)!=len(pairs): raise ValueError("Duplicate recovery field")
    return value


def stamp(value):
    if isinstance(value,str): value=datetime.fromisoformat(value.replace("Z","+00:00"))
    if not isinstance(value,datetime) or value.tzinfo is None: raise ValueError("Recovery time requires timezone")
    return value.astimezone(timezone.utc)


def encoded(value):
    if isinstance(value,datetime):
        return stamp(value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return value


def hex_value(value,size=64):
    return isinstance(value,str) and re.fullmatch(r"[0-9a-f]{"+str(size)+"}",value) is not None


def key_bytes(value):
    if not hex_value(value): raise ValueError("Recovery key must be 32-byte lowercase hex")
    return bytes.fromhex(value)


def schema_digest():
    return sha256(canonical({p.name:sha256(p.read_bytes()) for p in migration_files()}))


def derive(private,public):
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=DOMAIN).derive(private.exchange(public))


def snapshot(db):
    result={"format":FORMAT}
    for group,(model,names) in GROUPS.items():
        result[group]=[{name:encoded(getattr(row,name)) for name in names}
            for row in db.scalars(select(model).order_by(*model.__table__.primary_key.columns))]
    sessions={}
    for model in (AuthSession,AuthRevocation,RecoveredSessionRevocation):
        for row in db.scalars(select(model)):
            sid=row.id if model is AuthSession else row.session_id
            identity={"id":sid,"tenant_id":row.tenant_id,"user_id":row.user_id}
            if sid in sessions and sessions[sid]!=identity: raise ValueError("Conflicting session recovery identity")
            sessions[sid]=identity
    result["sessions"]=[sessions[key] for key in sorted(sessions)]
    result["exported_at"]=datetime.now(timezone.utc).isoformat()
    validate_snapshot(result)
    return result


def validate_snapshot(value):
    if not isinstance(value,dict) or set(value)!={"format","exported_at","sessions",*GROUPS} or value["format"]!=FORMAT:
        raise ValueError("Invalid security snapshot fields")
    exported=stamp(value["exported_at"])
    for group,(model,names) in GROUPS.items():
        rows=value[group]
        if not isinstance(rows,list): raise ValueError("Invalid security snapshot collection")
        seen=set()
        for row in rows:
            if not isinstance(row,dict) or set(row)!=set(names): raise ValueError("Invalid security record fields")
            identifier=row["user_id"] if group=="factors" else row["id"]
            if not hex_value(identifier,32) or identifier in seen: raise ValueError("Invalid or duplicate security identity")
            seen.add(identifier)
            for name in names:
                column=model.__table__.columns[name]
                item=row[name]
                if item is None:
                    if not column.nullable: raise ValueError("Missing security field")
                    continue
                kind=column.type.python_type
                if kind is datetime:
                    parsed=stamp(item)
                    latest=exported+timedelta(minutes=15) if name=="locked_until" else exported
                    if parsed>latest: raise ValueError("Future security record time")
                elif type(item) is not kind: raise ValueError("Invalid security field type")
                if isinstance(item,str):
                    maximum=getattr(column.type,"length",None) or 4096
                    if len(item)>maximum: raise ValueError("Oversized security field")
                    if name in {"id","tenant_id","user_id","referred_by"} and not hex_value(item,32):
                        raise ValueError("Invalid security identity")
            if group=="tenants" and row["key_policy"] not in {"central","byo","both"}: raise ValueError("Invalid key policy")
            if group=="users":
                if row["role"] not in {"admin","manager","consultant","auditor"}: raise ValueError("Invalid account role")
                if row["is_active"]:
                    from argon2 import extract_parameters, Type
                    try: parameters=extract_parameters(row["password_hash"])
                    except Exception: raise ValueError("Invalid active password verifier") from None
                    if parameters.type!=Type.ID or not 1<=parameters.time_cost<=10 or not 8192<=parameters.memory_cost<=524288 or not 1<=parameters.parallelism<=16:
                        raise ValueError("Unsupported password verifier parameters")
            if group=="factors" and (row["last_counter"] < -1 or row["failed_attempts"] < 0):
                raise ValueError("Invalid MFA replay state")
            if group=="recovery_codes" and not hex_value(row["digest"]): raise ValueError("Invalid recovery code digest")
    tenants={r["id"]:r for r in value["tenants"]}
    users={r["id"]:r for r in value["users"]}
    emails=set(); referrals=set()
    for user in users.values():
        if user["tenant_id"] not in tenants or user["email"] in emails: raise ValueError("Invalid account ownership or email collision")
        emails.add(user["email"])
        if user["referred_by"] is not None and user["referred_by"] not in users: raise ValueError("Missing referral identity")
        if user["referral_code"] is not None:
            if user["referral_code"] in referrals: raise ValueError("Duplicate referral identity")
            referrals.add(user["referral_code"])
    for group in ("factors","recovery_codes","sessions"):
        if not isinstance(value[group],list): raise ValueError("Invalid account security collection")
        seen=set()
        for row in value[group]:
            if group=="sessions":
                if not isinstance(row,dict) or set(row)!={"id","tenant_id","user_id"} or not all(hex_value(v,32) for v in row.values()):
                    raise ValueError("Invalid session recovery identity")
                if row["id"] in seen: raise ValueError("Duplicate session recovery identity")
                seen.add(row["id"])
            user=users.get(row["user_id"])
            if not user or user["tenant_id"]!=row["tenant_id"]: raise ValueError("Security record ownership mismatch")
    return value


@dataclass(frozen=True)
class AuthenticatedSnapshot:
    value: dict = field(repr=False)
    digest: str
    privacy_digest: str
    authentication: object = field(repr=False,default=None)


def export_encrypted(db,recipient_hex,privacy_sha256):
    if not hex_value(privacy_sha256): raise ValueError("Invalid privacy binding")
    value=snapshot(db)
    clear=canonical(value)
    if not 0<len(clear)<=MAX_PLAIN: raise ValueError("Security snapshot exceeds size limit")
    recipient=X25519PublicKey.from_public_bytes(key_bytes(recipient_hex))
    ephemeral=X25519PrivateKey.generate()
    header={"format":FORMAT,"exported_at":value["exported_at"],"schema_sha256":schema_digest(),
        "privacy_sha256":privacy_sha256,"recipient_sha256":sha256(recipient.public_bytes_raw()),
        "ephemeral_public_key":ephemeral.public_key().public_bytes_raw().hex(),"nonce":os.urandom(12).hex()}
    ciphertext=AESGCM(derive(ephemeral,recipient)).encrypt(bytes.fromhex(header["nonce"]),clear,canonical(header))
    return canonical({**header,"ciphertext":base64.b64encode(ciphertext).decode("ascii")})


def load_encrypted(raw,expected_sha256,not_before,private_hex,privacy_sha256,*,now=None):
    now=stamp(now or datetime.now(timezone.utc)); not_before=stamp(not_before)
    if len(raw)>MAX_ENVELOPE or not hex_value(expected_sha256) or not hmac.compare_digest(sha256(raw),expected_sha256):
        raise ValueError("Security snapshot digest or size mismatch")
    envelope=json.loads(raw,object_pairs_hook=strict_object)
    if not isinstance(envelope,dict) or set(envelope)!={"format","exported_at","schema_sha256","privacy_sha256","recipient_sha256","ephemeral_public_key","nonce","ciphertext"}:
        raise ValueError("Invalid encrypted recovery fields")
    exported=stamp(envelope["exported_at"])
    if envelope["format"]!=FORMAT or envelope["schema_sha256"]!=schema_digest() or not not_before<=exported<=now:
        raise ValueError("Security snapshot schema or freshness mismatch")
    if not hex_value(privacy_sha256) or envelope["privacy_sha256"]!=privacy_sha256:
        raise ValueError("Security snapshot erasure binding mismatch")
    private=X25519PrivateKey.from_private_bytes(key_bytes(private_hex))
    if sha256(private.public_key().public_bytes_raw())!=envelope["recipient_sha256"]:
        raise ValueError("Wrong security recovery recipient")
    if not hex_value(envelope["nonce"],24): raise ValueError("Invalid recovery nonce")
    ephemeral=X25519PublicKey.from_public_bytes(key_bytes(envelope["ephemeral_public_key"]))
    cipher=base64.b64decode(envelope["ciphertext"],validate=True)
    if not 16<len(cipher)<=MAX_PLAIN+16: raise ValueError("Invalid recovery ciphertext size")
    header={k:v for k,v in envelope.items() if k!="ciphertext"}
    try: clear=AESGCM(derive(private,ephemeral)).decrypt(bytes.fromhex(header["nonce"]),cipher,canonical(header))
    except Exception: raise ValueError("Security recovery authentication failed") from None
    value=validate_snapshot(json.loads(clear,object_pairs_hook=strict_object))
    if value["exported_at"]!=envelope["exported_at"]: raise ValueError("Security recovery time binding mismatch")
    return AuthenticatedSnapshot(value,expected_sha256,privacy_sha256,_AUTHENTICATED)
