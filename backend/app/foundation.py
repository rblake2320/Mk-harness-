"""Customer & permission foundation helpers (WP03).

Destinations are normalized exactly as the kernel does (rust/crates/mk-api/src/
routes/mod.rs::normalize_destination) and fingerprinted with the same HMAC so a
suppression recorded on either side matches the other:

    fingerprint = HMAC-SHA256(master_key, f"{tenant_uuid}|{channel}|{normalized}")

Raw destination values are stored AES-GCM encrypted with AAD bound to the tenant.
Nothing in this module writes consent: consent is created only by routes that
require evidence, never by import.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
import zoneinfo
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .crypto import seal_secret, unseal_secret
from .models import AuditLog, ContactPreference, Customer, CustomerDestination, SuppressionEvent

E164 = re.compile(r"^\+[1-9][0-9]{6,14}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CHANNELS = ("sms", "email")
PURPOSES = ("customer_requested_follow_up", "order_status", "appointment", "reorder_reminder")
CONSENT_SOURCES = ("web_form", "verbal_confirmed", "inbound_message", "paper_form")
EVIDENCE_TYPES = ("form_submission", "message", "signed_document", "consultant_attestation")


def tenant_uuid(tenant_id: str) -> str:
    return str(uuid.UUID(tenant_id))


def normalize(channel: str, raw: str) -> str:
    """Mirror of the kernel normalizer. Raises 422 on an unusable value."""
    if channel == "sms":
        digits = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
        # Accept US 10-digit and 1+10-digit input; store E.164.
        if digits and not digits.startswith("+"):
            if len(digits) == 10:
                digits = "+1" + digits
            elif len(digits) == 11 and digits.startswith("1"):
                digits = "+" + digits
        if not E164.match(digits):
            raise HTTPException(422, "phone must be a valid E.164 number")
        return digits
    if channel == "email":
        v = raw.strip().lower()
        if not EMAIL.match(v):
            raise HTTPException(422, "email is not valid")
        return v
    raise HTTPException(422, "unsupported channel")


def fingerprint(tenant_id: str, channel: str, normalized: str) -> str:
    """Fingerprint under the CURRENT key (first of FINGERPRINT_KEYS; default the master key)."""
    return fingerprints_all(tenant_id, channel, normalized)[0]


def fingerprints_all(tenant_id: str, channel: str, normalized: str) -> list[str]:
    """Fingerprints under every configured key, current first. Lookups match any of
    them, so rows written before a key rotation keep matching until re-keyed
    (`python -m app.tools.refingerprint`)."""
    msg = f"{tenant_uuid(tenant_id)}|{channel}|{normalized}".encode()
    return [hmac.new(key, msg, hashlib.sha256).hexdigest() for _, key in get_settings().fingerprint_key_list]


def _aad(tenant_id: str, kind: str) -> str:
    return f"mk-foundation:{tenant_id}:{kind}"


def seal(tenant_id: str, kind: str, plaintext: str) -> str:
    return seal_secret(plaintext, _aad(tenant_id, kind))


def unseal(tenant_id: str, kind: str, ciphertext: str) -> str:
    return unseal_secret(ciphertext, _aad(tenant_id, kind))


def audit(db: Session, tenant_id: str, user_id: str, action: str, detail: dict) -> str:
    """Attribution record for every permission-relevant change (F8). Detail must not
    carry raw destinations or message text; callers pass fingerprints and ids."""
    forbidden = {"phone", "email", "to", "destination", "text", "rendered_text"}
    if forbidden & set(detail):
        raise RuntimeError("audit detail must not carry raw destinations or text")
    row = AuditLog(tenant_id=tenant_id, user_id=user_id, action=action,
                   detail=json.dumps(detail, sort_keys=True, separators=(",", ":")))
    db.add(row)
    db.flush()
    return row.id


def own_customer(db: Session, tenant_id: str, user_id: str, cid: str) -> Customer:
    c = db.get(Customer, cid)
    if not c or c.tenant_id != tenant_id or c.user_id != user_id:
        raise HTTPException(404, "Customer not found")
    return c


def add_destination(db: Session, tenant_id: str, user_id: str, customer: Customer, channel: str,
                    raw: str, *, source: str, source_ref: str = "", label: str = "",
                    is_primary: bool = True) -> CustomerDestination:
    norm = normalize(channel, raw)
    fps = fingerprints_all(tenant_id, channel, norm)
    fp = fps[0]
    existing = db.scalar(select(CustomerDestination).where(
        CustomerDestination.tenant_id == tenant_id,
        CustomerDestination.customer_id == customer.id,
        CustomerDestination.channel == channel,
        CustomerDestination.fingerprint.in_(fps),
        CustomerDestination.retired_at.is_(None)))
    if existing:
        return existing
    if is_primary:
        for d in db.scalars(select(CustomerDestination).where(
                CustomerDestination.customer_id == customer.id,
                CustomerDestination.channel == channel,
                CustomerDestination.is_primary.is_(True))):
            d.is_primary = False
    aref = audit(db, tenant_id, user_id, "destination.add",
                 {"customer_id": customer.id, "channel": channel, "fingerprint": fp, "source": source})
    dest = CustomerDestination(tenant_id=tenant_id, customer_id=customer.id, channel=channel,
                               value_enc=seal(tenant_id, "destination", norm), fingerprint=fp,
                               label=label, is_primary=is_primary, source=source,
                               source_ref=source_ref, audit_ref=aref)
    db.add(dest)
    db.flush()
    return dest


def destination_value(dest: CustomerDestination) -> str:
    return unseal(dest.tenant_id, "destination", dest.value_enc)


def active_suppressions(db: Session, tenant_id: str, fp: str, channel: str | None) -> list[SuppressionEvent]:
    rows = db.scalars(select(SuppressionEvent).where(
        SuppressionEvent.tenant_id == tenant_id,
        SuppressionEvent.fingerprint == fp,
        SuppressionEvent.lifted_at.is_(None)))
    return [s for s in rows if s.channel is None or channel is None or s.channel == channel]


def validate_timezone(tz: str | None) -> str | None:
    if tz is None or tz == "":
        return None
    try:
        zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise HTTPException(422, "timezone must be an IANA zone name")
    return tz


def preference_for(db: Session, customer: Customer) -> ContactPreference | None:
    return db.scalar(select(ContactPreference).where(ContactPreference.customer_id == customer.id))


def require_dispatch_timezone(db: Session, customer: Customer) -> str:
    """F9: automated dispatch needs a known destination timezone."""
    pref = preference_for(db, customer)
    if not pref or not pref.timezone:
        raise HTTPException(422, {"code": "TIMEZONE_UNKNOWN",
                                  "detail": "customer timezone must be set before automated outreach"})
    return pref.timezone


def preference_for_tz(db: Session, customer: Customer) -> str | None:
    pref = preference_for(db, customer)
    return pref.timezone if pref and pref.timezone else None


def csv_cell(value: str) -> str:
    """Spreadsheet-formula escaping on export (F5)."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
