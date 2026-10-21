"""Customer & permission foundation routes (WP03, rows F1–F9).

- destinations and preferences per customer
- consent events (evidence-bearing) that grant kernel permissions atomically
- suppression events mirrored into the kernel
- CSV import: preview → commit → rollback; never creates consent
- CSV export with formula escaping

The kernel remains the execution-time authority: every consent/suppression write
here is paired with the matching kernel call and the local row is committed only
if the kernel accepted it. Kernel unavailable → 503 and nothing is recorded.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..foundation import (
    CHANNELS, CONSENT_SOURCES, EVIDENCE_TYPES, PURPOSES, active_suppressions, add_destination,
    audit, csv_cell, destination_value, fingerprints_all, normalize, own_customer, preference_for,
    seal, utcnow, validate_timezone,
)
from ..kernel import KernelClient, KernelUnavailable, get_kernel_client
from ..kernel.assertions import roles_for
from ..models import (
    ConsentEvent, ContactPreference, Customer, CustomerDestination, ImportJob, ImportRow,
    SuppressionEvent, User,
)
from ..ratelimit import check_rate

router = APIRouter(tags=["foundation"])


def _mask(v: str) -> str:
    return ("•" * max(len(v) - 4, 0)) + v[-4:] if v else ""


def _session_id(request: Request) -> str:
    return "jwt:" + hashlib.sha256(request.headers.get("Authorization", "").encode()).hexdigest()[:24]


async def _kernel(client: KernelClient, user: User, request: Request, method: str, path: str, body=None):
    try:
        r = await client.call(method, path, user_id=user.id, tenant_id=user.tenant_id,
                              roles=roles_for(user.role), session_id=_session_id(request), json=body)
    except KernelUnavailable as e:
        raise HTTPException(503, {"code": e.code, "detail": e.detail})
    return r


# --------------------------------------------------------------------------- #
# Destinations & preferences
# --------------------------------------------------------------------------- #
class DestinationIn(BaseModel):
    channel: str = Field(pattern="^(sms|email)$")
    value: str = Field(min_length=3, max_length=255)
    label: str = Field(default="", max_length=40)
    is_primary: bool = True


@router.post("/customers/{cid}/destinations", status_code=201)
def add_customer_destination(cid: str, body: DestinationIn, user: User = Depends(check_rate),
                             db: Session = Depends(get_db)):
    c = own_customer(db, user.tenant_id, user.id, cid)
    d = add_destination(db, user.tenant_id, user.id, c, body.channel, body.value,
                        source="manual", label=body.label, is_primary=body.is_primary)
    db.commit()
    return {"id": d.id, "channel": d.channel, "value_masked": _mask(destination_value(d)),
            "fingerprint": d.fingerprint, "is_primary": d.is_primary}


@router.get("/customers/{cid}/destinations")
def list_destinations(cid: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    c = own_customer(db, user.tenant_id, user.id, cid)
    rows = db.scalars(select(CustomerDestination).where(
        CustomerDestination.customer_id == c.id, CustomerDestination.retired_at.is_(None)))
    out = []
    for d in rows:
        sup = active_suppressions(db, user.tenant_id, d.fingerprint, d.channel)
        out.append({"id": d.id, "channel": d.channel, "value_masked": _mask(destination_value(d)),
                    "fingerprint": d.fingerprint, "is_primary": d.is_primary, "source": d.source,
                    "suppressed": bool(sup)})
    return out


class PreferenceIn(BaseModel):
    timezone: str | None = None
    preferred_channel: str = Field(default="sms", pattern="^(sms|email)$")
    window_start_hour: int | None = Field(default=None, ge=0, le=23)
    window_end_hour: int | None = Field(default=None, ge=0, le=23)
    language: str = Field(default="en", max_length=8)


@router.put("/customers/{cid}/preferences")
def set_preferences(cid: str, body: PreferenceIn, user: User = Depends(check_rate),
                    db: Session = Depends(get_db)):
    c = own_customer(db, user.tenant_id, user.id, cid)
    tz = validate_timezone(body.timezone)
    pref = preference_for(db, c)
    aref = audit(db, user.tenant_id, user.id, "preference.set",
                 {"customer_id": c.id, "timezone": tz or "", "channel": body.preferred_channel})
    if not pref:
        pref = ContactPreference(tenant_id=user.tenant_id, customer_id=c.id)
        db.add(pref)
    else:
        pref.version += 1
    pref.timezone, pref.preferred_channel = tz, body.preferred_channel
    pref.window_start_hour, pref.window_end_hour = body.window_start_hour, body.window_end_hour
    pref.language, pref.audit_ref, pref.updated_at = body.language, aref, utcnow()
    db.commit()
    return {"customer_id": c.id, "timezone": pref.timezone, "preferred_channel": pref.preferred_channel,
            "dispatch_blocked_reason": None if pref.timezone else "TIMEZONE_UNKNOWN", "version": pref.version}


# --------------------------------------------------------------------------- #
# Consent (evidence-bearing) → kernel permission
# --------------------------------------------------------------------------- #
class ConsentIn(BaseModel):
    destination_id: str
    purposes: list[str] = Field(min_length=1, max_length=8)
    source: str
    evidence_type: str
    evidence_ref: str = Field(default="", max_length=256)
    evidence_text: str = Field(min_length=1, max_length=4000,
                               description="The exact wording the customer agreed to, or the message text; hashed, not stored in audit")
    effective_at: datetime | None = None
    expires_in_days: int = Field(default=365, ge=1, le=1825)


@router.post("/customers/{cid}/consent", status_code=201)
async def record_consent(cid: str, body: ConsentIn, request: Request, user: User = Depends(check_rate),
                         db: Session = Depends(get_db), client: KernelClient = Depends(get_kernel_client)):
    c = own_customer(db, user.tenant_id, user.id, cid)
    if body.source not in CONSENT_SOURCES or body.evidence_type not in EVIDENCE_TYPES:
        raise HTTPException(422, "unsupported consent source or evidence type")
    if body.source == "import" or body.evidence_type == "import":
        raise HTTPException(422, "import is never a source of consent")
    bad = [p for p in body.purposes if p not in PURPOSES]
    if bad:
        raise HTTPException(422, f"unknown purposes: {bad}")
    d = db.get(CustomerDestination, body.destination_id)
    if not d or d.customer_id != c.id or d.retired_at is not None:
        raise HTTPException(404, "Destination not found")
    if active_suppressions(db, user.tenant_id, d.fingerprint, d.channel):
        raise HTTPException(409, {"code": "SUPPRESSED",
                                  "detail": "destination is suppressed; lifting suppression is a separate, evidenced workflow"})
    effective = body.effective_at or utcnow()
    expires = effective + timedelta(days=body.expires_in_days)
    digest = "sha256:" + hashlib.sha256(body.evidence_text.encode()).hexdigest()
    aref = audit(db, user.tenant_id, user.id, "consent.record",
                 {"customer_id": c.id, "destination_fingerprint": d.fingerprint, "channel": d.channel,
                  "purposes": body.purposes, "source": body.source, "evidence_digest": digest})
    ev = ConsentEvent(tenant_id=user.tenant_id, customer_id=c.id, destination_id=d.id, channel=d.channel,
                      purposes_json=json.dumps(body.purposes), source=body.source,
                      evidence_type=body.evidence_type, evidence_ref=body.evidence_ref,
                      evidence_digest=digest, effective_at=effective, expires_at=expires,
                      created_by=user.id, audit_ref=aref)
    db.add(ev)
    db.flush()
    # Kernel grant — the execution-time authority. Fail → nothing recorded.
    r = await _kernel(client, user, request, "POST", f"/contacts/{uuid.UUID(c.id)}/permissions", {
        "channel": d.channel, "destination": destination_value(d), "scope": body.purposes, "source": body.source,
        "proof_digest": digest, "granted_at": effective.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z")})
    if r.status_code != 201:
        db.rollback()
        return JSONResponse(status_code=r.status_code, content=r.body)
    ev.kernel_permission_id = str(r.body.get("id", ""))
    db.commit()
    return {"id": ev.id, "status": ev.status, "channel": ev.channel, "purposes": body.purposes,
            "effective_at": ev.effective_at.isoformat(), "expires_at": ev.expires_at.isoformat(),
            "evidence_digest": digest, "kernel_permission_id": ev.kernel_permission_id}


class RevokeIn(BaseModel):
    reason: str = Field(min_length=1, max_length=120)


@router.post("/customers/{cid}/consent/{eid}/revoke")
async def revoke_consent(cid: str, eid: str, body: RevokeIn, request: Request, user: User = Depends(check_rate),
                         db: Session = Depends(get_db), client: KernelClient = Depends(get_kernel_client)):
    c = own_customer(db, user.tenant_id, user.id, cid)
    ev = db.get(ConsentEvent, eid)
    if not ev or ev.customer_id != c.id:
        raise HTTPException(404, "Consent event not found")
    if ev.status == "revoked":
        return {"id": ev.id, "status": "revoked", "revoked_at": ev.revoked_at.isoformat()}
    if ev.kernel_permission_id:
        r = await _kernel(client, user, request, "POST",
                          f"/contacts/{uuid.UUID(c.id)}/permissions/{ev.kernel_permission_id}/revoke")
        if r.status_code not in (200, 404):
            return JSONResponse(status_code=r.status_code, content=r.body)
    ev.status, ev.revoked_at, ev.revoked_reason, ev.version = "revoked", utcnow(), body.reason, ev.version + 1
    ev.audit_ref = audit(db, user.tenant_id, user.id, "consent.revoke",
                         {"customer_id": c.id, "consent_event_id": ev.id, "reason": body.reason})
    db.commit()
    return {"id": ev.id, "status": "revoked", "revoked_at": ev.revoked_at.isoformat()}


@router.get("/customers/{cid}/permissions")
def permission_view(cid: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    """Historical observation only (F4). Execution re-checks the kernel."""
    c = own_customer(db, user.tenant_id, user.id, cid)
    events = db.scalars(select(ConsentEvent).where(ConsentEvent.customer_id == c.id)
                        .order_by(ConsentEvent.created_at)).all()
    dests = db.scalars(select(CustomerDestination).where(
        CustomerDestination.customer_id == c.id, CustomerDestination.retired_at.is_(None))).all()
    sups = [s for d in dests for s in active_suppressions(db, user.tenant_id, d.fingerprint, None)]
    return {
        "observed_at": utcnow().isoformat(),
        "note": "historical observation; current permission and suppression are re-checked at execution",
        "consent_events": [{"id": e.id, "channel": e.channel, "purposes": json.loads(e.purposes_json),
                            "status": e.status, "source": e.source, "effective_at": e.effective_at.isoformat(),
                            "expires_at": e.expires_at.isoformat(), "revoked_at": e.revoked_at.isoformat() if e.revoked_at else None}
                           for e in events],
        "suppressions": [{"id": s.id, "channel": s.channel, "reason": s.reason, "source": s.source,
                          "created_at": s.created_at.isoformat()} for s in sups],
    }


# --------------------------------------------------------------------------- #
# Suppression (never-contact) — mirrored into the kernel
# --------------------------------------------------------------------------- #
class SuppressIn(BaseModel):
    customer_id: str | None = None
    destination_id: str | None = None
    channel: str | None = Field(default=None, pattern="^(sms|email)$")
    reason: str = Field(min_length=1, max_length=120)
    source: str = Field(pattern="^(consultant|sms_reply|provider|complaint)$")
    permanent: bool = True


@router.post("/suppressions", status_code=201)
async def add_suppression(body: SuppressIn, request: Request, user: User = Depends(check_rate),
                          db: Session = Depends(get_db), client: KernelClient = Depends(get_kernel_client)):
    if not body.destination_id:
        raise HTTPException(422, "destination_id required")
    d = db.get(CustomerDestination, body.destination_id)
    if not d or d.tenant_id != user.tenant_id:
        raise HTTPException(404, "Destination not found")
    c = own_customer(db, user.tenant_id, user.id, d.customer_id)
    # The channel is the destination's. A caller-supplied channel that differs would file the
    # fingerprint under the wrong channel (locally and in the kernel) and leave the real
    # destination contactable — refused, never reinterpreted.
    if body.channel is not None and body.channel != d.channel:
        raise HTTPException(422, {"code": "channel_mismatch",
                                  "detail": f"destination is {d.channel}; a suppression cannot be filed as {body.channel}"})
    channel = d.channel
    aref = audit(db, user.tenant_id, user.id, "suppression.add",
                 {"customer_id": c.id, "destination_fingerprint": d.fingerprint, "channel": channel,
                  "reason": body.reason, "source": body.source})
    ev = SuppressionEvent(tenant_id=user.tenant_id, customer_id=c.id, channel=channel, fingerprint=d.fingerprint,
                          reason=body.reason, source=body.source, permanent=body.permanent,
                          created_by=user.id, audit_ref=aref)
    db.add(ev)
    db.flush()
    r = await _kernel(client, user, request, "POST", "/suppressions", {
        "channel": channel, "destination": destination_value(d), "reason": body.reason,
        "permanent": body.permanent, "source": body.source})
    if r.status_code != 201:
        db.rollback()
        return JSONResponse(status_code=r.status_code, content=r.body)
    ev.kernel_suppression_id = str(r.body.get("id", ""))
    # Any active consent for this destination/channel is revoked locally too.
    for ce in db.scalars(select(ConsentEvent).where(ConsentEvent.destination_id == d.id,
                                                    ConsentEvent.status == "active")):
        ce.status, ce.revoked_at, ce.revoked_reason = "revoked", utcnow(), f"suppressed:{body.source}"
    db.commit()
    return {"id": ev.id, "fingerprint": ev.fingerprint, "channel": ev.channel,
            "kernel_suppression_id": ev.kernel_suppression_id}


# --------------------------------------------------------------------------- #
# CSV import: preview → commit → rollback. Never creates consent.
# --------------------------------------------------------------------------- #
ALLOWED_MAPPING_TARGETS = {"name", "phone", "email", "notes"}
FORBIDDEN_MAPPING_TARGETS = {"consent", "consented", "opt_in", "permission", "suppressed", "timezone"}


class ImportPreviewIn(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=80)
    filename: str = Field(default="upload.csv", max_length=200)
    csv_text: str = Field(min_length=1, max_length=2_000_000)
    mapping: dict[str, str] = Field(description="target field -> CSV column header")


def _rows(csv_text: str) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(csv_text))
    headers = reader.fieldnames or []
    return headers, [dict(r) for r in reader]


@router.post("/customers/import/preview", status_code=201)
def import_preview(body: ImportPreviewIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    bad = set(body.mapping) & FORBIDDEN_MAPPING_TARGETS
    if bad:
        raise HTTPException(422, f"import cannot set {sorted(bad)}: consent and suppression require evidence")
    unknown = set(body.mapping) - ALLOWED_MAPPING_TARGETS
    if unknown or "name" not in body.mapping:
        raise HTTPException(422, "mapping must map 'name' and only name/phone/email/notes")
    existing = db.scalar(select(ImportJob).where(ImportJob.tenant_id == user.tenant_id,
                                                 ImportJob.idempotency_key == body.idempotency_key))
    if existing:
        return _job_view(db, existing)
    headers, rows = _rows(body.csv_text)
    missing_cols = [col for col in body.mapping.values() if col not in headers]
    if missing_cols:
        raise HTTPException(422, f"mapped columns not in CSV: {missing_cols}")
    job = ImportJob(tenant_id=user.tenant_id, user_id=user.id, idempotency_key=body.idempotency_key,
                    source_filename=body.filename,
                    source_digest="sha256:" + hashlib.sha256(body.csv_text.encode()).hexdigest(),
                    mapping_json=json.dumps(body.mapping, sort_keys=True), row_count=len(rows))
    db.add(job)
    db.flush()
    # Existing fingerprints for this consultant → duplicates.
    # Fingerprints are channel-keyed, so one set covers both sms and email destinations.
    known_fps = {fp for (fp,) in db.execute(
        select(CustomerDestination.fingerprint).join(Customer, Customer.id == CustomerDestination.customer_id)
        .where(Customer.user_id == user.id, CustomerDestination.retired_at.is_(None)))}
    seen_in_file: set[str] = set()
    for i, r in enumerate(rows):
        name = (r.get(body.mapping["name"]) or "").strip()
        phone_raw = (r.get(body.mapping["phone"]) or "").strip() if "phone" in body.mapping else ""
        email_raw = (r.get(body.mapping["email"]) or "").strip() if "email" in body.mapping else ""
        notes_raw = (r.get(body.mapping["notes"]) or "").strip() if "notes" in body.mapping else ""
        row = ImportRow(tenant_id=user.tenant_id, job_id=job.id, row_index=i, name=name[:120], status="create",
                        notes=notes_raw[:4000])
        try:
            if not name:
                raise HTTPException(422, "name is required")
            if phone_raw:
                norm = normalize("sms", phone_raw)
                fps = fingerprints_all(user.tenant_id, "sms", norm)
                fp = fps[0]
                row.phone_enc, row.phone_fingerprint = seal(user.tenant_id, "destination", norm), fp
                if known_fps.intersection(fps) or fp in seen_in_file:
                    row.status = "duplicate"
                seen_in_file.add(fp)
            if email_raw:
                enorm = normalize("email", email_raw)
                efps = fingerprints_all(user.tenant_id, "email", enorm)
                efp = efps[0]
                row.email_enc, row.email_fingerprint = seal(user.tenant_id, "destination", enorm), efp
                if known_fps.intersection(efps) or efp in seen_in_file:
                    row.status = "duplicate"
                seen_in_file.add(efp)
            if not phone_raw and not email_raw:
                raise HTTPException(422, "a phone or email is required")
        except HTTPException as e:
            row.status, row.error = "error", str(e.detail)[:200]
        db.add(row)
    db.flush()
    job.duplicate_count = sum(1 for _ in db.scalars(select(ImportRow).where(ImportRow.job_id == job.id, ImportRow.status == "duplicate")))
    job.error_count = sum(1 for _ in db.scalars(select(ImportRow).where(ImportRow.job_id == job.id, ImportRow.status == "error")))
    job.audit_ref = audit(db, user.tenant_id, user.id, "import.preview",
                          {"job_id": job.id, "rows": job.row_count, "duplicates": job.duplicate_count,
                           "errors": job.error_count, "source_digest": job.source_digest})
    db.commit()
    return _job_view(db, job)


def _job_view(db: Session, job: ImportJob) -> dict:
    rows = db.scalars(select(ImportRow).where(ImportRow.job_id == job.id).order_by(ImportRow.row_index)).all()
    return {
        "job_id": job.id, "status": job.status, "row_count": job.row_count,
        "will_create": sum(1 for r in rows if r.status == "create"),
        "duplicates": job.duplicate_count, "errors": job.error_count,
        "created_count": job.created_count, "source_digest": job.source_digest,
        "consent_note": "Imported contacts have NO outreach permission until consent with evidence is recorded.",
        "rows": [{"row": r.row_index, "status": r.status, "error": r.error, "name": r.name,
                  "customer_id": r.customer_id} for r in rows],
    }


def _own_job(db: Session, user: User, job_id: str) -> ImportJob:
    job = db.get(ImportJob, job_id)
    if not job or job.tenant_id != user.tenant_id or job.user_id != user.id:
        raise HTTPException(404, "Import job not found")
    return job


@router.get("/customers/import/{job_id}")
def import_status(job_id: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    return _job_view(db, _own_job(db, user, job_id))


@router.post("/customers/import/{job_id}/commit")
def import_commit(job_id: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    job = _own_job(db, user, job_id)
    if job.status == "committed":
        return _job_view(db, job)           # idempotent
    if job.status != "preview":
        raise HTTPException(409, f"job is {job.status}")
    created = 0
    for r in db.scalars(select(ImportRow).where(ImportRow.job_id == job.id, ImportRow.status == "create")
                        .order_by(ImportRow.row_index)):
        c = Customer(tenant_id=user.tenant_id, user_id=user.id, name=r.name, notes=r.notes or "")
        db.add(c)
        db.flush()
        if r.phone_fingerprint:
            from ..foundation import unseal
            add_destination(db, user.tenant_id, user.id, c, "sms",
                            unseal(user.tenant_id, "destination", r.phone_enc),
                            source="import", source_ref=job.id)
        if r.email_enc:
            from ..foundation import unseal
            add_destination(db, user.tenant_id, user.id, c, "email",
                            unseal(user.tenant_id, "destination", r.email_enc),
                            source="import", source_ref=job.id)
        r.customer_id = c.id
        created += 1
    job.status, job.created_count, job.committed_at = "committed", created, utcnow()
    job.version += 1
    job.audit_ref = audit(db, user.tenant_id, user.id, "import.commit", {"job_id": job.id, "created": created})
    db.commit()
    return _job_view(db, job)


@router.post("/customers/import/{job_id}/rollback")
def import_rollback(job_id: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    """Remove customers this import created that nothing else references (F5)."""
    job = _own_job(db, user, job_id)
    if job.status != "committed":
        raise HTTPException(409, f"job is {job.status}")
    removed, kept = 0, []
    for r in db.scalars(select(ImportRow).where(ImportRow.job_id == job.id, ImportRow.customer_id.is_not(None))):
        c = db.get(Customer, r.customer_id)
        if not c:
            continue
        referenced = db.scalar(select(ConsentEvent.id).where(ConsentEvent.customer_id == c.id).limit(1)) \
            or db.scalar(select(SuppressionEvent.id).where(SuppressionEvent.customer_id == c.id).limit(1))
        if referenced:
            kept.append(c.id)
            continue
        for d in db.scalars(select(CustomerDestination).where(CustomerDestination.customer_id == c.id)):
            db.delete(d)
        pref = preference_for(db, c)
        if pref:
            db.delete(pref)
        db.delete(c)
        r.customer_id = None
        removed += 1
    job.status, job.rolled_back_at, job.version = "rolled_back", utcnow(), job.version + 1
    job.audit_ref = audit(db, user.tenant_id, user.id, "import.rollback",
                          {"job_id": job.id, "removed": removed, "kept_referenced": kept})
    db.commit()
    return {"job_id": job.id, "status": job.status, "removed": removed, "kept_referenced": kept}


@router.get("/customers/export.csv", response_class=PlainTextResponse)
def export_csv(user: User = Depends(check_rate), db: Session = Depends(get_db)):
    """Formula-escaped export (F5). Destinations are masked; raw values never leave in bulk."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "phone_masked", "email_masked", "notes", "created_at"])
    for c in db.scalars(select(Customer).where(Customer.user_id == user.id).order_by(Customer.name)):
        phone = email = ""
        for d in db.scalars(select(CustomerDestination).where(CustomerDestination.customer_id == c.id,
                                                              CustomerDestination.retired_at.is_(None))):
            if d.channel == "sms" and d.is_primary:
                phone = _mask(destination_value(d))
            if d.channel == "email" and d.is_primary:
                email = _mask(destination_value(d))
        w.writerow([csv_cell(c.name), phone, email, csv_cell(c.notes), c.created_at.isoformat()])
    audit(db, user.tenant_id, user.id, "customers.export", {"format": "csv"})
    db.commit()
    return buf.getvalue()
