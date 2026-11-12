"""Subject erasure (contract S13) and its restore-safe ledger.

`erase_customer` removes or empties every content field the application holds for
one customer, in one transaction, and keeps only what the data map says must stay:

  kept, content-free   customer row (anchor: erased_at, empty fields), action links
                       (ids + digests), inbound application ids, audit rows
  kept, minimal legal  consent evidence (who / purpose / when / evidence digest — the
                       free-text evidence reference is cleared), suppression rows, the
                       fingerprints they need and — for an opted-out number only — its
                       sealed value, so key rotation can re-key the opt-out
  emptied              destinations (ciphertext; fingerprint tombstoned unless a
                       suppression needs it), preferences, commitment / draft /
                       exception / outcome text, import rows, skin analyses and the
                       skin profile, brief items (derived)

Nothing else holds customer content in the application: Redis carries only
rate-limit and sign-in-failure counters, exports are streamed and never stored,
and there is no search index outside these tables. The kernel's copies (action
payloads, inbound bodies) and provider-held copies are erased by the kernel; the
request is delivered from `erasure_requests` (outbox) and acknowledged there.

Restore safety: every request is appended to an append-only, hash-chained,
HMAC-sealed JSONL ledger stored OUTSIDE the database (ERASURE_LEDGER_PATH, its own
volume/bucket). After a database restore, `python -m app.tools.erasure replay`
re-applies every ledgered erasure before dispatch is re-enabled, so restored
content cannot reappear. The ledger is content-free: ids, times, digests only.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import get_settings
from .foundation import audit, utcnow
from .models import (
    ActionLink, BriefItem, Commitment, ConsentEvent, ConsentRecord, ContactPreference, Customer,
    CustomerDestination, DraftVersion, ErasureRequest, ExceptionRecord, ImportRow, Outcome,
    SkinAnalysis, SuppressionEvent,
)

ERASURE_DAYS = 30           # contract: requests completed within 30 days
GENESIS = "sha256:" + "0" * 64


class LegalHold(Exception):
    pass


# --------------------------------------------------------------------------- #
# Erasure
# --------------------------------------------------------------------------- #
def _apply(db: Session, tenant_id: str, customer_id: str) -> dict:
    """Idempotent content removal for one customer. Returns the kernel scope
    (fingerprints and action ids) the kernel must erase too."""
    c = db.get(Customer, customer_id)
    if c is None or c.tenant_id != tenant_id:
        return {"fingerprints": [], "action_ids": []}
    now = utcnow()
    suppressed = set(db.scalars(select(SuppressionEvent.fingerprint).where(
        SuppressionEvent.tenant_id == tenant_id)).all())
    fingerprints: list[str] = []
    for d in db.scalars(select(CustomerDestination).where(CustomerDestination.customer_id == c.id)):
        keep_for_opt_out = d.fingerprint in suppressed
        if not d.fingerprint.startswith("erased:"):
            fingerprints.append(d.fingerprint)
            if not keep_for_opt_out:
                d.fingerprint = f"erased:{d.id}"   # irreversible tombstone; nothing to look up
        if not keep_for_opt_out:
            d.value_enc = ""
        # An opted-out number keeps its SEALED value (never shown; no read path returns an
        # erased customer): fingerprint-key rotation must be able to re-key the opt-out,
        # or the old key's removal would let the number be contacted again. Same rule as
        # the kernel's suppressions.destination_sealed.
        d.label, d.source_ref, d.is_primary = "", "", False
        d.retired_at = d.retired_at or now
    for e in db.scalars(select(ConsentEvent).where(ConsentEvent.customer_id == c.id)):
        e.evidence_ref = ""                         # minimal legal record: digest, purpose, time stay
    db.execute(delete(ContactPreference).where(ContactPreference.customer_id == c.id))
    for k in db.scalars(select(Commitment).where(Commitment.customer_id == c.id)):
        k.commitment_text = ""
        if k.status in ("draft", "confirmed", "deferred"):
            k.status = "cancelled"
    db.execute(delete(BriefItem).where(BriefItem.customer_id == c.id))
    for v in db.scalars(select(DraftVersion).where(DraftVersion.customer_id == c.id)):
        v.text_enc, v.relationship_spans_json = "", "[]"
    for x in db.scalars(select(ExceptionRecord).where(ExceptionRecord.customer_id == c.id)):
        x.detail_enc = ""
        if x.state == "open":
            x.state, x.resolved_at = "dismissed", now
    for o in db.scalars(select(Outcome).where(Outcome.customer_id == c.id)):
        o.note_enc = ""
    for r in db.scalars(select(ImportRow).where(ImportRow.customer_id == c.id)):
        r.name, r.phone_enc, r.email_enc, r.notes = "", "", "", ""
        r.phone_fingerprint = r.email_fingerprint = ""
    db.execute(delete(SkinAnalysis).where(SkinAnalysis.customer_id == c.id))
    for cr in db.scalars(select(ConsentRecord).where(ConsentRecord.customer_id == c.id)):
        cr.revoked_at = cr.revoked_at or now
    c.name, c.phone, c.email, c.notes = "Erased customer", "", "", ""
    c.skin_undertone, c.fitzpatrick_type, c.skin_profile_json, c.skin_profile_at = "", None, "", None
    c.last_contact = None
    c.erased_at = c.erased_at or now
    action_ids = sorted(db.scalars(select(ActionLink.kernel_action_id).where(ActionLink.customer_id == c.id)).all())
    return {"fingerprints": sorted(set(fingerprints)), "action_ids": action_ids}


def erase_customer(db: Session, *, tenant_id: str, customer_id: str, requested_by: str,
                   legal_hold_reason: str = "") -> ErasureRequest:
    """Erase one customer now (app copies) and queue the kernel/provider part.
    The caller commits. A legal hold records the request but erases nothing."""
    now = utcnow()
    req = ErasureRequest(tenant_id=tenant_id, subject_type="customer", subject_id=customer_id,
                         requested_by=requested_by, requested_at=now, due_by=now + timedelta(days=ERASURE_DAYS),
                         legal_hold=bool(legal_hold_reason), legal_hold_reason=legal_hold_reason[:200])
    db.add(req)
    db.flush()
    if req.legal_hold:
        audit(db, tenant_id, requested_by, "erasure.legal_hold", {"request": req.id, "customer_id": customer_id})
        return req
    scope = _apply(db, tenant_id, customer_id)
    req.kernel_fingerprints_json = json.dumps(scope["fingerprints"])
    req.kernel_action_ids_json = json.dumps(scope["action_ids"])
    req.app_completed_at = utcnow()
    audit(db, tenant_id, requested_by, "erasure.app_completed",
          {"request": req.id, "customer_id": customer_id, "destinations": len(scope["fingerprints"]),
           "actions": len(scope["action_ids"])})
    req.ledger_seq = ledger_append({"request": req.id, "tenant_id": tenant_id, "subject_type": "customer",
                                    "subject_id": customer_id, "requested_at": now.isoformat()})
    return req


# --------------------------------------------------------------------------- #
# Kernel delivery (outbox)
# --------------------------------------------------------------------------- #
def deliver_to_kernel(db: Session, *, tenant_id: str | None = None, limit: int = 50) -> int:
    """Deliver pending kernel erasures. Returns how many the kernel acknowledged.
    Undelivered requests stay pending and are counted in readiness."""
    from .kernel.client import KernelUnavailable, get_kernel_client
    client = get_kernel_client()
    if not client.configured:
        return 0
    q = select(ErasureRequest).where(ErasureRequest.kernel_acknowledged_at.is_(None),
                                     ErasureRequest.app_completed_at.is_not(None),
                                     ErasureRequest.legal_hold.is_(False))
    if tenant_id:
        q = q.where(ErasureRequest.tenant_id == tenant_id)
    done = 0
    for req in db.scalars(q.order_by(ErasureRequest.requested_at).limit(limit)).all():
        from .foundation import tenant_uuid
        import uuid as _uuid
        actor = (tenant_uuid(req.requested_by) if len(req.requested_by) == 32
                 else str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"mk:system:{req.requested_by}")))
        req.kernel_attempts += 1
        try:
            r = client.call_sync("POST", "/erasures", user_id=actor,
                                 tenant_id=tenant_uuid(req.tenant_id), roles=["tenant_admin"],
                                 session_id=f"erasure:{req.id}",
                                 json={"request_ref": req.id,
                                       "destination_hashes": json.loads(req.kernel_fingerprints_json),
                                       "action_ids": json.loads(req.kernel_action_ids_json)})
        except KernelUnavailable as e:
            req.kernel_last_error = str(e)[:200]
            db.commit()
            break
        if r.status_code in (200, 201):
            req.kernel_acknowledged_at = utcnow()
            req.kernel_result_json = json.dumps(r.body or {}, sort_keys=True)[:4000]
            req.kernel_last_error = ""
            done += 1
        else:
            req.kernel_last_error = f"HTTP {r.status_code}"
        db.commit()
    return done


# --------------------------------------------------------------------------- #
# The separately stored ledger
# --------------------------------------------------------------------------- #
def _ledger_path() -> Path:
    return Path(get_settings().erasure_ledger_path)


def _ledger_key() -> bytes:
    st = get_settings()
    if st.erasure_ledger_key:
        return st.erasure_ledger_key.encode()
    # Development fallback, domain-separated from every other use of the master key.
    return hmac.new(st.master_key_bytes, b"mk-erasure-ledger-v1", hashlib.sha256).digest()


def _seal(prev: str, body: dict) -> tuple[str, str]:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256((prev + "\n" + canon).encode()).hexdigest()
    mac = hmac.new(_ledger_key(), digest.encode(), hashlib.sha256).hexdigest()
    return digest, mac


def ledger_append(body: dict) -> int:
    """Append one content-free entry. Cross-process safe (flock), crash safe (the
    line is written and fsynced in one call; a torn last line fails verification
    loudly instead of being silently skipped)."""
    path = _ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(os.dup(fd), "r", encoding="utf-8") as f:
            f.seek(0)
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        prev, seq = GENESIS, 0
        if lines:
            last = json.loads(lines[-1])
            prev, seq = last["digest"], last["seq"]
        entry = {"seq": seq + 1, "prev": prev, "body": body}
        entry["digest"], entry["mac"] = _seal(prev, {"seq": seq + 1, "body": body})
        os.write(fd, (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
        return seq + 1
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def ledger_entries(verify: bool = True) -> list[dict]:
    """All entries in order; raises ValueError naming the first broken line."""
    path = _ledger_path()
    if not path.exists():
        return []
    out, prev = [], GENESIS
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"erasure ledger line {i}: not JSON (torn write?)") from exc
        if verify:
            digest, mac = _seal(prev, {"seq": e.get("seq"), "body": e.get("body")})
            if e.get("prev") != prev or e.get("digest") != digest or e.get("seq") != len(out) + 1:
                raise ValueError(f"erasure ledger line {i}: chain broken")
            if not hmac.compare_digest(e.get("mac", ""), mac):
                raise ValueError(f"erasure ledger line {i}: seal does not verify")
        out.append(e)
        prev = e["digest"]
    return out


def replay(db: Session) -> dict:
    """Re-apply every ledgered erasure (after a restore). Idempotent. Re-creates the
    request row when the restored database predates it, and re-queues the kernel
    part so restored kernel copies are erased again too."""
    entries = ledger_entries(verify=True)
    reapplied = recreated = 0
    for e in entries:
        b = e["body"]
        if b.get("subject_type") != "customer":
            continue
        scope = _apply(db, b["tenant_id"], b["subject_id"])
        req = db.get(ErasureRequest, b["request"])
        if req is None:
            from datetime import datetime
            at = datetime.fromisoformat(b["requested_at"])
            req = ErasureRequest(id=b["request"], tenant_id=b["tenant_id"], subject_type="customer",
                                 subject_id=b["subject_id"], requested_by="erasure-replay", requested_at=at,
                                 due_by=at + timedelta(days=ERASURE_DAYS), ledger_seq=e["seq"])
            db.add(req)
            recreated += 1
        req.app_completed_at = req.app_completed_at or utcnow()
        req.kernel_fingerprints_json = json.dumps(sorted(set(json.loads(req.kernel_fingerprints_json or "[]"))
                                                         | set(scope["fingerprints"])))
        req.kernel_action_ids_json = json.dumps(sorted(set(json.loads(req.kernel_action_ids_json or "[]"))
                                                       | set(scope["action_ids"])))
        req.kernel_acknowledged_at = None           # the kernel may have been restored too
        reapplied += 1
    db.commit()
    return {"entries": len(entries), "reapplied": reapplied, "recreated_requests": recreated}
