"""Commitments and the daily brief (WP04, rows W1–W7, X1).

Rules enforced here, not in the UI:
* AI extraction creates *drafts only*. A consultant confirms customer, meaning and
  date/window before a commitment is actionable.
* Relative phrases ("next month") become explicit **windows**; the system never
  invents a date. Absolute dates are accepted from the extractor only when the date
  text appears in the source.
* Brief candidates come only from the five contract sources; each carries the rule
  that produced it and its source reference. Ranking is deterministic.
* Brief generation is idempotent: (tenant, dedupe_key) is unique.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import re
import zoneinfo
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .foundation import active_suppressions, audit, preference_for, utcnow
from .models import (
    BriefItem, Commitment, ConsentEvent, Customer, CustomerDestination, ExceptionRecord, Outcome,
)

KINDS = ("promise", "customer_request", "unanswered_question", "customer_date")
STATUSES = ("draft", "confirmed", "deferred", "resolved", "cancelled")
RELATIVE_WINDOWS = ("today", "tomorrow", "this_week", "next_week", "next_month", "unspecified")
OUTCOME_KINDS = ("resolved", "deferred", "opted_out", "no_response", "customer_reported_order",
                 "consultant_confirmed_order", "exception_open", "cancelled")

# Deterministic ranking categories (W3). Lower sorts first.
RANK_SAFETY = 0          # safety concerns / opt-outs requiring attention (open exceptions)
RANK_OVERDUE = 1         # overdue confirmed commitments
RANK_DUE_TODAY = 2       # due today
RANK_UNANSWERED = 3      # unanswered requests / questions
RANK_FUTURE = 4          # future scheduled work (window started, due later)


def aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes for DateTime(timezone=True); every value we write is
    UTC-aware, so naive values are interpreted as UTC. Postgres returns aware values."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def tz_of(db: Session, customer: Customer, fallback: str = "America/Chicago") -> zoneinfo.ZoneInfo:
    pref = preference_for(db, customer)
    try:
        return zoneinfo.ZoneInfo((pref.timezone if pref and pref.timezone else fallback))
    except Exception:  # noqa: BLE001
        return zoneinfo.ZoneInfo(fallback)


def window_for(phrase: str, now_local: datetime) -> tuple[datetime | None, datetime | None]:
    """Explicit window for a relative phrase, in the given local time. 'unspecified' → none."""
    d = now_local.date()
    tz = now_local.tzinfo
    def span(a: date, b: date):
        return (datetime.combine(a, time.min, tz), datetime.combine(b, time.max, tz))
    if phrase == "today":
        return span(d, d)
    if phrase == "tomorrow":
        return span(d + timedelta(days=1), d + timedelta(days=1))
    if phrase == "this_week":
        end = d + timedelta(days=6 - d.weekday())
        return span(d, end)
    if phrase == "next_week":
        start = d + timedelta(days=7 - d.weekday())
        return span(start, start + timedelta(days=6))
    if phrase == "next_month":
        y, m = (d.year + 1, 1) if d.month == 12 else (d.year, d.month + 1)
        return span(date(y, m, 1), date(y, m, calendar.monthrange(y, m)[1]))
    return (None, None)


_DATE_PATTERNS = [
    r"\b(\d{4}-\d{2}-\d{2})\b",
    r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2}\b",
    r"\b\d{1,2}/\d{1,2}(/\d{2,4})?\b",
]


def date_text_present(source_text: str, iso_date: str) -> bool:
    """An extractor may only assert an absolute date that the source actually states.
    Accepts ISO, 'Month D', or M/D forms that resolve to the same calendar date."""
    try:
        target = date.fromisoformat(iso_date)
    except ValueError:
        return False
    low = source_text.lower()
    if iso_date in low:
        return True
    month_names = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
    for m in re.finditer(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})\b", low):
        mon = month_names.index(m.group(1)[:3]) + 1
        if mon == target.month and int(m.group(2)) == target.day:
            return True
    for m in re.finditer(r"\b(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?\b", low):
        if int(m.group(1)) == target.month and int(m.group(2)) == target.day:
            return True
    return False


@dataclass
class ExtractedDraft:
    kind: str
    commitment_text: str
    relative_window: str          # one of RELATIVE_WINDOWS
    absolute_date: str | None     # ISO date, only if present in source
    evidence_quote: str           # verbatim span from the source


def parse_extractor_output(raw: str, source_text: str) -> list[ExtractedDraft]:
    """Strict validation of model JSON. Anything malformed is dropped, never repaired.
    Dates not present in the source are downgraded to the relative window or 'unspecified'."""
    try:
        data = json.loads(raw)
    except ValueError:
        raise HTTPException(502, "extractor returned non-JSON")
    items = data.get("commitments") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise HTTPException(502, "extractor output missing 'commitments' list")
    out: list[ExtractedDraft] = []
    for it in items[:20]:
        if not isinstance(it, dict):
            continue
        kind = it.get("kind")
        text = str(it.get("text", "")).strip()
        quote = str(it.get("evidence_quote", "")).strip()
        rel = it.get("relative_window", "unspecified")
        absolute = it.get("absolute_date")
        if kind not in KINDS or not text or len(text) > 500:
            continue
        # The quote must be a verbatim span of the source: it is the evidence.
        if not quote or quote.lower() not in source_text.lower():
            continue
        if rel not in RELATIVE_WINDOWS:
            rel = "unspecified"
        if absolute is not None and not (isinstance(absolute, str) and date_text_present(source_text, absolute)):
            absolute = None   # invented → dropped; the window (or 'unspecified') remains
        out.append(ExtractedDraft(kind, text, rel, absolute, quote))
    return out


EXTRACTOR_SYSTEM = (
    "You extract commitments from a consultant–customer conversation. Return ONLY a JSON object "
    '{"commitments":[{"kind":"promise|customer_request|unanswered_question|customer_date",'
    '"text":"<what was promised or asked, one sentence>",'
    '"relative_window":"today|tomorrow|this_week|next_week|next_month|unspecified",'
    '"absolute_date":"YYYY-MM-DD or null — ONLY if that exact date is written in the conversation",'
    '"evidence_quote":"<verbatim quote from the conversation>"}]}. '
    "Never invent dates. Never include product claims. If nothing qualifies, return {\"commitments\":[]}."
)


def create_draft(db: Session, *, tenant_id: str, user_id: str, customer: Customer, kind: str, text: str,
                 source_type: str, source_reference: str, source_version: str, evidence_text: str,
                 created_by: str, relative_window: str = "unspecified", absolute_date: str | None = None,
                 now: datetime | None = None) -> Commitment:
    if kind not in KINDS:
        raise HTTPException(422, "unknown commitment kind")
    tz = tz_of(db, customer)
    now_local = (now or utcnow()).astimezone(tz)
    due_at = None
    ws, we = (None, None)
    if absolute_date:
        d = date.fromisoformat(absolute_date)
        due_at = datetime.combine(d, time(9, 0), tz)
    else:
        ws, we = window_for(relative_window, now_local)
    digest = "sha256:" + hashlib.sha256(evidence_text.encode()).hexdigest()
    aref = audit(db, tenant_id, user_id, "commitment.draft",
                 {"customer_id": customer.id, "kind": kind, "source_type": source_type,
                  "source_reference": source_reference, "evidence_digest": digest, "created_by": created_by})
    c = Commitment(tenant_id=tenant_id, customer_id=customer.id, owner_user_id=user_id, kind=kind,
                   source_type=source_type, source_reference=source_reference, source_version=source_version,
                   source_evidence_reference=digest, commitment_text=text[:500], due_at=due_at,
                   due_window_start=ws, due_window_end=we, timezone=str(tz.key), status="draft",
                   created_by=created_by, audit_ref=aref)
    db.add(c)
    db.flush()
    return c


def confirm(db: Session, c: Commitment, *, user_id: str, text: str | None, due_at: datetime | None,
            relative_window: str | None, now: datetime | None = None) -> Commitment:
    """Consultant confirms customer, meaning and date/window (W1). A draft with only
    'unspecified' timing cannot be confirmed without a window or a date."""
    if c.status not in ("draft", "deferred"):
        raise HTTPException(409, f"commitment is {c.status}")
    tz = zoneinfo.ZoneInfo(c.timezone or "America/Chicago")
    if text:
        c.commitment_text = text[:500]
    if due_at is not None:
        c.due_at, c.due_window_start, c.due_window_end = due_at.astimezone(tz), None, None
    elif relative_window:
        if relative_window not in RELATIVE_WINDOWS or relative_window == "unspecified":
            raise HTTPException(422, "choose a window or a date")
        ws, we = window_for(relative_window, (now or utcnow()).astimezone(tz))
        c.due_at, c.due_window_start, c.due_window_end = None, ws, we
    if c.due_at is None and c.due_window_start is None:
        raise HTTPException(422, "a date or an explicit window is required to confirm")
    c.status, c.confirmed_by, c.confirmed_at, c.version = "confirmed", user_id, utcnow(), c.version + 1
    c.updated_at = utcnow()
    c.audit_ref = audit(db, c.tenant_id, user_id, "commitment.confirm",
                        {"commitment_id": c.id, "customer_id": c.customer_id,
                         "due_at": c.due_at.isoformat() if c.due_at else None,
                         "window": [c.due_window_start.isoformat() if c.due_window_start else None,
                                    c.due_window_end.isoformat() if c.due_window_end else None]})
    return c


def record_outcome(db: Session, *, tenant_id: str, user_id: str, customer_id: str, kind: str,
                   commitment: Commitment | None, action_link_id: str | None, note: str) -> Outcome:
    if kind not in OUTCOME_KINDS:
        raise HTTPException(422, "unknown outcome kind")
    from .foundation import seal
    aref = audit(db, tenant_id, user_id, "outcome.record",
                 {"customer_id": customer_id, "kind": kind, "commitment_id": commitment.id if commitment else None})
    o = Outcome(tenant_id=tenant_id, customer_id=customer_id, commitment_id=commitment.id if commitment else None,
                action_link_id=action_link_id, kind=kind, recorded_by=user_id,
                note_enc=seal(tenant_id, "outcome", note) if note else "", audit_ref=aref)
    db.add(o)
    if commitment is not None:
        if kind in ("resolved", "customer_reported_order", "consultant_confirmed_order"):
            commitment.status, commitment.resolution_reference = "resolved", f"outcome:{o.id or ''}"
        elif kind == "cancelled":
            commitment.status = "cancelled"
        elif kind == "deferred":
            commitment.status = "deferred"
        commitment.version += 1
        commitment.updated_at = utcnow()
    db.flush()
    return o


# --------------------------------------------------------------------------- #
# Daily brief
# --------------------------------------------------------------------------- #
def permission_snapshot(db: Session, tenant_id: str, customer: Customer) -> tuple[str, datetime]:
    """Historical observation for display (F4): active | suppressed | none."""
    dests = db.scalars(select(CustomerDestination).where(CustomerDestination.customer_id == customer.id,
                                                         CustomerDestination.retired_at.is_(None))).all()
    now = utcnow()
    for d in dests:
        if active_suppressions(db, tenant_id, d.fingerprint, None):
            return "suppressed", now
    active = db.scalar(select(ConsentEvent.id).where(ConsentEvent.customer_id == customer.id,
                                                     ConsentEvent.status == "active",
                                                     ConsentEvent.expires_at > now).limit(1))
    return ("active" if active else "none"), now


def generate_brief(db: Session, *, tenant_id: str, user_id: str, brief_date: date, now: datetime | None = None) -> list[BriefItem]:
    """Deterministic candidates for one consultant on one local day. Idempotent."""
    now = now or utcnow()
    created: list[BriefItem] = []

    def upsert(customer: Customer, rule: str, rank: int, source_type: str, source_ref: str,
               due_at: datetime | None, step: str) -> None:
        key = f"{brief_date.isoformat()}:{user_id}:{rule}:{source_type}:{source_ref}"
        if db.scalar(select(BriefItem.id).where(BriefItem.tenant_id == tenant_id, BriefItem.dedupe_key == key)):
            return
        pstate, pts = permission_snapshot(db, tenant_id, customer)
        aref = audit(db, tenant_id, user_id, "brief.item",
                     {"customer_id": customer.id, "rule": rule, "source_type": source_type, "source_reference": source_ref})
        item = BriefItem(tenant_id=tenant_id, user_id=user_id, customer_id=customer.id,
                         brief_date=brief_date.isoformat(), rule=rule, rank_category=rank,
                         source_type=source_type, source_reference=source_ref, due_at=due_at,
                         permission_state=pstate, permission_checked_at=pts, suggested_step=step,
                         dedupe_key=key, audit_ref=aref)
        db.add(item)
        created.append(item)

    # 1. Unresolved exceptions (safety / opt-out attention) — rank 0
    for ex in db.scalars(select(ExceptionRecord).where(ExceptionRecord.tenant_id == tenant_id,
                                                       ExceptionRecord.state == "open")):
        if not ex.customer_id:
            continue
        cust = db.get(Customer, ex.customer_id)
        if cust and cust.user_id == user_id:
            upsert(cust, "exception", RANK_SAFETY, "exception", ex.id, aware(ex.created_at),
                   "Review the exception before any outreach")

    # 2–5. Confirmed commitments by kind and timing
    for c in db.scalars(select(Commitment).where(Commitment.tenant_id == tenant_id,
                                                 Commitment.owner_user_id == user_id,
                                                 Commitment.status == "confirmed")):
        cust = db.get(Customer, c.customer_id)
        if not cust:
            continue
        tz = zoneinfo.ZoneInfo(c.timezone or "America/Chicago")
        day_start = datetime.combine(brief_date, time.min, tz)
        day_end = datetime.combine(brief_date, time.max, tz)
        due = aware(c.due_at or c.due_window_start)
        due_at = aware(c.due_at)
        window_end = aware(c.due_window_end)
        if due is None or due > day_end:
            continue    # not yet in scope
        if c.kind in ("customer_request", "unanswered_question"):
            rule = "explicit_request" if c.kind == "customer_request" else "unanswered_question"
            upsert(cust, rule, RANK_UNANSWERED, "commitment", c.id, due, "Answer the customer")
            continue
        rule = "commitment_due" if c.kind == "promise" else "customer_date"
        if due_at is not None and due_at < day_start:
            rank, step = RANK_OVERDUE, "Overdue — follow through today"
        elif due_at is not None:
            rank, step = RANK_DUE_TODAY, "Due today — follow through"
        else:
            # window: started (or starts today) — future scheduled work until it ends
            rank = RANK_FUTURE if (window_end and window_end > day_end) else RANK_DUE_TODAY
            step = "Window open — choose a day to follow through" if rank == RANK_FUTURE else "Window closes today"
        upsert(cust, rule, rank, "commitment", c.id, due, step)
    db.flush()
    return created


def brief_for(db: Session, tenant_id: str, user_id: str, brief_date: date) -> list[BriefItem]:
    rows = db.scalars(select(BriefItem).where(BriefItem.tenant_id == tenant_id, BriefItem.user_id == user_id,
                                              BriefItem.brief_date == brief_date.isoformat(),
                                              BriefItem.state.in_(("open", "approved")))).all()
    # Deterministic order: category, then due time, then oldest unresolved (created_at), then id.
    far = datetime.max.replace(tzinfo=timezone.utc)
    return sorted(rows, key=lambda r: (r.rank_category, (aware(r.due_at) or far).timestamp(),
                                       aware(r.created_at).timestamp(), r.id))
