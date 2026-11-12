"""Retention (contract S13) — ONE table that both the purge job and the published
privacy policy are generated from, so the policy cannot claim a period the code
does not enforce (that divergence existed: the policy promised a 12-month
conversation purge that no job performed).

Run daily: `python -m app.tools.retention run` (compose service `retention`).
Every rule is idempotent and works in bounded batches; a crash mid-run leaves
the remaining rows for the next run. Each run writes one content-free audit row
with per-rule counts.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from .foundation import utcnow
from .models import (
    AuditLog, AuthSession, Commitment, Conversation, DraftVersion, ExceptionRecord, ImportJob, ImportRow,
    KernelRevocationOutbox, Message, Outcome, WebAuthnChallenge,
)

BATCH = 5000


@dataclass(frozen=True)
class Rule:
    key: str
    days: int
    policy: str                 # exact sentence published in the privacy policy
    run: Callable[[Session, object], int]


def _ids(db: Session, stmt) -> list:
    return list(db.scalars(stmt.limit(BATCH)).all())


def _messages(db, cutoff):
    ids = _ids(db, select(Message.id).where(Message.created_at < cutoff))
    if ids:
        db.execute(delete(Message).where(Message.id.in_(ids)))
    empty = _ids(db, select(Conversation.id).where(
        Conversation.created_at < cutoff, ~select(Message.id).where(Message.conversation_id == Conversation.id).exists()))
    if empty:
        db.execute(delete(Conversation).where(Conversation.id.in_(empty)))
    return len(ids) + len(empty)


def _drafts(db, cutoff):
    ids = _ids(db, select(DraftVersion.id).where(DraftVersion.created_at < cutoff, DraftVersion.text_enc != ""))
    if ids:
        db.execute(update(DraftVersion).where(DraftVersion.id.in_(ids)).values(text_enc="", relationship_spans_json="[]"))
    return len(ids)


def _exceptions(db, cutoff):
    ids = _ids(db, select(ExceptionRecord.id).where(ExceptionRecord.state != "open",
                                                    ExceptionRecord.resolved_at < cutoff, ExceptionRecord.detail_enc != ""))
    if ids:
        db.execute(update(ExceptionRecord).where(ExceptionRecord.id.in_(ids)).values(detail_enc=""))
    return len(ids)


def _commitments(db, cutoff):
    ids = _ids(db, select(Commitment.id).where(Commitment.status.in_(("resolved", "cancelled")),
                                               Commitment.updated_at < cutoff, Commitment.commitment_text != ""))
    if ids:
        db.execute(update(Commitment).where(Commitment.id.in_(ids)).values(commitment_text=""))
    return len(ids)


def _outcomes(db, cutoff):
    ids = _ids(db, select(Outcome.id).where(Outcome.created_at < cutoff, Outcome.note_enc != ""))
    if ids:
        db.execute(update(Outcome).where(Outcome.id.in_(ids)).values(note_enc=""))
    return len(ids)


def _imports(db, cutoff):
    jobs = select(ImportJob.id).where(ImportJob.created_at < cutoff)
    ids = _ids(db, select(ImportRow.id).where(ImportRow.job_id.in_(jobs), or_(
        ImportRow.name != "", ImportRow.phone_enc != "", ImportRow.email_enc != "", ImportRow.notes != "")))
    if ids:
        db.execute(update(ImportRow).where(ImportRow.id.in_(ids)).values(
            name="", phone_enc="", email_enc="", notes="", phone_fingerprint="", email_fingerprint=""))
    return len(ids)


def _sessions(db, cutoff):
    ids = _ids(db, select(AuthSession.id).where(or_(AuthSession.expires_at < cutoff, AuthSession.revoked_at < cutoff)))
    if ids:
        db.execute(delete(WebAuthnChallenge).where(WebAuthnChallenge.session_id.in_(ids)))
        db.execute(delete(AuthSession).where(AuthSession.id.in_(ids)))
    stale = _ids(db, select(WebAuthnChallenge.id).where(WebAuthnChallenge.expires_at < cutoff))
    if stale:
        db.execute(delete(WebAuthnChallenge).where(WebAuthnChallenge.id.in_(stale)))
    done = _ids(db, select(KernelRevocationOutbox.id).where(KernelRevocationOutbox.delivered_at < cutoff))
    if done:
        db.execute(delete(KernelRevocationOutbox).where(KernelRevocationOutbox.id.in_(done)))
    return len(ids) + len(stale) + len(done)


def _audit(db, cutoff):
    ids = _ids(db, select(AuditLog.id).where(AuditLog.created_at < cutoff))
    if ids:
        db.execute(delete(AuditLog).where(AuditLog.id.in_(ids)))
    return len(ids)


RULES: tuple[Rule, ...] = (
    Rule("assistant_conversations", 365, "Assistant chat conversations: deleted 12 months after they were written.", _messages),
    Rule("message_drafts", 365, "Message drafts: text deleted 12 months after it was written.", _drafts),
    Rule("exception_details", 365, "Customer-reported issues (exceptions): details deleted 12 months after they are resolved.", _exceptions),
    Rule("commitments", 730, "Follow-up promises: text deleted 24 months after they are resolved or cancelled.", _commitments),
    Rule("outcome_notes", 730, "Outcome notes: deleted 24 months after they were recorded.", _outcomes),
    Rule("import_files", 30, "Imported spreadsheet rows: contact details deleted 30 days after the import.", _imports),
    Rule("sign_in_sessions", 30, "Sign-in sessions and security challenges: deleted 30 days after they end.", _sessions),
    Rule("application_audit", 7 * 365, "Application audit records (who changed what; no message text): deleted after 7 years.", _audit),
)

# Rules that are not periodic purges but are true and enforced — published with the table.
STANDING = (
    "Customer records: kept while your account is active; when you erase a customer, or delete your account, "
    "their content is erased at once in the application and the erasure of message copies held by our sending "
    "system and our SMS provider is queued and completed within 30 days.",
    "Permission evidence and opt-out records are kept in minimal form (no message text) after erasure, so a "
    "customer who opted out is never contacted again.",
    "Skin analysis results: kept while the customer record exists; erased with it.",
    "Database backups age out within 35 days; an erasure is re-applied after any restore before sending resumes.",
)


def policy_html() -> str:
    items = [f"  <li>{r.policy}</li>" for r in RULES] + [f"  <li>{t}</li>" for t in STANDING]
    return "<ul>\n" + "\n".join(items) + "\n</ul>"


def run(db: Session, *, now=None, only: set[str] | None = None) -> dict[str, int]:
    now = now or utcnow()
    counts: dict[str, int] = {}
    for r in RULES:
        if only and r.key not in only:
            continue
        total = 0
        while True:                       # bounded batches until the rule is drained
            n = r.run(db, now - timedelta(days=r.days))
            db.commit()
            total += n
            if n < BATCH:
                break
        counts[r.key] = total
    db.add(AuditLog(tenant_id="platform", user_id="retention", action="retention.run",
                    detail=json.dumps(counts, sort_keys=True)))
    db.commit()
    return counts
