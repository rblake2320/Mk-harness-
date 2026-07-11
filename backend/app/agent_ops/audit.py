"""Tenant-scoped hash chain stored atomically with Agent Operations state."""

from __future__ import annotations

import hashlib
import json
import threading
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AgentOpsAuditEntry,
    AgentOpsAuditHead,
    AgentOpsTask,
    uid,
)

_locks: defaultdict[str, threading.RLock] = defaultdict(threading.RLock)


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _canonical(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def _detail_digest(detail: Any) -> str:
    return hashlib.sha256(_canonical(detail)).hexdigest()


def append_event(
    db: Session,
    *,
    tenant_id: str,
    event: str,
    detail: Any,
    task: AgentOpsTask | None = None,
    agent_id: str = "",
    workflow: str = "",
) -> AgentOpsAuditEntry:
    """Append without committing; the caller commits task and audit together."""
    with _locks[tenant_id]:
        head = db.scalar(
            select(AgentOpsAuditHead)
            .where(AgentOpsAuditHead.tenant_id == tenant_id)
            .with_for_update()
        )
        if head is None:
            head = AgentOpsAuditHead(tenant_id=tenant_id)
            db.add(head)
            db.flush()

        created_at = datetime.now(UTC)
        entry_id = uid()
        sequence = head.entry_count + 1
        digest = _detail_digest(detail)
        fields = {
            "id": entry_id,
            "tenant_id": tenant_id,
            "task_id": task.id if task else None,
            "agent_id": agent_id or (task.agent_id if task else ""),
            "workflow": workflow or (task.workflow if task else ""),
            "event": event,
            "detail_digest": digest,
            "sequence": sequence,
            "prev_hash": head.last_hash,
            "created_at": _utc_iso(created_at),
        }
        entry_hash = hashlib.sha256(
            head.last_hash.encode() + _canonical(fields)
        ).hexdigest()
        persistence_fields = {
            key: value for key, value in fields.items() if key != "created_at"
        }
        entry = AgentOpsAuditEntry(
            **persistence_fields, entry_hash=entry_hash, created_at=created_at
        )
        db.add(entry)
        head.last_hash = entry_hash
        head.entry_count = sequence
        head.updated_at = created_at
        if task:
            task.audit_hash = entry_hash
        db.flush()
        return entry


def verify_chain(db: Session, tenant_id: str) -> tuple[bool, int, str]:
    entries = list(
        db.scalars(
            select(AgentOpsAuditEntry)
            .where(AgentOpsAuditEntry.tenant_id == tenant_id)
            .order_by(AgentOpsAuditEntry.sequence)
        )
    )
    previous = "genesis"
    for expected_sequence, entry in enumerate(entries, 1):
        fields = {
            "id": entry.id,
            "tenant_id": entry.tenant_id,
            "task_id": entry.task_id,
            "agent_id": entry.agent_id,
            "workflow": entry.workflow,
            "event": entry.event,
            "detail_digest": entry.detail_digest,
            "sequence": entry.sequence,
            "prev_hash": entry.prev_hash,
            "created_at": _utc_iso(entry.created_at),
        }
        computed = hashlib.sha256(previous.encode() + _canonical(fields)).hexdigest()
        if entry.sequence != expected_sequence or entry.prev_hash != previous:
            return False, expected_sequence - 1, "sequence_or_link_mismatch"
        if not hmac_compare(computed, entry.entry_hash):
            return False, expected_sequence - 1, "entry_hash_mismatch"
        previous = entry.entry_hash

    head = db.get(AgentOpsAuditHead, tenant_id)
    if head is None:
        return (not entries), len(entries), "missing_head" if entries else "empty"
    if head.entry_count != len(entries) or head.last_hash != previous:
        return False, len(entries), "head_mismatch"
    return True, len(entries), "valid"


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)
