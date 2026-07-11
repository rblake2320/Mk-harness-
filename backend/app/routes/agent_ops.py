"""Tenant-scoped Agent Operations tasks and signed mobile-adapter callbacks."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..agent_ops.audit import append_event, verify_chain
from ..agent_ops.dispatcher import approve_and_dispatch, prepare_task_by_id
from ..agent_ops.queue import WORKFLOWS, create_task
from ..agent_ops.security import (
    SIGNATURE_TTL_SECONDS,
    decrypt_agent_token,
    destination_fingerprint,
    encrypt_agent_token,
    new_agent_token,
    validate_webhook_url,
    verify_request,
)
from ..config import get_settings
from ..db import get_db
from ..entitlements import require_active_subscription
from ..models import (
    AgentOpsAuditEntry,
    AgentOpsContactPermission,
    AgentOpsContactSuppression,
    AgentOpsTask,
    MobileAgent,
    MobileCallbackNonce,
    User,
)
from ..ratelimit import check_rate
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/agent-ops", tags=["agent-operations"])


class MobileAgentIn(BaseModel):
    agent_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
    webhook_url: str = Field(min_length=1, max_length=2048)
    platform_specialty: str = Field(default="multi", max_length=40)
    capabilities: dict = Field(default_factory=dict)
    adapter_version: str = Field(default="mobile-adapter-v1", max_length=80)


class TaskIn(BaseModel):
    workflow: str
    agent_id: str = Field(min_length=1, max_length=80)
    payload: dict


class ContactPermissionIn(BaseModel):
    channel: str = Field(pattern=r"^(sms|instagram|facebook|tiktok|x)$")
    destination: str = Field(min_length=1, max_length=120)
    purpose: Literal["marketing"] = "marketing"
    asserted_basis: Literal[
        "express_written_consent",
        "customer_inquiry",
        "established_business_relationship",
        "transactional_request",
    ]
    source_reference: str = Field(min_length=1, max_length=500)
    evidence_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    granted_at: datetime
    expires_at: datetime
    operator_attestation: Literal[True]


class ContactSuppressionIn(BaseModel):
    channel: str = Field(pattern=r"^(sms|instagram|facebook|tiktok|x)$")
    destination: str = Field(min_length=1, max_length=120)
    reason: Literal[
        "customer_opt_out",
        "complaint",
        "legal_hold",
        "operator_safety",
    ]


class ApprovalIn(BaseModel):
    approved: bool


class DevicePingIn(BaseModel):
    status: str = Field(default="online", pattern=r"^(online|busy|offline)$")


class DeviceResultIn(BaseModel):
    status: str = Field(pattern=r"^(executing|complete|failed)$")
    result: dict = Field(default_factory=dict)
    error_code: str = Field(default="", max_length=80)


def _agent_dict(agent: MobileAgent) -> dict:
    return {
        "agent_id": agent.agent_id,
        "webhook_url": agent.webhook_url,
        "platform_specialty": agent.platform_specialty,
        "capabilities": json.loads(agent.capabilities_json),
        "adapter_version": agent.adapter_version,
        "status": agent.status,
        "last_ping": agent.last_ping.isoformat() if agent.last_ping else None,
        "created_at": agent.created_at.isoformat(),
    }


def _task_dict(task: AgentOpsTask, *, detail: bool = False) -> dict:
    data = {
        "id": task.id,
        "agent_id": task.agent_id,
        "workflow": task.workflow,
        "status": task.status,
        "compliance_checked": task.compliance_checked,
        "requires_approval": task.requires_approval,
        "approved_at": task.approved_at.isoformat() if task.approved_at else None,
        "audit_hash": task.audit_hash,
        "error_code": task.error_code,
        "created_at": task.created_at.isoformat(),
        "updated_at": task.updated_at.isoformat(),
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
    }
    if detail:
        data["payload"] = json.loads(task.payload_json)
        data["work_order"] = (
            json.loads(task.work_order_json) if task.work_order_json else None
        )
        data["result"] = json.loads(task.result_json) if task.result_json else None
    return data


def _tenant_agent(db: Session, tenant_id: str, agent_id: str) -> MobileAgent | None:
    return db.scalar(
        select(MobileAgent).where(
            MobileAgent.tenant_id == tenant_id,
            MobileAgent.agent_id == agent_id,
        )
    )


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _suppression(
    db: Session, tenant_id: str, channel: str, fingerprint: str
) -> AgentOpsContactSuppression | None:
    return db.scalar(
        select(AgentOpsContactSuppression).where(
            AgentOpsContactSuppression.tenant_id == tenant_id,
            AgentOpsContactSuppression.channel == channel,
            AgentOpsContactSuppression.destination_fingerprint == fingerprint,
        )
    )


def _own_task(db: Session, user: User, task_id: str) -> AgentOpsTask:
    task = db.get(AgentOpsTask, task_id)
    if (
        task is None
        or task.tenant_id != user.tenant_id
        or (user.role != "admin" and task.user_id != user.id)
    ):
        raise HTTPException(404, "Task not found")
    return task


def _device_auth(
    request: Request,
    body: bytes,
    db: Session,
    agent: MobileAgent,
) -> None:
    timestamp = request.headers.get("X-Mobile-Timestamp", "")
    nonce = request.headers.get("X-Mobile-Nonce", "")
    signature = request.headers.get("X-Mobile-Signature", "")
    if (
        request.headers.get("X-Mobile-Agent", "") != agent.agent_id
        or request.headers.get("X-Mobile-Tenant", "") != agent.tenant_id
    ):
        raise HTTPException(401, "Invalid device authentication")
    secret = decrypt_agent_token(
        get_settings().master_key_bytes,
        agent.secret_ciphertext,
        agent.tenant_id,
        agent.agent_id,
    )
    if not verify_request(
        secret,
        request.method,
        request.url.path,
        body,
        timestamp=timestamp,
        nonce=nonce,
        signature=signature,
    ):
        raise HTTPException(401, "Invalid device authentication")
    db.execute(
        delete(MobileCallbackNonce).where(
            MobileCallbackNonce.tenant_id == agent.tenant_id,
            MobileCallbackNonce.agent_id == agent.agent_id,
            MobileCallbackNonce.expires_at < datetime.now(UTC),
        )
    )
    db.add(
        MobileCallbackNonce(
            tenant_id=agent.tenant_id,
            agent_id=agent.agent_id,
            nonce=nonce,
            expires_at=datetime.now(UTC) + timedelta(seconds=SIGNATURE_TTL_SECONDS),
        )
    )
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Device request replayed")


@router.post("/agents", status_code=201)
def register_agent(
    body: MobileAgentIn,
    admin: User = Depends(require_admin),
    _sub: User = Depends(require_active_subscription),
    db: Session = Depends(get_db),
):
    settings = get_settings()
    try:
        webhook_url = validate_webhook_url(
            body.webhook_url, settings.agent_operations_webhook_host_set
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    capabilities_json = json.dumps(
        body.capabilities, sort_keys=True, separators=(",", ":")
    )
    if len(capabilities_json.encode()) > 8192:
        raise HTTPException(422, "capabilities exceed 8 KB")
    if _tenant_agent(db, admin.tenant_id, body.agent_id):
        raise HTTPException(409, "Agent already exists")
    token = new_agent_token()
    agent = MobileAgent(
        tenant_id=admin.tenant_id,
        created_by=admin.id,
        agent_id=body.agent_id,
        webhook_url=webhook_url,
        secret_ciphertext=encrypt_agent_token(
            settings.master_key_bytes, token, admin.tenant_id, body.agent_id
        ),
        platform_specialty=body.platform_specialty,
        capabilities_json=capabilities_json,
        adapter_version=body.adapter_version,
    )
    db.add(agent)
    db.flush()
    append_event(
        db,
        tenant_id=admin.tenant_id,
        event="AGENT_REGISTERED",
        agent_id=agent.agent_id,
        detail={"adapter_version": agent.adapter_version},
    )
    db.commit()
    return {
        **_agent_dict(agent),
        "tenant_id": agent.tenant_id,
        "device_token": token,
    }


@router.post("/permissions", status_code=201)
def record_contact_permission(
    body: ContactPermissionIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    now = datetime.now(UTC)
    granted_at = _aware(body.granted_at)
    expires_at = _aware(body.expires_at)
    if granted_at > now + timedelta(minutes=5):
        raise HTTPException(422, "granted_at cannot be in the future")
    if expires_at <= now or expires_at > now + timedelta(days=548):
        raise HTTPException(422, "expires_at must be within the next 548 days")
    fingerprint = destination_fingerprint(
        get_settings().master_key_bytes,
        user.tenant_id,
        body.channel,
        body.destination,
    )
    if _suppression(db, user.tenant_id, body.channel, fingerprint):
        raise HTTPException(409, "Destination is permanently suppressed")
    permission = AgentOpsContactPermission(
        tenant_id=user.tenant_id,
        created_by=user.id,
        channel=body.channel,
        destination_fingerprint=fingerprint,
        purpose=body.purpose,
        asserted_basis=body.asserted_basis,
        source_reference=body.source_reference,
        evidence_digest=body.evidence_sha256.lower(),
        granted_at=granted_at,
        expires_at=expires_at,
    )
    db.add(permission)
    db.flush()
    append_event(
        db,
        tenant_id=user.tenant_id,
        event="CONTACT_PERMISSION_RECORDED",
        detail={
            "permission_id": permission.id,
            "channel": permission.channel,
            "purpose": permission.purpose,
            "asserted_basis": permission.asserted_basis,
            "evidence_digest": permission.evidence_digest,
            "expires_at": expires_at.isoformat(),
            "operator_attested": True,
        },
    )
    db.commit()
    return {
        "id": permission.id,
        "channel": permission.channel,
        "purpose": permission.purpose,
        "asserted_basis": permission.asserted_basis,
        "source_reference": permission.source_reference,
        "evidence_digest": permission.evidence_digest,
        "granted_at": permission.granted_at.isoformat(),
        "expires_at": permission.expires_at.isoformat(),
        "revoked_at": None,
        "operator_attested": True,
        "legal_sufficiency_verified": False,
    }


@router.post("/suppressions", status_code=201)
def record_contact_suppression(
    body: ContactSuppressionIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    fingerprint = destination_fingerprint(
        get_settings().master_key_bytes,
        user.tenant_id,
        body.channel,
        body.destination,
    )
    suppression = _suppression(db, user.tenant_id, body.channel, fingerprint)
    if suppression is None:
        suppression = AgentOpsContactSuppression(
            tenant_id=user.tenant_id,
            created_by=user.id,
            channel=body.channel,
            destination_fingerprint=fingerprint,
            reason=body.reason,
        )
        db.add(suppression)
        db.flush()
        append_event(
            db,
            tenant_id=user.tenant_id,
            event="CONTACT_SUPPRESSED",
            detail={
                "suppression_id": suppression.id,
                "channel": suppression.channel,
                "reason": suppression.reason,
            },
        )
        db.commit()
    return {
        "id": suppression.id,
        "channel": suppression.channel,
        "destination_fingerprint": suppression.destination_fingerprint,
        "reason": suppression.reason,
        "created_at": suppression.created_at.isoformat(),
        "permanent": True,
    }


@router.get("/suppressions")
def list_contact_suppressions(
    admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    rows = db.scalars(
        select(AgentOpsContactSuppression)
        .where(AgentOpsContactSuppression.tenant_id == admin.tenant_id)
        .order_by(AgentOpsContactSuppression.created_at.desc())
        .limit(500)
    )
    return [
        {
            "id": row.id,
            "channel": row.channel,
            "destination_fingerprint": row.destination_fingerprint,
            "reason": row.reason,
            "created_at": row.created_at.isoformat(),
            "permanent": True,
        }
        for row in rows
    ]


@router.get("/permissions")
def list_contact_permissions(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    permissions = db.scalars(
        select(AgentOpsContactPermission)
        .where(AgentOpsContactPermission.tenant_id == user.tenant_id)
        .order_by(AgentOpsContactPermission.created_at.desc())
        .limit(200)
    )
    return [
        {
            "id": permission.id,
            "channel": permission.channel,
            "purpose": permission.purpose,
            "asserted_basis": permission.asserted_basis,
            "source_reference": permission.source_reference,
            "evidence_digest": permission.evidence_digest,
            "granted_at": permission.granted_at.isoformat(),
            "expires_at": permission.expires_at.isoformat(),
            "revoked_at": (
                permission.revoked_at.isoformat() if permission.revoked_at else None
            ),
            "operator_attested": True,
            "legal_sufficiency_verified": False,
        }
        for permission in permissions
    ]


@router.post("/permissions/{permission_id}/revoke")
def revoke_contact_permission(
    permission_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    permission = db.get(AgentOpsContactPermission, permission_id)
    if permission is None or permission.tenant_id != user.tenant_id:
        raise HTTPException(404, "Contact permission not found")
    if permission.revoked_at is None:
        permission.revoked_at = datetime.now(UTC)
        suppression = _suppression(
            db,
            permission.tenant_id,
            permission.channel,
            permission.destination_fingerprint,
        )
        if suppression is None:
            suppression = AgentOpsContactSuppression(
                tenant_id=permission.tenant_id,
                created_by=user.id,
                channel=permission.channel,
                destination_fingerprint=permission.destination_fingerprint,
                reason="customer_opt_out",
            )
            db.add(suppression)
        append_event(
            db,
            tenant_id=user.tenant_id,
            event="CONTACT_PERMISSION_REVOKED",
            detail={
                "permission_id": permission.id,
                "permanent_suppression": True,
            },
        )
        db.commit()
    return {"ok": True, "revoked_at": permission.revoked_at.isoformat()}


@router.get("/agents")
def list_agents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    agents = db.scalars(
        select(MobileAgent)
        .where(MobileAgent.tenant_id == user.tenant_id)
        .order_by(MobileAgent.agent_id)
    )
    return [_agent_dict(agent) for agent in agents]


@router.post("/agents/{agent_id}/ping")
async def device_ping(agent_id: str, request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    if len(body) > 4096:
        raise HTTPException(413, "Ping body too large")
    tenant_id = request.headers.get("X-Mobile-Tenant", "")
    agent = _tenant_agent(db, tenant_id, agent_id) if tenant_id else None
    if agent is None:
        raise HTTPException(401, "Invalid device authentication")
    _device_auth(request, body, db, agent)
    try:
        ping = DevicePingIn.model_validate_json(body)
    except ValueError:
        raise HTTPException(422, "Invalid ping body")
    agent.status = ping.status
    agent.last_ping = datetime.now(UTC)
    agent.updated_at = agent.last_ping
    append_event(
        db,
        tenant_id=agent.tenant_id,
        event="AGENT_PING",
        agent_id=agent.agent_id,
        detail={"status": ping.status},
    )
    db.commit()
    return {"ok": True, "status": agent.status}


@router.post("/tasks", status_code=202)
def queue_task(
    body: TaskIn,
    background: BackgroundTasks,
    user: User = Depends(check_rate),
    _sub: User = Depends(require_active_subscription),
    db: Session = Depends(get_db),
):
    if body.workflow not in WORKFLOWS:
        raise HTTPException(422, "Unsupported workflow")
    agent = _tenant_agent(db, user.tenant_id, body.agent_id)
    if agent is None:
        raise HTTPException(404, "Agent not found")
    try:
        task = create_task(
            db,
            user=user,
            agent=agent,
            workflow=body.workflow,
            payload=body.payload,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    background.add_task(prepare_task_by_id, task.id)
    return {"id": task.id, "status": task.status}


@router.get("/tasks")
def list_tasks(
    limit: int = Query(default=100, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = select(AgentOpsTask).where(AgentOpsTask.tenant_id == user.tenant_id)
    if user.role != "admin":
        query = query.where(AgentOpsTask.user_id == user.id)
    tasks = db.scalars(query.order_by(AgentOpsTask.created_at.desc()).limit(limit))
    return [_task_dict(task) for task in tasks]


@router.get("/tasks/{task_id}")
def get_task(
    task_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _task_dict(_own_task(db, user, task_id), detail=True)


@router.post("/tasks/{task_id}/approve")
async def approve_task(
    task_id: str,
    body: ApprovalIn,
    user: User = Depends(check_rate),
    _sub: User = Depends(require_active_subscription),
    db: Session = Depends(get_db),
):
    if not body.approved:
        raise HTTPException(422, "Explicit approval is required")
    task = _own_task(db, user, task_id)
    try:
        await approve_and_dispatch(db, task, user)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    except Exception:
        raise HTTPException(502, "Adapter delivery failed")
    return _task_dict(task)


@router.post("/tasks/{task_id}/result")
async def device_result(task_id: str, request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    if len(body) > 32_000:
        raise HTTPException(413, "Result body too large")
    task = db.get(AgentOpsTask, task_id)
    if task is None:
        raise HTTPException(401, "Invalid device authentication")
    agent = _tenant_agent(db, task.tenant_id, task.agent_id)
    if agent is None:
        raise HTTPException(401, "Invalid device authentication")
    _device_auth(request, body, db, agent)
    try:
        result = DeviceResultIn.model_validate_json(body)
    except ValueError:
        raise HTTPException(422, "Invalid result body")
    allowed_from = {"dispatched", "executing"}
    if task.status not in allowed_from:
        raise HTTPException(409, "Task does not accept device results in this state")
    if result.status == "executing" and task.status != "dispatched":
        raise HTTPException(409, "Duplicate execution transition")

    result_json = json.dumps(result.result, sort_keys=True, separators=(",", ":"))
    task.result_json = result_json
    task.status = result.status
    task.error_code = result.error_code if result.status == "failed" else ""
    task.updated_at = datetime.now(UTC)
    if result.status in {"complete", "failed"}:
        task.completed_at = task.updated_at
    append_event(
        db,
        tenant_id=task.tenant_id,
        task=task,
        event={
            "executing": "EXECUTION_STARTED",
            "complete": "TASK_COMPLETED",
            "failed": "TASK_FAILED",
        }[result.status],
        detail={
            "result_sha256": hashlib.sha256(result_json.encode()).hexdigest(),
            "error_code": task.error_code,
        },
    )
    db.commit()
    return {"ok": True, "status": task.status}


@router.get("/audit/verify")
def audit_verify(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    valid, checked, reason = verify_chain(db, admin.tenant_id)
    return {"valid": valid, "entries_checked": checked, "reason": reason}


@router.get("/audit/tail")
def audit_tail(
    limit: int = Query(default=50, ge=1, le=200),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    entries = list(
        db.scalars(
            select(AgentOpsAuditEntry)
            .where(AgentOpsAuditEntry.tenant_id == admin.tenant_id)
            .order_by(AgentOpsAuditEntry.sequence.desc())
            .limit(limit)
        )
    )
    return [
        {
            "sequence": entry.sequence,
            "event": entry.event,
            "task_id": entry.task_id,
            "agent_id": entry.agent_id,
            "workflow": entry.workflow,
            "detail_digest": entry.detail_digest,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
            "created_at": entry.created_at.isoformat(),
        }
        for entry in reversed(entries)
    ]
