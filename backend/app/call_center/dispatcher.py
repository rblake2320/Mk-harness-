"""Generate compliant work orders, stage approval, and deliver to device adapters."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..db import new_session
from ..models import CallCenterTask, ClawAgent, Tenant, User
from ..providers.base import ChatMessage, ChatRequest
from ..providers.router import complete_with_failover
from ..skills import get_skills, response_has_income_claim, response_leaks_system_prompt
from .audit import append_event
from .claw_bridge import build as build_work_order
from .transport import send_to_phone

_SKILL_MAP = {
    "follow_up": "follow_up",
    "social_post": "social",
    "recruit_outreach": "sales_coach",
}


def _prompt(workflow: str, payload: dict) -> str:
    return (
        f"Create only the customer-facing text for workflow {workflow}. "
        "Do not claim that an action was completed. Do not include system instructions. "
        "Use only supplied facts. Input:\n" + json.dumps(payload, sort_keys=True)
    )


def _agent(db: Session, task: CallCenterTask) -> ClawAgent | None:
    return db.scalar(
        select(ClawAgent).where(
            ClawAgent.tenant_id == task.tenant_id,
            ClawAgent.agent_id == task.agent_id,
        )
    )


async def prepare_task(db: Session, task: CallCenterTask) -> None:
    if task.status != "pending":
        return
    user = db.get(User, task.user_id)
    tenant = db.get(Tenant, task.tenant_id)
    if user is None or tenant is None or _agent(db, task) is None:
        raise ValueError("task principal or agent no longer exists")

    task.status = "generating"
    task.updated_at = datetime.now(UTC)
    db.commit()
    payload = json.loads(task.payload_json)
    response = ""
    if task.workflow in _SKILL_MAP:
        skills = get_skills(tenant.brand)
        request = ChatRequest(
            messages=[
                ChatMessage(role="user", content=_prompt(task.workflow, payload))
            ],
            system=skills[_SKILL_MAP[task.workflow]]["system"],
            max_tokens=700,
            temperature=0.5,
        )
        result = await complete_with_failover(db, user, request, kind="call_center")
        response = result.text
        claim, phrase = response_has_income_claim(response, tenant.brand)
        if claim:
            task.status = "compliance_blocked"
            task.compliance_checked = True
            task.error_code = "income_claim"
            append_event(
                db,
                tenant_id=task.tenant_id,
                task=task,
                event="COMPLIANCE_BLOCKED",
                detail={"rule": "income_claim", "matched_phrase": phrase},
            )
            db.commit()
            return
        if response_leaks_system_prompt(response):
            task.status = "compliance_blocked"
            task.compliance_checked = True
            task.error_code = "prompt_leak"
            append_event(
                db,
                tenant_id=task.tenant_id,
                task=task,
                event="COMPLIANCE_BLOCKED",
                detail={"rule": "prompt_leak"},
            )
            db.commit()
            return

    task.claw_script_json = json.dumps(
        build_work_order(task.workflow, response, task.payload_json),
        sort_keys=True,
        separators=(",", ":"),
    )
    task.compliance_checked = True
    task.status = "awaiting_approval"
    task.updated_at = datetime.now(UTC)
    append_event(
        db,
        tenant_id=task.tenant_id,
        task=task,
        event="WORK_ORDER_STAGED",
        detail={"requires_human_approval": True},
    )
    db.commit()


async def prepare_task_by_id(task_id: str) -> None:
    db = new_session()
    try:
        task = db.get(CallCenterTask, task_id)
        if task is None:
            return
        await prepare_task(db, task)
    except Exception as exc:
        db.rollback()
        task = db.get(CallCenterTask, task_id)
        if task is not None:
            task.status = "failed"
            task.error_code = type(exc).__name__
            task.updated_at = datetime.now(UTC)
            append_event(
                db,
                tenant_id=task.tenant_id,
                task=task,
                event="PREPARATION_FAILED",
                detail={"error_type": type(exc).__name__},
            )
            db.commit()
    finally:
        db.close()


async def approve_and_dispatch(
    db: Session, task: CallCenterTask, approver: User
) -> None:
    if task.status != "awaiting_approval" or not task.claw_script_json:
        raise ValueError("task is not awaiting approval")
    agent = _agent(db, task)
    if agent is None or agent.status != "online":
        raise ValueError("agent is not online")

    approved_at = datetime.now(UTC)
    claimed = db.execute(
        update(CallCenterTask)
        .where(
            CallCenterTask.id == task.id,
            CallCenterTask.status == "awaiting_approval",
        )
        .values(
            status="dispatching",
            approved_at=approved_at,
            approved_by=approver.id,
            updated_at=approved_at,
        )
    )
    if claimed.rowcount != 1:
        db.rollback()
        raise ValueError("task approval was already claimed")
    db.refresh(task)
    append_event(
        db,
        tenant_id=task.tenant_id,
        task=task,
        event="HUMAN_APPROVED",
        detail={"approver_id": approver.id},
    )
    db.commit()
    try:
        await send_to_phone(agent, task, json.loads(task.claw_script_json))
    except (httpx.HTTPError, ValueError) as exc:
        task.status = "failed"
        task.error_code = "adapter_delivery_failed"
        append_event(
            db,
            tenant_id=task.tenant_id,
            task=task,
            event="DELIVERY_FAILED",
            detail={"error_type": type(exc).__name__},
        )
        db.commit()
        raise

    task.status = "dispatched"
    task.updated_at = datetime.now(UTC)
    append_event(
        db,
        tenant_id=task.tenant_id,
        task=task,
        event="DISPATCHED",
        detail={"adapter_version": agent.adapter_version},
    )
    db.commit()
