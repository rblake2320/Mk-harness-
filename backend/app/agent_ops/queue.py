"""Inbound work-order validation and durable task creation."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import (
    AgentOpsContactPermission,
    AgentOpsContactSuppression,
    AgentOpsTask,
    MobileAgent,
    User,
)
from .audit import append_event
from .security import destination_fingerprint

WORKFLOWS = {
    "follow_up",
    "appointment",
    "order_status",
    "recruit_outreach",
    "social_post",
}
_E164 = re.compile(r"\+[1-9][0-9]{7,14}\Z")
_HANDLE = re.compile(r"@?[A-Za-z0-9_.]{1,64}\Z")
_PLATFORMS = {"instagram", "facebook", "sms", "tiktok", "x"}


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _required(payload: dict, *names: str) -> None:
    missing = [name for name in names if not str(payload.get(name, "")).strip()]
    if missing:
        raise ValueError("missing workflow field(s): " + ", ".join(missing))


def _https_url(value: str, field: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError(f"{field} must be an HTTPS URL without embedded credentials")
    if parsed.fragment or len(value) > 2048:
        raise ValueError(f"{field} is invalid")
    authority = parsed.netloc.lower().rstrip(".")
    if authority not in get_settings().agent_operations_target_host_set:
        raise ValueError(f"{field} authority is not in AGENT_OPERATIONS_TARGET_HOSTS")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise ValueError(f"{field} cannot target a private or reserved IP address")
    return parsed.geturl()


def validate_payload(workflow: str, raw: dict) -> dict:
    if workflow not in WORKFLOWS:
        raise ValueError(f"unsupported workflow: {workflow}")
    if not isinstance(raw, dict):
        raise ValueError("payload must be an object")
    encoded = json.dumps(raw, separators=(",", ":"))
    if len(encoded.encode()) > 32_000:
        raise ValueError("payload exceeds 32 KB")
    payload = json.loads(encoded)

    if workflow == "follow_up":
        _required(payload, "customer_name", "phone")
        if not _E164.fullmatch(str(payload["phone"])):
            raise ValueError("phone must be E.164 format")
    elif workflow == "recruit_outreach":
        _required(payload, "handle")
        if not _HANDLE.fullmatch(str(payload["handle"])):
            raise ValueError("handle contains unsupported characters")
    elif workflow == "appointment":
        _required(payload, "booking_url", "requested_time")
        payload["booking_url"] = _https_url(str(payload["booking_url"]), "booking_url")
    elif workflow == "order_status":
        _required(payload, "portal_url", "order_id")
        payload["portal_url"] = _https_url(str(payload["portal_url"]), "portal_url")
    elif workflow == "social_post":
        _required(payload, "topic")

    if workflow in {"follow_up", "recruit_outreach", "social_post"}:
        default_platform = "sms" if workflow == "follow_up" else "instagram"
        platform = str(payload.get("platform", default_platform)).lower()
        if platform not in _PLATFORMS:
            raise ValueError(f"platform must be one of {sorted(_PLATFORMS)}")
        if workflow == "follow_up" and platform != "sms":
            raise ValueError("follow_up currently supports only the sms platform")
        payload["platform"] = platform
    return payload


def assert_contact_permission(
    db: Session, tenant_id: str, workflow: str, payload: dict
) -> None:
    """Reject direct outreach without current permission or after suppression."""
    if workflow in {"follow_up", "recruit_outreach"}:
        permission_id = str(payload.get("permission_id", ""))
        permission = db.get(AgentOpsContactPermission, permission_id)
        destination = payload["phone"] if workflow == "follow_up" else payload["handle"]
        channel = payload["platform"]
        expected = destination_fingerprint(
            get_settings().master_key_bytes,
            tenant_id,
            channel,
            str(destination),
        )
        now = datetime.now(UTC)
        suppressed = db.scalar(
            select(AgentOpsContactSuppression.id).where(
                AgentOpsContactSuppression.tenant_id == tenant_id,
                AgentOpsContactSuppression.channel == channel,
                AgentOpsContactSuppression.destination_fingerprint == expected,
            )
        )
        if suppressed:
            raise ValueError("destination is permanently suppressed")
        if (
            permission is None
            or permission.tenant_id != tenant_id
            or permission.purpose != "marketing"
            or permission.channel != channel
            or permission.revoked_at is not None
            or _as_utc(permission.expires_at) <= now
            or not hmac.compare_digest(permission.destination_fingerprint, expected)
        ):
            raise ValueError("an active matching contact permission is required")


def create_task(
    db: Session,
    *,
    user: User,
    agent: MobileAgent,
    workflow: str,
    payload: dict,
) -> AgentOpsTask:
    payload = validate_payload(workflow, payload)
    assert_contact_permission(db, user.tenant_id, workflow, payload)
    task = AgentOpsTask(
        tenant_id=user.tenant_id,
        user_id=user.id,
        agent_id=agent.agent_id,
        workflow=workflow,
        payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        status="pending",
        requires_approval=True,
    )
    db.add(task)
    db.flush()
    append_event(
        db,
        tenant_id=user.tenant_id,
        task=task,
        event="TASK_QUEUED",
        detail={
            "workflow": workflow,
            "payload_sha256": hashlib.sha256(task.payload_json.encode()).hexdigest(),
        },
    )
    db.commit()
    return task
