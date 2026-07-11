"""Signed outbound delivery to an allowlisted PhoneClaw adapter."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import httpx

from ..config import get_settings
from ..models import CallCenterTask, ClawAgent
from .security import decrypt_agent_token, sign_request, validate_webhook_url


def callback_url(task_id: str) -> str:
    base = get_settings().agent_operations_public_base_url.rstrip("/")
    path = f"/api/claw/tasks/{task_id}/result"
    return f"{base}{path}" if base else path


async def send_to_phone(
    agent: ClawAgent, task: CallCenterTask, work_order: dict
) -> None:
    settings = get_settings()
    url = validate_webhook_url(
        agent.webhook_url, settings.agent_operations_webhook_host_set
    )
    body_obj = {
        **work_order,
        "task_id": task.id,
        "agent_id": agent.agent_id,
        "callback_url": callback_url(task.id),
        "callback_auth": "hmac-sha256-v1",
    }
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":")).encode()
    secret = decrypt_agent_token(
        settings.master_key_bytes,
        agent.secret_ciphertext,
        agent.tenant_id,
        agent.agent_id,
    )
    path = urlsplit(url).path or "/"
    headers = {
        "Content-Type": "application/json",
        "X-Claw-Agent": agent.agent_id,
        "X-Claw-Tenant": agent.tenant_id,
        **sign_request(secret, "POST", path, body),
    }
    async with httpx.AsyncClient(
        timeout=settings.agent_operations_dispatch_timeout_seconds,
        follow_redirects=False,
    ) as client:
        response = await client.post(url, content=body, headers=headers)
    response.raise_for_status()
