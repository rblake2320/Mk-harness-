"""Signed outbound delivery to an allowlisted mobile adapter."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlsplit

import httpx

from ..config import get_settings
from ..models import AgentOpsTask, MobileAgent
from .contracts import validate_contract
from .security import decrypt_agent_token, sign_request, validate_webhook_url

DELIVERY_ATTEMPTS = 3
RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


def callback_url(task_id: str) -> str:
    base = get_settings().agent_operations_public_base_url.rstrip("/")
    path = f"/api/agent-ops/tasks/{task_id}/result"
    return f"{base}{path}" if base else path


async def send_to_mobile_agent(
    agent: MobileAgent, task: AgentOpsTask, work_order: dict
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
    validate_contract("work_order", body_obj)
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":")).encode()
    secret = decrypt_agent_token(
        settings.master_key_bytes,
        agent.secret_ciphertext,
        agent.tenant_id,
        agent.agent_id,
    )
    path = urlsplit(url).path or "/"
    async with httpx.AsyncClient(
        timeout=settings.agent_operations_dispatch_timeout_seconds,
        follow_redirects=False,
    ) as client:
        for attempt in range(DELIVERY_ATTEMPTS):
            headers = {
                "Content-Type": "application/json",
                "X-Mobile-Agent": agent.agent_id,
                "X-Mobile-Tenant": agent.tenant_id,
                **sign_request(secret, "POST", path, body),
            }
            try:
                response = await client.post(url, content=body, headers=headers)
                if response.status_code not in RETRYABLE_STATUS_CODES:
                    response.raise_for_status()
                    return
                response.raise_for_status()
            except (httpx.TransportError, httpx.HTTPStatusError):
                if attempt + 1 == DELIVERY_ATTEMPTS:
                    raise
                await asyncio.sleep(0.25 * (2**attempt))
