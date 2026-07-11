"""Loopback-only conformance simulator for the mobile-adapter v1 contract."""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from . import COMPLETION_SCHEMA, EXECUTION_SCHEMA, FAILURE_SCHEMA
from .contracts import ContractValidationError, validate_contract
from .security import sign_request, verify_request

SimulatorMode = Literal["accept", "fail_once", "reject", "unsupported_actions"]


@dataclass
class SimulatorConfig:
    agent_id: str
    tenant_id: str
    device_token: str
    control_token: str
    mode: SimulatorMode = "accept"


@dataclass
class SimulatorState:
    config: SimulatorConfig
    work_orders: dict[str, dict] = field(default_factory=dict)
    nonces: set[str] = field(default_factory=set)
    attempts: int = 0

    def accept(self, path: str, headers: httpx.Headers, body: bytes) -> dict:
        self.attempts += 1
        if (
            headers.get("X-Mobile-Agent") != self.config.agent_id
            or headers.get("X-Mobile-Tenant") != self.config.tenant_id
        ):
            raise HTTPException(401, "invalid simulator identity")
        timestamp = headers.get("X-Mobile-Timestamp", "")
        nonce = headers.get("X-Mobile-Nonce", "")
        signature = headers.get("X-Mobile-Signature", "")
        if not verify_request(
            self.config.device_token,
            "POST",
            path,
            body,
            timestamp=timestamp,
            nonce=nonce,
            signature=signature,
        ):
            raise HTTPException(401, "invalid simulator signature")
        if nonce in self.nonces:
            raise HTTPException(409, "simulator request replayed")
        self.nonces.add(nonce)
        try:
            value = json.loads(body)
            validate_contract("work_order", value)
        except (json.JSONDecodeError, ContractValidationError) as exc:
            raise HTTPException(422, f"invalid work order: {exc}") from exc
        if self.config.mode == "fail_once" and self.attempts == 1:
            raise HTTPException(503, "deterministic first-attempt failure")
        if self.config.mode == "reject":
            raise HTTPException(422, "deterministic adapter rejection")
        if (
            self.config.mode == "unsupported_actions"
            and value["adapter_actions_required"]
        ):
            raise HTTPException(422, "adapter action is not implemented")
        previous = self.work_orders.get(value["task_id"])
        if previous is not None and previous != value:
            raise HTTPException(409, "task_id was reused with different content")
        self.work_orders[value["task_id"]] = value
        return value

    async def send_callback(
        self,
        task_id: str,
        status: Literal["executing", "complete", "failed"],
        *,
        result: dict | None = None,
        error_code: str = "",
        client: httpx.AsyncClient | None = None,
    ) -> httpx.Response:
        try:
            work_order = self.work_orders[task_id]
        except KeyError as exc:
            raise ValueError("unknown simulator task") from exc
        schema = {
            "executing": EXECUTION_SCHEMA,
            "complete": COMPLETION_SCHEMA,
            "failed": FAILURE_SCHEMA,
        }[status]
        body_obj = {
            "schema": schema,
            "status": status,
            "result": result or {},
            "error_code": error_code,
        }
        validate_contract(status, body_obj)
        body = json.dumps(body_obj, sort_keys=True, separators=(",", ":")).encode()
        url = work_order["callback_url"]
        path = urlsplit(url).path or "/"
        headers = {
            "Content-Type": "application/json",
            "X-Mobile-Agent": self.config.agent_id,
            "X-Mobile-Tenant": self.config.tenant_id,
            **sign_request(self.config.device_token, "POST", path, body),
        }
        owns_client = client is None
        client = client or httpx.AsyncClient(follow_redirects=False)
        try:
            return await client.post(url, content=body, headers=headers)
        finally:
            if owns_client:
                await client.aclose()


class CallbackCommand(BaseModel):
    status: Literal["executing", "complete", "failed"]
    result: dict = Field(default_factory=dict)
    error_code: str = Field(default="", max_length=80)


def create_simulator_app(config: SimulatorConfig) -> FastAPI:
    state = SimulatorState(config)
    app = FastAPI(title="Consultant Studio mobile-adapter conformance simulator")
    app.state.simulator = state

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "mode": config.mode, "real_device": False}

    @app.post("/work", status_code=202)
    async def receive_work_order(request: Request) -> dict:
        body = await request.body()
        if len(body) > 128_000:
            raise HTTPException(413, "work order too large")
        value = state.accept(request.url.path, request.headers, body)
        return {"accepted": True, "task_id": value["task_id"]}

    @app.post("/control/tasks/{task_id}/callback")
    async def send_controlled_callback(
        task_id: str,
        command: CallbackCommand,
        x_simulator_control: str = Header(default=""),
    ) -> dict:
        if not hmac.compare_digest(x_simulator_control, config.control_token):
            raise HTTPException(401, "invalid simulator control token")
        try:
            response = await state.send_callback(
                task_id,
                command.status,
                result=command.result,
                error_code=command.error_code,
            )
        except (ValueError, ContractValidationError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"callback_status": response.status_code}

    return app


def main() -> None:
    import uvicorn

    required = {
        "MOBILE_SIMULATOR_AGENT_ID": os.environ.get("MOBILE_SIMULATOR_AGENT_ID", ""),
        "MOBILE_SIMULATOR_TENANT_ID": os.environ.get("MOBILE_SIMULATOR_TENANT_ID", ""),
        "MOBILE_SIMULATOR_DEVICE_TOKEN": os.environ.get(
            "MOBILE_SIMULATOR_DEVICE_TOKEN", ""
        ),
        "MOBILE_SIMULATOR_CONTROL_TOKEN": os.environ.get(
            "MOBILE_SIMULATOR_CONTROL_TOKEN", ""
        ),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError("missing simulator environment: " + ", ".join(missing))
    mode = os.environ.get("MOBILE_SIMULATOR_MODE", "accept")
    if mode not in {"accept", "fail_once", "reject", "unsupported_actions"}:
        raise RuntimeError("invalid MOBILE_SIMULATOR_MODE")
    app = create_simulator_app(
        SimulatorConfig(
            agent_id=required["MOBILE_SIMULATOR_AGENT_ID"],
            tenant_id=required["MOBILE_SIMULATOR_TENANT_ID"],
            device_token=required["MOBILE_SIMULATOR_DEVICE_TOKEN"],
            control_token=required["MOBILE_SIMULATOR_CONTROL_TOKEN"],
            mode=mode,
        )
    )
    uvicorn.run(app, host="127.0.0.1", port=8787, log_level="warning")


if __name__ == "__main__":
    main()
