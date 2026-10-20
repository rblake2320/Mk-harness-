"""HTTP client for the Rust action kernel's internal API.

Fault barrier semantics (deliberate, tested in tests/test_agent_ops.py):

* Kernel URL or signing key not configured  → KernelUnavailable (503)
* Connect / read timeout / connection reset → KernelUnavailable (503)
* Any HTTP answer from the kernel            → returned as-is (status + body);
  policy denials (403), replays (401), conflicts (409), 422, 5xx are all the
  kernel's verdicts and are surfaced unchanged — the app never "repairs" them.

There is no retry on writes: every write carries a single-use ``jti`` and the
kernel's own idempotency keys make a client retry pointless at best and a
duplicate-approval attempt at worst. Reads (GET) are retried once on transport
failure only.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import httpx

from ..config import get_settings
from .assertions import AssertionMinter, build_minter

INTERNAL_PREFIX = "/internal/v1"


class KernelError(Exception):
    """Base for kernel boundary errors."""


class KernelUnavailable(KernelError):
    """The kernel cannot be reached or is not configured. Maps to HTTP 503."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class KernelResponse:
    status_code: int
    body: Any
    request_id: str


class KernelClient:
    def __init__(self, base_url: str, minter: AssertionMinter | None, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.minter = minter
        self.timeout = timeout

    # -- configuration state -------------------------------------------------
    @property
    def configured(self) -> bool:
        return bool(self.base_url) and self.minter is not None

    def _require_configured(self) -> AssertionMinter:
        if not self.base_url:
            raise KernelUnavailable(
                "KERNEL_NOT_CONFIGURED", "RUST_ACTION_KERNEL_URL is not set")
        if self.minter is None:
            raise KernelUnavailable(
                "KERNEL_NOT_CONFIGURED", "KERNEL_ASSERTION_PRIVATE_KEY is not set")
        return self.minter

    # -- the one call site ---------------------------------------------------
    async def call(
        self,
        method: str,
        path: str,
        *,
        user_id: str,
        tenant_id: str,
        roles: list[str],
        session_id: str,
        json: Any | None = None,
        request_id: str | None = None,
    ) -> KernelResponse:
        minter = self._require_configured()
        rid = request_id or str(uuid.uuid4())
        token = minter.mint(
            user_id=user_id, tenant_id=tenant_id, roles=roles,
            session_id=session_id, request_id=rid,
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Request-Id": rid,
            "Accept": "application/json",
        }
        url = f"{self.base_url}{INTERNAL_PREFIX}{path}"
        attempts = 2 if method.upper() == "GET" else 1
        last_exc: Exception | None = None
        for _ in range(attempts):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as http:
                    r = await http.request(method.upper(), url, headers=headers, json=json)
                return KernelResponse(
                    status_code=r.status_code, body=_json_or_none(r), request_id=rid)
            except httpx.TransportError as e:  # connect, read, write, pool, timeouts
                last_exc = e
        raise KernelUnavailable(
            "KERNEL_UNREACHABLE",
            f"action kernel unreachable: {type(last_exc).__name__}")

    async def health_ready(self) -> KernelResponse:
        """Unauthenticated readiness probe; used by /api/agent-ops/health."""
        if not self.base_url:
            raise KernelUnavailable(
                "KERNEL_NOT_CONFIGURED", "RUST_ACTION_KERNEL_URL is not set")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as http:
                r = await http.get(f"{self.base_url}/health/ready")
            return KernelResponse(status_code=r.status_code, body=_json_or_none(r),
                                  request_id="")
        except httpx.TransportError as e:
            raise KernelUnavailable(
                "KERNEL_UNREACHABLE", f"action kernel unreachable: {type(e).__name__}")


def _json_or_none(r: httpx.Response) -> Any:
    if r.status_code == 204 or not r.content:
        return None
    try:
        return r.json()
    except ValueError:
        # The kernel always speaks JSON; a non-JSON body is a proxy/misroute
        # and is reported as an opaque upstream failure, never echoed.
        return {"code": "KERNEL_BAD_RESPONSE", "title": "Non-JSON response from kernel"}


@lru_cache
def get_kernel_client() -> KernelClient:
    s = get_settings()
    return KernelClient(
        base_url=s.rust_action_kernel_url,
        minter=build_minter(s.kernel_assertion_kid, s.kernel_assertion_private_key),
        timeout=s.kernel_timeout_seconds,
    )
