"""FastAPI → Rust action kernel boundary.

This package is the *only* place the application talks to the kernel. It holds
no execution logic of its own: every governed action (outreach, approvals,
consent, suppression, adapter enrollment, kill switches) is forwarded to the
kernel and the kernel's answer is returned verbatim. If the kernel is not
configured or not reachable the caller gets 503 — there is deliberately no
Python fallback path.
"""
from .assertions import AssertionMinter, build_minter
from .client import KernelClient, KernelError, KernelUnavailable, get_kernel_client

__all__ = [
    "AssertionMinter",
    "build_minter",
    "KernelClient",
    "KernelError",
    "KernelUnavailable",
    "get_kernel_client",
]
