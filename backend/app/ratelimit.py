"""Per-user sliding-window rate limiter.

In-process implementation suitable for a single API node; swap the backing
store for Redis (same interface) when scaling horizontally — see README.
"""
import threading
import time

from fastapi import Depends, HTTPException

from .config import get_settings
from .models import User
from .security import get_current_user

_lock = threading.Lock()
_hits: dict[str, list[float]] = {}


def check_rate(user: User = Depends(get_current_user)) -> User:
    limit = get_settings().rate_limit_per_minute
    now = time.monotonic()
    with _lock:
        window = [t for t in _hits.get(user.id, []) if now - t < 60]
        if len(window) >= limit:
            raise HTTPException(429, "Rate limit exceeded. Try again shortly.")
        window.append(now)
        _hits[user.id] = window
    return user
