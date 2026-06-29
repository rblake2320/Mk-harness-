"""Per-user sliding-window rate limiter.

Uses Redis sorted sets when REDIS_URL is set — multi-replica safe.
Falls back to an in-process dict when Redis is unavailable (dev / tests).
"""
import threading
import time

from fastapi import Depends, HTTPException

from .cache import get_redis
from .config import get_settings
from .models import User
from .security import get_current_user

_lock = threading.Lock()
_hits: dict[str, list[float]] = {}


def check_rate(user: User = Depends(get_current_user)) -> User:
    limit = get_settings().rate_limit_per_minute
    r = get_redis()

    if r is not None:
        now = time.time()
        key = f"rl:{user.id}"
        pipe = r.pipeline()
        pipe.zremrangebyscore(key, 0, now - 60)
        pipe.zadd(key, {f"{now}": now})
        pipe.zcard(key)
        pipe.expire(key, 120)
        results = pipe.execute()
        count = int(results[2])
        if count > limit:
            raise HTTPException(429, "Rate limit exceeded. Try again shortly.")
        return user

    # In-process fallback (single-node / test environment).
    mono = time.monotonic()
    with _lock:
        window = [t for t in _hits.get(user.id, []) if mono - t < 60]
        if len(window) >= limit:
            raise HTTPException(429, "Rate limit exceeded. Try again shortly.")
        window.append(mono)
        _hits[user.id] = window
    return user
