"""Shared Redis singleton — used by rate limiter and brute-force protection.

Falls back to None when REDIS_URL is not set or Redis is unreachable.
Call get_redis() on each use; the first call initialises the connection pool.
"""
import logging
import threading

logger = logging.getLogger("mk.cache")

_client = None
_init_lock = threading.Lock()
_initialised = False


def get_redis():
    """Return a sync Redis client or None (in-process fallback active)."""
    global _client, _initialised
    if _initialised:
        return _client
    with _init_lock:
        if _initialised:
            return _client
        _initialised = True
        url = ""
        try:
            from .config import get_settings
            url = get_settings().redis_url
            if not url:
                return None
            import redis as _redis
            client = _redis.from_url(url, socket_connect_timeout=1, decode_responses=True)
            client.ping()
            _client = client
        except Exception as exc:
            _client = None
            if url:
                # REDIS_URL was configured but unusable: rate limiting and
                # brute-force lockout are now per-process only. In a
                # multi-replica deployment that is a real security downgrade —
                # make it impossible to miss in the logs.
                logger.error(
                    "REDIS_URL is set but Redis is unavailable (%s). "
                    "Falling back to in-process rate limiting — NOT safe "
                    "across multiple API replicas.", exc,
                )
    return _client


def reset_for_tests() -> None:
    """Force re-initialisation — called from test fixtures that inject a fake Redis."""
    global _client, _initialised
    _client = None
    _initialised = False
