"""In-memory (with Redis fallback) sliding-window rate limiter.

Used by the responder as an action type and by the ingest pipeline to throttle
abusive IPs."""
import logging
import time
from collections import defaultdict
from threading import Lock

from ..config import settings

log = logging.getLogger(__name__)

# In-memory fallback when Redis is not available
_lock = Lock()
_buckets: dict[str, list[float]] = defaultdict(list)


def _prune(ip: str, window: int) -> None:
    """Remove timestamps outside the window (must be called under _lock)."""
    cutoff = time.time() - window
    _buckets[ip] = [t for t in _buckets[ip] if t > cutoff]


def _try_redis(ip: str, window: int, limit: int) -> dict | None:
    """Attempt rate check via Redis sorted set.  Returns None if Redis is
    unavailable."""
    try:
        from .redis_counters import _get_client
        client = _get_client()
        if client is None:
            return None
        now = time.time()
        key = f"aegis:ratelimit:{ip}"
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, "-inf", now - window)
        pipe.zadd(key, {f"{now}": now})
        pipe.zcard(key)
        pipe.expire(key, window + 10)
        result = pipe.execute()
        current = int(result[2])
        return {"allowed": current <= limit, "current": current, "limit": limit}
    except Exception:  # noqa: BLE001
        return None


def check_rate(ip: str) -> dict:
    """Check whether *ip* is within the rate limit.

    Returns ``{allowed: bool, current: int, limit: int}``.
    """
    window = settings.rate_limit_window_seconds
    limit = settings.rate_limit_max_requests

    # Try Redis first
    redis_result = _try_redis(ip, window, limit)
    if redis_result is not None:
        return redis_result

    # Fallback to in-memory
    with _lock:
        _prune(ip, window)
        _buckets[ip].append(time.time())
        current = len(_buckets[ip])

    return {"allowed": current <= limit, "current": current, "limit": limit}
