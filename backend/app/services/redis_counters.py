"""Redis-backed counters for cross-batch behavioral detection.

Provides persistent counters (failed auth attempts, request rates) that survive
across ingest batches and process restarts.  Falls back gracefully to 0 if Redis
is unavailable so the rest of the pipeline is never blocked."""
import logging
from typing import Optional

import redis

from ..config import settings

log = logging.getLogger(__name__)

_pool: Optional[redis.ConnectionPool] = None
_redis_failed: bool = False


def _get_client() -> Optional[redis.Redis]:
    """Return a Redis client, or None if unavailable."""
    global _pool, _redis_failed
    if _redis_failed:
        return None
    try:
        if _pool is None:
            _pool = redis.ConnectionPool.from_url(
                settings.redis_url, decode_responses=True, socket_connect_timeout=0.5
            )
        client = redis.Redis(connection_pool=_pool)
        client.ping()
        return client
    except Exception:  # noqa: BLE001
        log.warning("Redis unavailable at %s — falling back to 0", settings.redis_url)
        _redis_failed = True
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def incr_failed_auth(ip: str, ttl: int = 3600) -> int:
    """Increment failed-auth counter for *ip*, auto-expire after *ttl* seconds."""
    key = f"aegis:failed_auth:{ip}"
    client = _get_client()
    if client is None:
        return 0
    try:
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl)
        result = pipe.execute()
        return int(result[0])
    except Exception:  # noqa: BLE001
        log.warning("Redis incr_failed_auth error for %s", ip)
        return 0


def incr_requests(ip: str, ttl: int = 300) -> int:
    """Increment per-IP request counter (5-min default window)."""
    key = f"aegis:requests:{ip}"
    client = _get_client()
    if client is None:
        return 0
    try:
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl)
        result = pipe.execute()
        return int(result[0])
    except Exception:  # noqa: BLE001
        log.warning("Redis incr_requests error for %s", ip)
        return 0


def get_counter(key: str) -> int:
    """Read an arbitrary counter value."""
    client = _get_client()
    if client is None:
        return 0
    try:
        val = client.get(key)
        return int(val) if val is not None else 0
    except Exception:  # noqa: BLE001
        return 0


def reset_counter(key: str) -> None:
    """Delete a counter key."""
    client = _get_client()
    if client is None:
        return
    try:
        client.delete(key)
    except Exception:  # noqa: BLE001
        log.warning("Redis reset_counter error for %s", key)


def get_rate(ip: str, window_seconds: int = 60) -> int:
    """Sliding-window request rate for *ip*.

    Uses a simple sorted-set approach: each request adds a timestamped member,
    old members outside the window are trimmed, and the remaining count is
    returned.
    """
    import time

    key = f"aegis:rate:{ip}"
    client = _get_client()
    if client is None:
        return 0
    try:
        now = time.time()
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, "-inf", now - window_seconds)
        pipe.zadd(key, {f"{now}": now})
        pipe.zcard(key)
        pipe.expire(key, window_seconds + 10)
        result = pipe.execute()
        return int(result[2])
    except Exception:  # noqa: BLE001
        log.warning("Redis get_rate error for %s", ip)
        return 0
