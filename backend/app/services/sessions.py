"""Session revocation adapter.

Manages session revocation for compromised accounts.  Uses Redis to maintain a
revocation list.  Designed as an integration point for future session stores
(e.g. JWT blacklists, server-side session invalidation)."""
import datetime as dt
import logging

from sqlalchemy.orm import Session

from ..config import settings
from ..models import AuditLog

log = logging.getLogger(__name__)


_redis_failed = False


def _get_redis():
    """Best-effort Redis client."""
    global _redis_failed
    if _redis_failed:
        return None
    try:
        import redis
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=0.5)
        client.ping()
        return client
    except Exception:  # noqa: BLE001
        _redis_failed = True
        return None


def revoke_sessions(ip: str, reason: str, db: Session | None = None) -> dict:
    """Invalidate all sessions associated with *ip*.

    Adds the IP to a Redis-backed revocation set and records the action in the
    audit log when a DB session is provided.

    Returns a summary dict with status information.
    """
    revoked_at = dt.datetime.now(dt.timezone.utc).isoformat()
    result = {
        "ip": ip,
        "reason": reason,
        "revoked_at": revoked_at,
        "redis_recorded": False,
    }

    client = _get_redis()
    if client is not None:
        try:
            key = f"aegis:revoked_sessions:{ip}"
            client.hset(key, mapping={
                "reason": reason,
                "revoked_at": revoked_at,
            })
            client.expire(key, 86400 * 7)  # keep for 7 days
            # Also add to a global revocation set for quick membership checks
            client.sadd("aegis:revoked_ips", ip)
            result["redis_recorded"] = True
        except Exception:  # noqa: BLE001
            log.warning("Failed to record session revocation in Redis for %s", ip)
    else:
        log.warning("Redis unavailable — session revocation for %s logged only", ip)

    # Record in audit log
    if db is not None:
        db.add(AuditLog(
            actor="system",
            action="revoke_sessions",
            details={"ip": ip, "reason": reason},
        ))
        db.flush()

    log.info("Sessions revoked for IP %s: %s", ip, reason)
    return result


def is_revoked(ip: str) -> bool:
    """Check whether *ip* has been revoked."""
    client = _get_redis()
    if client is None:
        return False
    try:
        return client.sismember("aegis:revoked_ips", ip)
    except Exception:  # noqa: BLE001
        return False
