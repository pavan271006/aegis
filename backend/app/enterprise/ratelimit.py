"""Redis-backed rate limiting.

- A reusable sliding-window limiter (atomic via a small Lua script).
- A strict per-account + per-IP throttle for the auth endpoints (anti brute-force
  for the console itself — the thing the legacy build lacked)."""
import time

import redis
from fastapi import HTTPException, Request, status

from .settings import get_settings

_r = redis.Redis.from_url(get_settings().redis_url, decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0)

# Atomic sliding-window counter: returns the current count within the window.
_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
redis.call('ZADD', key, now, now .. ':' .. math.random())
redis.call('EXPIRE', key, window)
return redis.call('ZCARD', key)
"""
_script = _r.register_script(_LUA)


def hit(key: str, limit: int, window_seconds: int) -> bool:
    """Return True if the call is allowed (under limit)."""
    try:
        count = _script(keys=[key], args=[int(time.time()), window_seconds])
        return int(count) <= limit
    except redis.RedisError:
        return True  # fail open on Redis outage; alert separately


def limit(limit_: int, window_seconds: int, scope: str = "ip"):
    """Generic dependency: throttle by client IP (or override scope)."""
    def dependency(request: Request):
        ident = request.client.host if scope == "ip" else scope
        if not hit(f"rl:{scope}:{ident}:{request.url.path}", limit_, window_seconds):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded",
                                headers={"Retry-After": str(window_seconds)})
    return dependency


def auth_throttle(email: str, ip: str) -> None:
    """Call inside login. Blocks brute force on both the account and the source IP."""
    s = get_settings()
    if not hit(f"rl:login:email:{email.lower()}", s.max_failed_logins * 3, 300):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; slow down")
    if not hit(f"rl:login:ip:{ip}", 30, 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts from this IP")
