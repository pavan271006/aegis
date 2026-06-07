"""Monitoring: uptime, SSL expiry, security headers, response time, API
availability. Pure standard library + httpx."""
import datetime as dt
import socket
import ssl
import time
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from ..models import MonitoringCheck, Site

IMPORTANT_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "referrer-policy",
]


def cert_days_left(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    host, port = parsed.hostname, parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc)
        return (exp - dt.datetime.now(dt.timezone.utc)).days
    except Exception:  # noqa: BLE001
        return None


def check_site(db: Session, site: Site) -> dict:
    start = time.time()
    up, status, headers = False, None, {}
    try:
        r = httpx.get(site.url, timeout=15, follow_redirects=True,
                      headers={"User-Agent": "AEGIS-Lite/1.0"})
        status, up = r.status_code, 200 <= r.status_code < 400
        headers = {k.lower(): v for k, v in r.headers.items()}
    except Exception:  # noqa: BLE001
        pass
    ms = int((time.time() - start) * 1000)
    missing = [h for h in IMPORTANT_HEADERS if h not in headers]
    days = cert_days_left(site.url)

    check = MonitoringCheck(site_id=site.id, up=up, status_code=status,
                            response_ms=ms, ssl_days_left=days, missing_headers=missing)
    db.add(check)
    db.commit()
    return {"up": up, "status": status, "response_ms": ms,
            "ssl_days_left": days, "missing_headers": missing}
