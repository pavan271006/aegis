"""Security score + dashboard aggregation.

Security score (0-100) starts at 100 and is reduced by recent open incidents,
discovered vulnerabilities (missing headers, expiring certs), and downtime."""
import datetime as dt

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import Action, Incident, MonitoringCheck


def _recent(days=7):
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)


def compute(db: Session, site_id: int | None = None) -> dict:
    since = _recent()

    open_q = db.query(Incident).filter(Incident.status == "open")
    high_q = db.query(Incident).filter(Incident.created_at >= since, Incident.severity == "high")
    blocked_q = db.query(Action).filter(Action.type == "block_ip", Action.status.like("applied%"))
    mon_q = db.query(MonitoringCheck)
    if site_id:
        open_q = open_q.filter(Incident.site_id == site_id)
        high_q = high_q.filter(Incident.site_id == site_id)
        blocked_q = blocked_q.join(Incident, Action.incident_id == Incident.id).filter(Incident.site_id == site_id)
        mon_q = mon_q.filter(MonitoringCheck.site_id == site_id)

    open_incidents = open_q.count()
    high_recent = high_q.count()
    threats_blocked = blocked_q.count()

    latest = mon_q.order_by(MonitoringCheck.ts.desc()).first()
    missing_headers = len(latest.missing_headers) if latest and latest.missing_headers else 0
    ssl_soon = 1 if (latest and latest.ssl_days_left is not None and latest.ssl_days_left < 21) else 0
    down = 1 if (latest and latest.up is False) else 0
    vulns = missing_headers + ssl_soon

    score = 100
    score -= min(40, open_incidents * 8)
    score -= min(20, high_recent * 5)
    score -= min(20, vulns * 4)
    score -= down * 15
    score = max(0, score)

    health = "healthy"
    if down:
        health = "site down"
    elif open_incidents or high_recent:
        health = "under attack"
    elif vulns:
        health = "needs hardening"

    return {
        "security_score": score,
        "threats_blocked": threats_blocked,
        "active_incidents": open_incidents,
        "vulnerabilities_found": vulns,
        "system_health": health,
    }
