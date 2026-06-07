"""AI Security Advisor service.

Scans monitoring checks, configs, and recent incident logs to output actionable,
non-jargon recommendations for hardening the monitored sites."""
import logging
from sqlalchemy.orm import Session

from ..config import settings
from ..models import MonitoringCheck, Incident

log = logging.getLogger(__name__)


def generate_recommendations(db: Session) -> list[dict]:
    """Analyze current configuration and state to return security suggestions."""
    recs = []

    # 1. Analyze latest monitoring check
    latest_check = db.query(MonitoringCheck).order_by(MonitoringCheck.ts.desc()).first()
    if latest_check:
        # SSL checks
        if latest_check.ssl_days_left is not None:
            if latest_check.ssl_days_left < 14:
                recs.append({
                    "id": "ssl_critical",
                    "title": "Renew SSL Certificate",
                    "description": f"SSL certificate is expiring in {latest_check.ssl_days_left} days. Renew immediately to avoid site downtime.",
                    "severity": "high",
                    "fix": "Generate and install a new SSL certificate."
                })
            elif latest_check.ssl_days_left < 30:
                recs.append({
                    "id": "ssl_warning",
                    "title": "SSL Certificate Expiring Soon",
                    "description": f"SSL certificate is expiring in {latest_check.ssl_days_left} days.",
                    "severity": "medium",
                    "fix": "Renew the SSL certificate soon."
                })

        # Security headers checks
        if latest_check.missing_headers:
            for h in latest_check.missing_headers:
                h_lower = h.lower()
                title = f"Enable {h} Header"
                severity = "medium"
                if h_lower == "strict-transport-security":
                    desc = "HTTP Strict Transport Security (HSTS) is missing. This exposes users to SSL-stripping man-in-the-middle attacks."
                    fix = "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' header."
                    severity = "high"
                elif h_lower == "content-security-policy":
                    desc = "Content Security Policy (CSP) is missing. This makes the application vulnerable to Cross-Site Scripting (XSS) and data injection."
                    fix = "Define a Content-Security-Policy header restricting script sources."
                    severity = "high"
                elif h_lower == "x-content-type-options":
                    desc = "X-Content-Type-Options header is missing. Browsers may try to MIME-sniff response types, enabling drive-by downloads."
                    fix = "Add 'X-Content-Type-Options: nosniff' header."
                elif h_lower == "x-frame-options":
                    desc = "X-Frame-Options header is missing. The site can be embedded in an iframe, making it vulnerable to Clickjacking attacks."
                    fix = "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
                else:
                    desc = f"Security header {h} is missing from web responses."
                    fix = f"Configure server to include the {h} header."

                recs.append({
                    "id": f"header_{h_lower.replace('-', '_')}",
                    "title": title,
                    "description": desc,
                    "severity": severity,
                    "fix": fix
                })

    # 2. Config checks (Autonomy mode)
    if settings.response_mode != "auto":
        recs.append({
            "id": "response_mode_not_auto",
            "title": "Enable Auto-Remediation",
            "description": f"AEGIS is currently in '{settings.response_mode}' mode. Malicious requests are only logged and not blocked automatically.",
            "severity": "high",
            "fix": "Change RESPONSE_MODE to 'auto' in settings or click 'Secure My Website'."
        })

    # 3. Config checks (Loose Rate limits)
    if settings.rate_limit_max_requests > 100:
        recs.append({
            "id": "rate_limit_loose",
            "title": "Tighten Rate Limiting",
            "description": f"Rate limit is set to {settings.rate_limit_max_requests} requests per minute, which is too high for basic protection.",
            "severity": "medium",
            "fix": "Reduce RATE_LIMIT_MAX_REQUESTS to 50 or lower."
        })

    # 4. Check for active critical incidents
    open_critical = db.query(Incident).filter(Incident.status == "open", Incident.severity == "high").count()
    if open_critical > 0:
        recs.append({
            "id": "open_high_incidents",
            "title": f"Review {open_critical} Critical Incidents",
            "description": f"There are {open_critical} active, unresolved high-severity threats active on the site.",
            "severity": "high",
            "fix": "Inspect the source IPs, approve queued blocks, and mark incidents as resolved."
        })

    # Default if clean
    if not recs:
        recs.append({
            "id": "system_fully_secured",
            "title": "All Protections Optimized",
            "description": "AEGIS Advisor has detected no immediate hardening risks. SSL, headers, and auto-blocking are active.",
            "severity": "low",
            "fix": "No action required. Continue monitoring baseline traffic."
        })

    return recs
