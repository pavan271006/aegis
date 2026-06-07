"""Responder: decides and executes autonomous remediation, respecting the
configured autonomy mode and a self-protection allowlist. Records an audit
entry for every action."""
import datetime as dt
import ipaddress

from sqlalchemy.orm import Session

from ..config import settings
from ..integrations import cloudflare
from ..models import Action, AuditLog, Allowlist


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


def audit(db: Session, action: str, details: dict, actor: str = "system"):
    db.add(AuditLog(actor=actor, action=action, details=details))


def is_allowlisted(db: Session, ip: str) -> bool:
    """Never block our own infra / office / monitoring."""
    entries = db.query(Allowlist).all()
    for e in entries:
        try:
            if ip == e.value or ipaddress.ip_address(ip) in ipaddress.ip_network(e.value, strict=False):
                return True
        except ValueError:
            if ip == e.value:
                return True
    return False


def respond(db: Session, incident, report: dict) -> list:
    """Returns a list of action summaries (dicts) for the report."""
    rank = {"low": 1, "medium": 2, "high": 3}
    min_sev = rank.get(settings.auto_block_min_severity, 3)
    summaries = []

    if rank.get(incident["severity"], 0) < min_sev:
        audit(db, "no_action", {"ip": incident["source_ip"], "reason": "below threshold"})
        return summaries

    if is_allowlisted(db, incident["source_ip"]):
        audit(db, "skipped_allowlisted", {"ip": incident["source_ip"]})
        return summaries

    mode = settings.response_mode
    expires = _utcnow() + dt.timedelta(hours=settings.block_ttl_hours)
    reason = "+".join(incident["threat_types"])

    if mode == "auto":
        result = cloudflare.block_ip(incident["source_ip"], reason)
        status = "applied" if result["ok"] else ("failed" if cloudflare.configured() else "applied (dry: no CF)")
        verified = cloudflare.verify_block(incident["source_ip"]) if result["ok"] else False
        rule_ref = result.get("rule_id") or ""
    elif mode == "approval":
        status, verified, rule_ref = "pending_approval", False, ""
    else:  # dry-run
        status, verified, rule_ref = "planned (dry-run)", False, ""

    act = Action(
        incident_id=None, type="block_ip", provider="cloudflare", mode=mode,
        status=status, params={"ip": incident["source_ip"], "reason": reason},
        rule_ref=rule_ref, verified=verified, expires_at=expires,
    )
    db.add(act)
    db.flush()
    incident["_action_rows"] = incident.get("_action_rows", []) + [act]
    audit(db, "block_ip", {"ip": incident["source_ip"], "mode": mode, "status": status})
    summaries.append({"type": "block_ip", "provider": "cloudflare", "status": status})

    # --- Rate-limit action ---
    _apply_rate_limit(db, incident, mode, expires, reason, summaries)

    # --- Session revocation action (for credential attacks) ---
    credential_types = {"credential_stuffing", "brute_force", "suspicious_login"}
    if credential_types & set(incident["threat_types"]):
        _apply_session_revoke(db, incident, mode, expires, reason, summaries)

    # --- Autonomous Verification & Rollback Engines ---
    if mode == "auto":
        from ..models import Site
        import httpx
        site = db.get(Site, incident.get("site_id", 1))
        target_url = site.url if site else "https://example.com"
        
        health_ok = True
        try:
            # Check service health (timeout fast to prevent backend blocking)
            r = httpx.get(target_url, timeout=3.0)
            if r.status_code >= 500:
                health_ok = False
        except Exception:
            health_ok = False
            
        if not health_ok:
            # ROLLBACK TRIGGERED: Site broke post-remediation
            for a in incident.get("_action_rows", []):
                if a.type == "block_ip" and a.status == "applied" and a.rule_ref:
                    cloudflare.unblock(a.rule_ref)
                a.status = "rolled_back"
            db.commit()
            
            audit(db, "remediation_rollback", {
                "ip": incident["source_ip"],
                "reason": f"Target site {target_url} failed health checks post-remediation"
            })
            
            from ..integrations import telegram
            telegram.send(
                f"⚠️ SECURITY ROLLBACK TRIGGERED\n"
                f"Action against {incident['source_ip']} broke site health on {target_url}.\n"
                f"Auto-reverted all IP blocks/remediation policies."
            )
            
            summaries = [{"type": s["type"], "provider": s["provider"], "status": "rolled_back"} for s in summaries]
        else:
            # Health check passed -> mark actions verified
            for a in incident.get("_action_rows", []):
                a.verified = True
            db.commit()

    return summaries


def _apply_rate_limit(db: Session, incident, mode, expires, reason, summaries):
    """Add a rate_limit action."""
    from . import rate_limiter

    status = "applied" if mode == "auto" else (
        "pending_approval" if mode == "approval" else "planned (dry-run)")

    if mode == "auto":
        rate_limiter.check_rate(incident["source_ip"])  # register the hit

    act = Action(
        incident_id=None, type="rate_limit", provider="internal", mode=mode,
        status=status, params={"ip": incident["source_ip"], "reason": reason},
        rule_ref="", verified=False, expires_at=expires,
    )
    db.add(act)
    db.flush()
    incident["_action_rows"] = incident.get("_action_rows", []) + [act]
    audit(db, "rate_limit", {"ip": incident["source_ip"], "mode": mode, "status": status})
    summaries.append({"type": "rate_limit", "provider": "internal", "status": status})


def _apply_session_revoke(db: Session, incident, mode, expires, reason, summaries):
    """Add a session_revoke action for credential-based attacks."""
    from . import sessions

    status = "applied" if mode == "auto" else (
        "pending_approval" if mode == "approval" else "planned (dry-run)")

    if mode == "auto":
        sessions.revoke_sessions(incident["source_ip"], reason, db=db)

    act = Action(
        incident_id=None, type="session_revoke", provider="internal", mode=mode,
        status=status, params={"ip": incident["source_ip"], "reason": reason},
        rule_ref="", verified=False, expires_at=expires,
    )
    db.add(act)
    db.flush()
    incident["_action_rows"] = incident.get("_action_rows", []) + [act]
    audit(db, "session_revoke", {"ip": incident["source_ip"], "mode": mode, "status": status})
    summaries.append({"type": "session_revoke", "provider": "internal", "status": status})


def expire_blocks(db: Session) -> list:
    """Roll back: remove blocks past TTL. Returns unblocked IPs."""
    now = _utcnow()
    expired = (
        db.query(Action)
        .filter(Action.type == "block_ip", Action.status.like("applied%"),
                Action.expires_at <= now)
        .all()
    )
    unblocked = []
    for a in expired:
        if a.rule_ref:
            cloudflare.unblock(a.rule_ref)
        a.status = "expired"
        unblocked.append((a.params or {}).get("ip"))
        audit(db, "expire_block", {"ip": (a.params or {}).get("ip"), "rule": a.rule_ref})
    if unblocked:
        db.commit()
    return [ip for ip in unblocked if ip]
