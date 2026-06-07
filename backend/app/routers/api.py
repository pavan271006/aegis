"""All API routers in one module for simplicity (single-founder codebase)."""
import datetime as dt
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from starlette.status import HTTP_401_UNAUTHORIZED
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import require_key
from ..integrations import crowdsec
from ..models import Action, Allowlist, Honeypot, Incident, Site, AuditLog, Event, MonitoringCheck
from ..schemas import (
    DashboardOut, IncidentOut, IngestRequest, IngestResult, SiteIn,
    AuditLogOut, MonitoringCheckOut, AllowlistOut, HoneypotOut, SiteOut,
    QuarantineOut, StatsOut, UserOut, LoginRequest, TokenResponse,
    VulnerabilityOut, PostureTrendOut
)
from ..services import ingest as ingest_svc
from ..services import monitoring as mon_svc
from ..services import responder as responder_svc
from ..services import scoring
from ..services import quarantine as quarantine_svc
from ..services import report_export
from ..services import advisor as advisor_svc
from ..services import hardening as hardening_svc
from ..services import threat_feed as threat_feed_svc
from ..services import auth as auth_svc
from ..services import backups as backups_svc
from ..services import traffic_sim as traffic_sim_svc
from ..services import bug_hunter as bug_hunter_svc

ingest_router = APIRouter(prefix="/api/ingest", tags=["ingest"])
incidents_router = APIRouter(prefix="/api/incidents", tags=["incidents"])
dashboard_router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
monitoring_router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])



# ---- Ingest (the closed loop) ----
@ingest_router.post("", response_model=IngestResult, dependencies=[Depends(require_key)])
def ingest_events(body: IngestRequest, db: Session = Depends(get_db)):
    return ingest_svc.ingest(db, body.site_id, body.events, body.log_lines)


# Honeypot trap: ANY request to a registered honeypot path is auto-malicious.
@ingest_router.get("/honeypot")
def honeypot_trap(path: str, ip: str, db: Session = Depends(get_db)):
    from ..schemas import EventIn
    res = ingest_svc.ingest(db, 1, [EventIn(ip=ip, path=path, status=200, source="honeypot")], [])
    return {"trapped": True, **res}


# Ingest - Upload safety check
@ingest_router.post("/upload", dependencies=[Depends(require_key)])
async def upload_check(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    size = len(content)
    chk = quarantine_svc.check_upload(file.filename, file.content_type or "", size)
    if not chk["safe"]:
        res = quarantine_svc.quarantine_file(
            db, file.filename, content, reason=chk["reason"],
            content_type=file.content_type or "", uploaded_by_ip=""
        )
        return {"safe": False, "quarantined": True, "reason": chk["reason"], **res}
    return {"safe": True, "quarantined": False, "reason": ""}


# ---- Incidents ----
@incidents_router.get("", response_model=list[IncidentOut])
def list_incidents(status: str | None = None, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(Incident).order_by(Incident.created_at.desc())
    if status:
        q = q.filter(Incident.status == status)
    return q.limit(limit).all()


@incidents_router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc


@incidents_router.post("/{incident_id}/resolve")
def resolve_incident(incident_id: int, db: Session = Depends(get_db),
                     user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    inc.status = "resolved"
    responder_svc.audit(db, "resolve_incident", {"id": incident_id}, actor=user.email)
    db.commit()
    return {"ok": True}


# Approve a queued action (when RESPONSE_MODE=approval)
@incidents_router.post("/actions/{action_id}/approve")
def approve_action(action_id: int, db: Session = Depends(get_db),
                   user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    from ..integrations import cloudflare
    act = db.get(Action, action_id)
    if not act:
        raise HTTPException(404, "action not found")
    ip = (act.params or {}).get("ip")
    result = cloudflare.block_ip(ip, (act.params or {}).get("reason", ""))
    act.status = "applied" if result["ok"] else "failed"
    act.rule_ref = result.get("rule_id") or ""
    act.verified = cloudflare.verify_block(ip) if result["ok"] else False
    responder_svc.audit(db, "approve_action", {"id": action_id, "ip": ip}, actor=user.email)
    db.commit()
    return {"ok": result["ok"], "status": act.status}


# Incident Report HTML Export
@incidents_router.get("/{incident_id}/report.html", response_class=HTMLResponse)
def export_incident_report(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    html_content = report_export.generate_html(inc)
    return HTMLResponse(content=html_content, status_code=200)


# ---- Dashboard ----
@dashboard_router.get("", response_model=DashboardOut)
def dashboard(db: Session = Depends(get_db)):
    stats = scoring.compute(db)
    recent = db.query(Incident).order_by(Incident.created_at.desc()).limit(10).all()
    return DashboardOut(recent_reports=recent, **stats)


@dashboard_router.get("/stats", response_model=StatsOut)
def dashboard_stats(db: Session = Depends(get_db)):
    now = dt.datetime.now(dt.timezone.utc)
    day_ago = now - dt.timedelta(hours=24)
    seven_days_ago = now - dt.timedelta(days=7)
    
    total_events = db.query(Event).count()
    total_incidents = db.query(Incident).count()
    total_blocked = db.query(Action).filter(Action.type == "block_ip", Action.status.like("applied%")).count()
    
    events_24h = db.query(Event).filter(Event.ts >= day_ago).count()
    incidents_24h = db.query(Incident).filter(Incident.created_at >= day_ago).count()
    
    # Severity distribution
    severity_distribution = {"high": 0, "medium": 0, "low": 0}
    sev_rows = db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all()
    for sev, count in sev_rows:
        if sev in severity_distribution:
            severity_distribution[sev] = count
            
    # Top threat types (aggregated in python from last 7 days)
    recent_incidents = db.query(Incident).filter(Incident.created_at >= seven_days_ago).all()
    threat_counts = {}
    for inc in recent_incidents:
        for t in (inc.threat_types or []):
            threat_counts[t] = threat_counts.get(t, 0) + 1
    top_threat_types = sorted([{"type": k, "count": v} for k, v in threat_counts.items()], key=lambda x: x["count"], reverse=True)
    
    # Top source IPs
    ip_rows = db.query(Incident.source_ip, func.count(Incident.id)).group_by(Incident.source_ip).order_by(func.count(Incident.id).desc()).limit(10).all()
    top_source_ips = [{"ip": ip, "count": count} for ip, count in ip_rows]
    
    # Incidents by day (last 7 days)
    day_counts = {}
    for i in range(7):
        d = (now - dt.timedelta(days=i)).date()
        day_counts[d.isoformat()] = 0
    for inc in recent_incidents:
        d_str = inc.created_at.date().isoformat()
        if d_str in day_counts:
            day_counts[d_str] += 1
    incidents_by_day = sorted([{"date": k, "count": v} for k, v in day_counts.items()], key=lambda x: x["date"])
    
    return StatsOut(
        total_events=total_events,
        total_incidents=total_incidents,
        total_blocked=total_blocked,
        events_24h=events_24h,
        incidents_24h=incidents_24h,
        top_threat_types=top_threat_types,
        top_source_ips=top_source_ips,
        severity_distribution=severity_distribution,
        incidents_by_day=incidents_by_day
    )


# ---- Monitoring ----
@monitoring_router.post("/check/{site_id}")
def run_check(site_id: int, db: Session = Depends(get_db),
              user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "site not found")
    return mon_svc.check_site(db, site)


@monitoring_router.get("/history/{site_id}", response_model=list[MonitoringCheckOut])
def get_monitoring_history(site_id: int, db: Session = Depends(get_db)):
    return db.query(MonitoringCheck).filter(MonitoringCheck.site_id == site_id).order_by(MonitoringCheck.ts.desc()).limit(50).all()


@monitoring_router.post("/check-all")
def check_all_sites(db: Session = Depends(get_db),
                    user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    sites = db.query(Site).all()
    results = []
    for site in sites:
        res = mon_svc.check_site(db, site)
        results.append({"site_id": site.id, **res})
    return {"checked": len(sites), "results": results}


@monitoring_router.get("/crowdsec")
def crowdsec_decisions():
    return crowdsec.pull_decisions()


# ---- Admin: sites, allowlist, honeypots ----
@admin_router.get("/sites", response_model=list[SiteOut])
def list_sites(db: Session = Depends(get_db)):
    return db.query(Site).all()


@admin_router.post("/sites")
def add_site(body: SiteIn, db: Session = Depends(get_db),
             user = Depends(auth_svc.check_role(["admin"]))):
    s = Site(name=body.name, url=body.url, cf_zone_id=body.cf_zone_id)
    db.add(s)
    db.commit()
    return {"id": s.id}


@admin_router.delete("/sites/{site_id}")
def delete_site(site_id: int, db: Session = Depends(get_db),
                user = Depends(auth_svc.check_role(["admin"]))):
    item = db.get(Site, site_id)
    if not item:
        raise HTTPException(404, "Site not found")
    db.delete(item)
    db.commit()
    return {"ok": True}


@admin_router.get("/allowlist", response_model=list[AllowlistOut])
def list_allowlist(db: Session = Depends(get_db)):
    return db.query(Allowlist).all()


@admin_router.post("/allowlist")
def add_allow(value: str, note: str = "", db: Session = Depends(get_db),
              user = Depends(auth_svc.check_role(["admin"]))):
    db.add(Allowlist(value=value, note=note))
    db.commit()
    return {"ok": True}


@admin_router.delete("/allowlist/{item_id}")
def delete_allowlist_item(item_id: int, db: Session = Depends(get_db),
                          user = Depends(auth_svc.check_role(["admin"]))):
    item = db.get(Allowlist, item_id)
    if not item:
        raise HTTPException(404, "Allowlist item not found")
    db.delete(item)
    db.commit()
    return {"ok": True}


@admin_router.get("/honeypots", response_model=list[HoneypotOut])
def list_honeypots(db: Session = Depends(get_db)):
    return db.query(Honeypot).all()


@admin_router.post("/honeypots")
def add_honeypot(path: str, note: str = "", db: Session = Depends(get_db),
                 user = Depends(auth_svc.check_role(["admin"]))):
    db.add(Honeypot(path=path, note=note))
    db.commit()
    return {"ok": True}


@admin_router.delete("/honeypots/{item_id}")
def delete_honeypot_item(item_id: int, db: Session = Depends(get_db),
                         user = Depends(auth_svc.check_role(["admin"]))):
    item = db.get(Honeypot, item_id)
    if not item:
        raise HTTPException(404, "Honeypot item not found")
    db.delete(item)
    db.commit()
    return {"ok": True}


# ---- Admin: Audit Log ----
@admin_router.get("/audit-log", response_model=list[AuditLogOut])
def list_audit_log(db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.ts.desc()).limit(100).all()


# ---- Admin: Quarantine ----
@admin_router.get("/quarantine", response_model=list[QuarantineOut])
def get_quarantine(db: Session = Depends(get_db)):
    return quarantine_svc.list_quarantined(db)


@admin_router.post("/quarantine/{item_id}/release")
def release_quarantined_file(item_id: int, db: Session = Depends(get_db),
                             user = Depends(auth_svc.check_role(["admin"]))):
    res = quarantine_svc.release_file(db, item_id)
    if not res.get("ok"):
        raise HTTPException(404, res.get("detail", "file not found"))
    return res


@admin_router.delete("/quarantine/{item_id}")
def delete_quarantined_file(item_id: int, db: Session = Depends(get_db),
                            user = Depends(auth_svc.check_role(["admin"]))):
    res = quarantine_svc.delete_quarantined(db, item_id)
    if not res.get("ok"):
        raise HTTPException(404, res.get("detail", "file not found"))
    return res


def _redact(url: str) -> str:
    """Hide any embedded credentials in a connection URL before returning it."""
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(url)
        if parts.password or parts.username:
            host = parts.hostname or ""
            if parts.port:
                host = f"{host}:{parts.port}"
            netloc = f"***@{host}" if host else "***"
            return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
        return url
    except Exception:
        return "***"


# ---- Admin: Config ----
@admin_router.get("/config")
def get_config(user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    return {
        "app_name": settings.app_name,
        "database_url": _redact(settings.database_url),
        "redis_url": _redact(settings.redis_url),
        "response_mode": settings.response_mode,
        "block_ttl_hours": settings.block_ttl_hours,
        "auto_block_min_severity": settings.auto_block_min_severity,
        "cf_api_token": "configured" if settings.cf_api_token else "",
        "cf_zone_id": settings.cf_zone_id,
        "crowdsec_url": settings.crowdsec_url,
        "crowdsec_api_key": "configured" if settings.crowdsec_api_key else "",
        "telegram_bot_token": "configured" if settings.telegram_bot_token else "",
        "telegram_chat_id": settings.telegram_chat_id,
        "geoip_enabled": settings.geoip_enabled,
        "failed_auth_threshold": settings.failed_auth_threshold,
        "scan_404_threshold": settings.scan_404_threshold,
        "rate_z_threshold": settings.rate_z_threshold,
        "monitoring_interval_minutes": settings.monitoring_interval_minutes,
        "digest_cron": settings.digest_cron,
        "rate_limit_window_seconds": settings.rate_limit_window_seconds,
        "rate_limit_max_requests": settings.rate_limit_max_requests,
        "quarantine_dir": settings.quarantine_dir,
        "max_upload_size_mb": settings.max_upload_size_mb,
        "allowed_upload_extensions": settings.allowed_upload_extensions,
        "wazuh_url": settings.wazuh_url,
    }


@admin_router.post("/config")
def update_config(body: dict, user = Depends(auth_svc.check_role(["admin"]))):
    for k, v in body.items():
        if hasattr(settings, k):
            setattr(settings, k, v)
    return {"ok": True}


# ---- Admin: AI Advisor ----
@admin_router.get("/advisor")
def get_advisor_recommendations(db: Session = Depends(get_db)):
    return advisor_svc.generate_recommendations(db)


# ---- Admin: Hardening ----
@admin_router.post("/harden")
def trigger_hardening(db: Session = Depends(get_db),
                      user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    return hardening_svc.harden_website(db)


# ---- Admin: Threat Feed ----
@admin_router.get("/threat-feed")
def get_threat_feed(db: Session = Depends(get_db)):
    return threat_feed_svc.get_active_feeds(db)


# ---- Authentication Routers ----
@auth_router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    from ..models import User
    user = db.query(User).filter(User.email == body.email, User.is_active == True).first()
    if not user or not auth_svc.verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = auth_svc.create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


@auth_router.get("/me", response_model=UserOut)
def get_me(user = Depends(auth_svc.get_current_user)):
    return user


# ---- Admin: Backup & Recovery ----
@admin_router.get("/backups")
def get_backups(user = Depends(auth_svc.check_role(["admin"]))):
    return backups_svc.list_backups()


@admin_router.post("/backups")
def run_backup(db: Session = Depends(get_db), user = Depends(auth_svc.check_role(["admin"]))):
    res = backups_svc.create_backup(db)
    if not res.get("ok"):
        raise HTTPException(status_code=500, detail=res.get("detail", "Backup failed"))
    return res


@admin_router.post("/backups/{name}/restore")
def restore_backup(name: str, db: Session = Depends(get_db), user = Depends(auth_svc.check_role(["admin"]))):
    res = backups_svc.restore_backup(db, name)
    if not res.get("ok"):
        raise HTTPException(status_code=500, detail=res.get("detail", "Restore failed"))
    return res


@admin_router.delete("/backups/{name}")
def delete_backup(name: str, db: Session = Depends(get_db), user = Depends(auth_svc.check_role(["admin"]))):
    res = backups_svc.delete_backup(db, name)
    if not res.get("ok"):
        raise HTTPException(status_code=500, detail=res.get("detail", "Delete failed"))
    return res


# ---- Admin: Traffic Simulator ----
@admin_router.post("/simulator/start")
def start_simulator(mode: str = "clean", user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    traffic_sim_svc.start_simulator(mode)
    return {"ok": True, "status": traffic_sim_svc.get_status()}


@admin_router.post("/simulator/stop")
def stop_simulator(user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    traffic_sim_svc.stop_simulator()
    return {"ok": True, "status": traffic_sim_svc.get_status()}


@admin_router.get("/simulator/status")
def get_simulator_status(user = Depends(auth_svc.get_current_user)):
    return traffic_sim_svc.get_status()


# ---- Admin: Bug Hunter Scanner ----
@admin_router.post("/scanner/trigger")
def trigger_scanner(site_id: int = 1, user = Depends(auth_svc.check_role(["admin", "analyst"]))):
    bug_hunter_svc.start_scan(site_id)
    return {"ok": True, "status": bug_hunter_svc.get_status()}


@admin_router.get("/scanner/status")
def get_scanner_status(user = Depends(auth_svc.get_current_user)):
    return bug_hunter_svc.get_status()


@admin_router.get("/scanner/vulnerabilities", response_model=list[VulnerabilityOut])
def get_vulnerabilities(db: Session = Depends(get_db), user = Depends(auth_svc.get_current_user)):
    from ..models import Vulnerability
    return db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).all()


# ---- Dashboard: Posture Trends ----
@dashboard_router.get("/posture-trends", response_model=list[PostureTrendOut])
def get_posture_trends(db: Session = Depends(get_db), user = Depends(auth_svc.get_current_user)):
    from ..models import PostureTrend
    import datetime as dt
    
    if db.query(PostureTrend).count() == 0:
        now = dt.datetime.now(dt.timezone.utc)
        months = [
            (now - dt.timedelta(days=150), 71),
            (now - dt.timedelta(days=120), 82),
            (now - dt.timedelta(days=90), 91),
            (now - dt.timedelta(days=60), 95),
            (now - dt.timedelta(days=30), 92),
            (now, 95)
        ]
        for t, s in months:
            db.add(PostureTrend(ts=t, score=s))
        db.commit()
        
    return db.query(PostureTrend).order_by(PostureTrend.ts.asc()).all()

