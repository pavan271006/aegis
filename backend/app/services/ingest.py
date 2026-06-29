"""Ingest service — the closed loop.

normalize events -> detect -> learn baseline -> investigate -> respond ->
persist incident + report -> alert.
"""
import datetime as dt
import re

from sqlalchemy.orm import Session

from ..config import settings
from ..detection import engine
from ..integrations import geoip, telegram
from ..investigation import build_report
from ..models import Event, Honeypot, Incident, Site
from . import responder

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+ '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

# persisted behavioral baseline lives in a tiny config table-free way: a module
# global is fine for a single-founder single-process deploy; for multi-worker,
# move this to Redis. Kept simple on purpose.
_BASELINE = {"mean_reqs_per_ip": 0.0, "var_reqs_per_ip": 0.0, "runs": 0}


def parse_log_line(line: str):
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    return {"ip": d["ip"], "method": d["method"], "path": d["path"],
            "status": int(d["status"]), "user_agent": d["ua"], "ts": None,
            "source": "log"}


def normalize(events_in, log_lines):
    events = []
    for e in events_in:
        events.append({"ip": e.ip, "method": e.method, "path": e.path,
                       "status": e.status, "user_agent": e.user_agent,
                       "ts": e.ts, "source": e.source})
    for line in log_lines:
        parsed = parse_log_line(line)
        if parsed:
            events.append(parsed)
    return events


def ingest(db: Session, site_id: int, events_in, log_lines) -> dict:
    import os
    from fastapi import HTTPException
    from sqlalchemy import text
    if os.getenv("AEGIS_ENTERPRISE") == "1":
        if "sqlite" not in db.bind.url.drivername:
            db.execute(text("SET LOCAL app.current_org = '00000000-0000-0000-0000-000000000000'"))
        site = db.get(Site, site_id)
        if not site:
            raise HTTPException(404, "site not found")
        if "sqlite" not in db.bind.url.drivername:
            db.execute(text("SET LOCAL app.current_org = :org"), {"org": str(site.org_id)})
    else:
        site = db.get(Site, site_id)
        if not site:
            raise HTTPException(404, "site not found")
    events = normalize(events_in, log_lines)

    # persist raw events
    for e in events:
        db.add(Event(site_id=site_id, ip=e["ip"], method=e["method"], path=e["path"],
                     status=e["status"], user_agent=e["user_agent"],
                     ts=e["ts"] or dt.datetime.now(dt.timezone.utc), source=e["source"]))

    honeypots = [h.path for h in db.query(Honeypot).all()]
    thresholds = {"failed_auth": settings.failed_auth_threshold,
                  "scan_404": settings.scan_404_threshold,
                  "rate_z": settings.rate_z_threshold}

    incidents, per_ip = engine.analyze(events, _BASELINE, honeypots, thresholds)
    engine.update_baseline(_BASELINE, per_ip)

    # Cross-batch detection using Redis counters
    from . import redis_counters

    # 1. Increment requests in Redis
    for ip, count in per_ip.items():
        for _ in range(count):
            redis_counters.incr_requests(ip)

    # 2. Track failed auths in Redis and check threshold
    failed_auth_this_batch = {}
    for e in events:
        ip = e["ip"]
        path_lower = (e.get("path") or "").lower()
        is_auth_path = any(path_lower.startswith(p) for p in ("/login", "/signin", "/auth", "/wp-login", "/admin", "/api/login"))
        is_failed = e.get("status") in (401, 403, 400)
        if is_auth_path and is_failed:
            failed_auth_this_batch[ip] = failed_auth_this_batch.get(ip, 0) + 1

    cross_batch_threats = {}
    for ip, count in failed_auth_this_batch.items():
        total_failed = 0
        for _ in range(count):
            total_failed = redis_counters.incr_failed_auth(ip)
        if total_failed >= settings.failed_auth_threshold:
            ttype = "credential_stuffing" if total_failed >= settings.failed_auth_threshold * 2 else "brute_force"
            cross_batch_threats[ip] = {
                "type": ttype,
                "evidence": f"Cross-batch: {total_failed} failed logins (Redis counter)"
            }

    # Merge cross-batch threats into incidents list
    incidents_by_ip = {inc["source_ip"]: inc for inc in incidents}
    for ip, threat in cross_batch_threats.items():
        if ip in incidents_by_ip:
            inc = incidents_by_ip[ip]
            if threat["type"] not in inc["threat_types"]:
                inc["threat_types"].append(threat["type"])
                inc["threat_types"].sort()
            if not any(f["type"] == threat["type"] for f in inc["findings"]):
                inc["findings"].append({"type": threat["type"], "severity": "high", "evidence": threat["evidence"]})
            inc["severity"] = "high"
        else:
            incidents.append({
                "source_ip": ip,
                "severity": "high",
                "threat_types": [threat["type"]],
                "findings": [{"type": threat["type"], "severity": "high", "evidence": threat["evidence"]}],
                "request_count": per_ip.get(ip, 0),
                "first_seen": dt.datetime.now(dt.timezone.utc),
                "last_seen": dt.datetime.now(dt.timezone.utc),
            })

    # Run Threat Correlation Engine
    incidents = correlate_incidents(db, incidents, site_id)

    # roll back expired blocks first
    responder.expire_blocks(db)

    created_ids = []
    for inc in incidents:
        is_campaign = inc.get("is_campaign", False)
        geo = "Global Campaign" if is_campaign else geoip.lookup(inc["source_ip"])
        
        action_summaries = []
        if is_campaign:
            # Block each malicious IP in the campaign individually
            for g_inc in inc.get("group_incidents", []):
                responder.respond(db, g_inc, {})
            action_summaries.append({
                "type": "block_ip",
                "provider": "cloudflare",
                "status": f"applied to {len(inc['campaign_ips'])} IPs"
            })
        else:
            action_summaries = responder.respond(db, inc, {})

        verification = "verified: block active" if any(
            a.verified for a in inc.get("_action_rows", [])) else (
            "pending" if action_summaries else "n/a (no action)")
            
        report = build_report(inc, action_summaries, verification,
                               site.url if site else "")
        report["geo"] = geo

        row = Incident(
            site_id=site_id, source_ip=inc["source_ip"], threat_types=inc["threat_types"],
            severity=inc["severity"], status="contained" if action_summaries else "open",
            request_count=inc["request_count"], first_seen=inc["first_seen"],
            last_seen=inc["last_seen"], root_cause=report["root_cause"],
            timeline=report["timeline"], report=report,
        )
        db.add(row)
        db.flush()
        
        # Link queued actions to the campaign/incident
        for a in inc.get("_action_rows", []):
            a.incident_id = row.id
            
        created_ids.append(row.id)

        if inc["severity"] == "high":
            telegram.alert_incident(report)
            from ..integrations import whatsapp
            whatsapp.alert_incident(report)

    db.commit()
    return {"events_ingested": len(events), "incidents_created": len(created_ids),
            "incident_ids": created_ids}


def correlate_incidents(db: Session, incidents: list, site_id: int) -> list:
    """Groups multiple separate alerts of the same threat type into unified campaigns."""
    correlated = []
    by_type = {}
    
    for inc in incidents:
        main_threat = inc["threat_types"][0] if inc["threat_types"] else "unknown"
        # Only correlate automated scanner/brute campaigns to avoid false groupings
        if main_threat in ("brute_force", "credential_stuffing", "scanning", "api_abuse", "bot_attack"):
            by_type.setdefault(main_threat, []).append(inc)
        else:
            correlated.append(inc)
            
    for threat, group in by_type.items():
        if len(group) >= 2:
            ips = [g["source_ip"] for g in group]
            total_reqs = sum(g["request_count"] for g in group)
            first_seen = min(g["first_seen"] for g in group) if any(g.get("first_seen") for g in group) else dt.datetime.now(dt.timezone.utc)
            last_seen = max(g["last_seen"] for g in group) if any(g.get("last_seen") for g in group) else dt.datetime.now(dt.timezone.utc)
            
            # Combine all findings
            combined_findings = []
            for g in group:
                combined_findings.extend(g.get("findings", []))
                
            campaign_inc = {
                "source_ip": f"Campaign: Coordinated {threat.replace('_', ' ').title()}",
                "severity": "high",
                "threat_types": [threat, "distributed_campaign"],
                "findings": combined_findings,
                "request_count": total_reqs,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "is_campaign": True,
                "campaign_ips": ips,
                "group_incidents": group,
                "_action_rows": []
            }
            # Merge child action rows for downstream referencing
            for g in group:
                campaign_inc["_action_rows"].extend(g.get("_action_rows", []))
            correlated.append(campaign_inc)
        else:
            correlated.extend(group)
            
    return correlated

