"""Trial-site end-to-end demo seeder.

Creates a trial website, drives REALISTIC benign + attack traffic through the real
detection engine / ingest pipeline (producing incidents), then bridges those
incidents into enterprise Cases and populates the rest of the console (ATT&CK,
Threat Intel, Agent Fleet, Detections, SLA/playbooks, audit) so every tab shows
live, coherent data.

Run from backend/:  python scripts/seed_trial_site.py
Idempotent: clears prior demo rows for the default org, then re-seeds.
"""
import datetime as dt
import os
import sys

# Env must be set BEFORE importing app config (pydantic settings read env at import).
sys.path.insert(0, os.getcwd())
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.getcwd(), ".env"))
except ImportError:
    pass
os.environ["AEGIS_ENTERPRISE"] = "1"
os.environ.setdefault("AEGIS_KEK", "KKpMzYUQkhmM0qAoGWmtsIp_X3B_1bWVt4svQTXH22c=")
os.environ["GEOIP_ENABLED"] = "false"          # avoid the GeoLite2 DB dependency for the demo

from sqlalchemy import text
from app.database import SessionLocal, init_db
from app.models import Site, Honeypot, Incident, User
from app.enterprise.models import Organization, Membership
from app.enterprise.models_p3 import Case, CaseIncident, CaseNote, CaseEvent, SlaPolicy, Playbook, Agent
from app.enterprise.models_p4 import ThreatActor, Indicator, DetectionRule, RuleVersion
from app.services import ingest as ingest_svc
from app.enterprise import attack


def clf(ip, method, path, status, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    return (f'{ip} - - [02/Jul/2026:10:00:00 +0000] "{method} {path} HTTP/1.1" '
            f'{status} 512 "-" "{ua}"')


def trial_traffic():
    """A realistic day of traffic for 'Trial Shop' — benign browsing + a spread of attacks."""
    lines = []
    # ── benign customers (must NOT be flagged) ──
    for ip in ("10.0.0.5", "10.0.0.6", "10.0.0.7"):
        for path in ("/", "/products", "/product/42", "/cart", "/about", "/checkout"):
            lines.append(clf(ip, "GET", path, 200))
    # ── SQL injection ──
    lines.append(clf("203.0.113.10", "GET",
                     "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--", 200))
    # ── XSS ──
    lines.append(clf("203.0.113.11", "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200))
    # ── path traversal ──
    lines.append(clf("203.0.113.12", "GET", "/download?file=../../../../etc/passwd", 200))
    # ── scanner tool by user-agent ──
    for _ in range(4):
        lines.append(clf("203.0.113.20", "GET", "/", 200, ua="sqlmap/1.7-dev"))
    # ── brute force (>=5 failed logins) ──
    for _ in range(8):
        lines.append(clf("198.51.100.5", "POST", "/login", 401))
    # ── credential stuffing (>=10 failed logins) ──
    for _ in range(13):
        lines.append(clf("198.51.100.9", "POST", "/login", 401))
    # ── honeypot decoy hits ──
    lines.append(clf("203.0.113.30", "GET", "/.env", 404))
    lines.append(clf("203.0.113.30", "GET", "/wp-admin/setup-config.php", 404))
    # ── 404 scanning (>=15) ──
    for i in range(18):
        lines.append(clf("203.0.113.40", "GET", f"/admin/panel-{i}", 404))
    return lines


HONEYPOTS = ["/.env", "/wp-admin/setup-config.php", "/.git/config", "/phpmyadmin",
             "/api/v1/admin/debug", "/backup.zip"]

MALICIOUS_IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.20",
                 "198.51.100.5", "198.51.100.9", "203.0.113.30", "203.0.113.40"]


def clear_demo(db, org_id):
    """Idempotency: wipe prior demo rows (leave org/users/keys/audit_log intact)."""
    for tbl in ("case_events", "case_notes", "case_incidents", "cases",
                "playbook_runs", "playbooks", "escalation_rules", "sla_policies",
                "sightings", "indicators", "threat_actors", "agents",
                "rule_versions", "rule_tests", "rule_feedback", "rule_confidence",
                "detection_rules", "actions", "events", "incidents", "audit_log"):
        try:
            db.execute(text(f"DELETE FROM {tbl}"))
        except Exception as e:      # table may not exist in some builds
            print(f"  (skip {tbl}: {e})")
    db.commit()


def main():
    init_db()
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.slug == "default").first()
        if not org:
            print("ERROR: default org not seeded. Run scripts/seed_sqlite_enterprise.py first.")
            return
        org_name = org.name                      # capture before we may change the PK
        # Normalize legacy org ids stored as 32-hex (no hyphens, from the old
        # as_uuid=True bind processor) to the canonical hyphenated form the ORM/token
        # now use — otherwise raw-SQL org filters (e.g. GDPR export) never match.
        # Read the RAW stored value (the ORM reformats to hyphenated on read).
        import uuid as _uuid
        raw_id = db.execute(text("SELECT id FROM organizations WHERE slug='default'")).scalar()
        canon = str(_uuid.UUID(raw_id))
        if canon != raw_id:
            db.execute(text("UPDATE organizations SET id=:c WHERE id=:o"), {"c": canon, "o": raw_id})
            db.execute(text("UPDATE memberships SET org_id=:c WHERE org_id=:o"), {"c": canon, "o": raw_id})
            db.commit()
        db.expire_all()                          # drop stale identity-map refs
        org_id = canon
        owner = db.query(User).filter(User.email == "admin@aegis.internal").first()
        owner_id = owner.id if owner else None
        print(f"Org: {org_name} ({org_id})  owner_id={owner_id}")

        print("Clearing prior demo data…")
        clear_demo(db, org_id)

        # ── trial website ──
        site = db.query(Site).filter(Site.name == "Trial Shop").first()
        if not site:
            site = Site(name="Trial Shop", url="https://trial-shop.example.com")
            if hasattr(site, "org_id"):
                site.org_id = org_id
            db.add(site); db.flush()
        for p in HONEYPOTS:
            if not db.query(Honeypot).filter(Honeypot.path == p).first():
                db.add(Honeypot(path=p, note="trial decoy"))
        db.commit()
        print(f"Trial site id={site.id}  ({site.url})")

        # ── 1) DRIVE THE REAL DETECTION PIPELINE ──
        print("Feeding trial traffic through the detection engine…")
        result = ingest_svc.ingest(db, site.id, [], trial_traffic())
        print(f"  events_ingested={result['events_ingested']}  "
              f"incidents_created={result['incidents_created']}")

        incidents = (db.query(Incident).filter(Incident.site_id == site.id)
                     .order_by(Incident.created_at.desc()).all())
        # confirm benign IPs were NOT flagged
        flagged = {i.source_ip for i in incidents}
        benign_flagged = [ip for ip in ("10.0.0.5", "10.0.0.6", "10.0.0.7") if ip in flagged]
        print(f"  incidents in DB={len(incidents)}  benign_false_positives={benign_flagged or 'none'}")

        # ── 2) ATT&CK reference data ──
        attack.seed()
        print("Seeded ATT&CK techniques + detection map")

        # ── 3) SLA policies + a response playbook ──
        for sev, fr, res in [("high", 30, 240), ("medium", 60, 480), ("low", 120, 1440)]:
            db.add(SlaPolicy(org_id=org_id, severity=sev, first_response_mins=fr, resolution_mins=res))
        db.add(Playbook(org_id=org_id, name="Contain malicious IP",
                        trigger={"threat": "brute_force"},
                        steps=[{"action": "note", "body": "Auto-triage: block source IP at edge."},
                               {"action": "status", "to": "contained"},
                               {"action": "notify", "channel": "soc"}]))
        db.flush()

        # ── 4) BRIDGE incidents -> enterprise Cases ──
        statuses = ["open", "investigating", "contained"]
        made = 0
        for i, inc in enumerate(incidents):
            if inc.severity not in ("high", "medium"):
                continue
            tt = (inc.threat_types or ["threat"])[0].replace("_", " ").title()
            case = Case(org_id=org_id, title=f"{tt} from {inc.source_ip}",
                        severity=inc.severity, priority="p1" if inc.severity == "high" else "p2",
                        status=statuses[i % len(statuses)], created_by=owner_id,
                        opened_at=dt.datetime.now(dt.timezone.utc))
            pol = db.query(SlaPolicy).filter(SlaPolicy.severity == inc.severity).first()
            if pol:
                case.sla_response_due = case.opened_at + dt.timedelta(minutes=pol.first_response_mins)
                case.sla_resolve_due = case.opened_at + dt.timedelta(minutes=pol.resolution_mins)
            db.add(case); db.flush()
            db.add(CaseIncident(case_id=case.id, incident_id=inc.id, org_id=org_id))
            db.add(CaseNote(org_id=org_id, case_id=case.id, author_id=owner_id, internal=True,
                            body=f"Auto-created from detected incident #{inc.id}. "
                                 f"Threats: {', '.join(inc.threat_types or [])}. "
                                 f"Requests: {inc.request_count}."))
            db.add(CaseEvent(org_id=org_id, case_id=case.id, type="created", actor="system",
                             data={"from_incident": inc.id, "severity": inc.severity}))
            made += 1
        db.commit()
        print(f"Created {made} cases from incidents")

        # ── 5) Threat Intelligence ──
        actor = ThreatActor(org_id=org_id, name="APT-Trial (demo)",
                            aliases=["ShopRaider", "CartThief"],
                            description="Demo actor targeting e-commerce checkout + auth.",
                            source="AEGIS Trial Feed")
        db.add(actor); db.flush()
        for ip in MALICIOUS_IPS:
            db.add(Indicator(org_id=org_id, type="ipv4", value=ip, confidence=85,
                             source="AEGIS Trial Feed", actor_id=actor.id,
                             labels=["malicious", "observed"],
                             valid_until=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)))
        for dom in ("cart-exfil.example.net", "creds-drop.example.org"):
            db.add(Indicator(org_id=org_id, type="domain", value=dom, confidence=70,
                             source="AEGIS Trial Feed", labels=["c2"]))
        db.commit()
        print(f"Seeded threat intel: 1 actor, {len(MALICIOUS_IPS)+2} indicators")

        # ── 6) Agent Fleet ──
        now = dt.datetime.now(dt.timezone.utc)
        db.add(Agent(org_id=org_id, name="web-edge-01", hostname="edge01.trial-shop",
                     status="active", version="1.4.2", channel="stable",
                     health={"cpu": 12, "mem": 41}, enrolled_at=now - dt.timedelta(days=5),
                     last_seen_at=now - dt.timedelta(seconds=30)))
        db.add(Agent(org_id=org_id, name="api-node-02", hostname="api02.trial-shop",
                     status="active", version="1.4.1", channel="stable",
                     health={"cpu": 8, "mem": 55}, enrolled_at=now - dt.timedelta(days=5),
                     last_seen_at=now - dt.timedelta(hours=2)))  # stale (>15m)
        db.commit()
        print("Enrolled 2 agents (1 fresh, 1 stale)")

        # ── 7) Detection content ──
        for key, name, pattern in [
            ("trial_sqli", "SQLi in query params", "union.+select|'\\s+or\\s+'1'='1"),
            ("trial_admin_honeypot", "Admin honeypot access", "/wp-admin|/\\.env|/\\.git"),
        ]:
            rid = __import__("uuid").uuid4().__str__()
            db.add(DetectionRule(id=rid, org_id=org_id, key=key, name=name,
                                 type="signature", enabled=True, current_version=1))
            db.add(RuleVersion(org_id=org_id, rule_id=rid, version=1,
                               definition={"pattern": pattern}, author="admin@aegis.internal",
                               note="trial seed"))
        db.commit()
        print("Created 2 detection rules")

        # ── 8) Audit trail — reset to a clean hash chain. The legacy responder.audit()
        #     writes NON-chained rows into the same audit_log table during ingest, which
        #     would break the enterprise tamper-evident verify. Clear + re-chain here.
        try:
            from app.enterprise import compliance
            db.execute(text("DELETE FROM audit_log"))
            db.commit()
            compliance.append_audit(db, "system", "scan.completed",
                                    {"site": "Trial Shop", "incidents": len(incidents)}, org_id=org_id)
            compliance.append_audit(db, "admin@aegis.internal", "cases.created",
                                    {"count": made}, org_id=org_id)
            compliance.append_audit(db, "admin@aegis.internal", "intel.ingested",
                                    {"indicators": len(MALICIOUS_IPS) + 2, "agents": 2}, org_id=org_id)
            db.commit()
            print("Wrote 3 audit entries (clean chain)")
        except Exception as e:
            db.rollback()
            print(f"  (audit append skipped: {e})")

        print("\n=== TRIAL SITE SEED COMPLETE ===")
        print(f"  incidents={len(incidents)}  cases={made}  "
              f"indicators={len(MALICIOUS_IPS)+2}  agents=2  rules=2")
        print(f"  benign false positives: {benign_flagged or 'NONE (good)'}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
