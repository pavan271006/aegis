import os
import shutil

# Override settings for tests
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["API_KEY"] = "test-key"
os.environ["RESPONSE_MODE"] = "auto"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["GEOIP_ENABLED"] = "false"

import pytest
import datetime as dt
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal, init_db, engine
from app.models import Site, Allowlist, Honeypot, Incident, Action, Event, QuarantinedFile
from app.config import settings

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    # Release connection pool and delete the test DB
    engine.dispose()
    if os.path.exists("./test.db"):
        try:
            os.remove("./test.db")
        except OSError:
            pass
    # Initialize DB
    init_db()
    db = SessionLocal()
    # Add seed site
    site = Site(name="Test Site", url="https://example.com")
    db.add(site)
    db.commit()
    db.close()
    yield
    # Cleanup and release DB
    engine.dispose()
    if os.path.exists("./test.db"):
        try:
            os.remove("./test.db")
        except OSError:
            pass

def test_health():
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

def test_auth_enforcement():
    with TestClient(app) as client:
        # All admin/ingest endpoints should return 401 without key
        assert client.post("/api/ingest", json={}).status_code == 401
        assert client.post("/api/admin/sites", json={}).status_code == 401
        assert client.post("/api/admin/allowlist", params={"value": "1.1.1.1"}).status_code == 401
        assert client.post("/api/admin/honeypots", params={"path": "/fake"}).status_code == 401
        assert client.delete("/api/admin/sites/1").status_code == 401
        assert client.delete("/api/admin/allowlist/1").status_code == 401
        assert client.delete("/api/admin/honeypots/1").status_code == 401
        assert client.post("/api/monitoring/check-all").status_code == 401
        assert client.post("/api/admin/quarantine/1/release").status_code == 401
        assert client.delete("/api/admin/quarantine/1").status_code == 401
        assert client.post("/api/ingest/upload", files={"file": ("test.txt", b"test")}).status_code == 401

def test_detection_engine_attack_classes():
    # Let's test the 10 threat types via ingest
    with TestClient(app) as client:
        headers = {"X-API-Key": "test-key"}
        
        # Helper to run an ingest and get incidents
        def ingest_events(events):
            r = client.post("/api/ingest", json={"site_id": 1, "events": events}, headers=headers)
            assert r.status_code == 200
            return r.json()

        # 1. SQL Injection
        res = ingest_events([{"ip": "1.1.1.1", "path": "/?id=1%20UNION%20SELECT%20username%20FROM%20users--"}])
        assert res["incidents_created"] >= 1
        
        # 2. XSS
        res = ingest_events([{"ip": "1.1.1.2", "path": "/?q=<script>alert(1)</script>"}])
        assert res["incidents_created"] >= 1
        
        # 3. Path Traversal
        res = ingest_events([{"ip": "1.1.1.3", "path": "/../../etc/passwd"}])
        assert res["incidents_created"] >= 1
        
        # 4. Malware Upload
        res = ingest_events([{"ip": "1.1.1.4", "path": "/uploads/webshell.php"}])
        assert res["incidents_created"] >= 1

        # 5. Bot Attack (User Agent)
        res = ingest_events([{"ip": "1.1.1.5", "user_agent": "sqlmap/1.7"}])
        assert res["incidents_created"] >= 1

        # 6. Scanning (high number of 404s)
        events = [{"ip": "1.1.1.6", "path": f"/fake-path-{i}", "status": 404} for i in range(20)]
        res = ingest_events(events)
        assert res["incidents_created"] >= 1

        # 7. Brute Force (failed logins)
        events = [{"ip": "1.1.1.7", "path": "/login", "status": 401} for i in range(6)]
        res = ingest_events(events)
        assert res["incidents_created"] >= 1

        # 8. API Abuse (heavy hits to /api)
        events = [{"ip": "1.1.1.8", "path": f"/api/items/{i}", "status": 200} for i in range(25)]
        res = ingest_events(events)
        assert res["incidents_created"] >= 1

        # 9. Honeypot (instant high-signal decoy hit)
        # First seed the honeypot
        client.post("/api/admin/honeypots", params={"path": "/decoy.php", "note": "decoy"}, headers=headers)
        # Hit it
        r = client.get("/api/ingest/honeypot", params={"path": "/decoy.php", "ip": "1.1.1.9"})
        assert r.status_code == 200
        assert r.json()["trapped"] is True

        # Let's verify all the incidents exist in the db and check their types
        incs = client.get("/api/incidents").json()
        ips = {i["source_ip"]: i for i in incs}
        assert "1.1.1.1" in ips and "sql_injection" in ips["1.1.1.1"]["threat_types"]
        assert "1.1.1.2" in ips and "xss" in ips["1.1.1.2"]["threat_types"]
        assert "1.1.1.3" in ips and "path_traversal" in ips["1.1.1.3"]["threat_types"]
        assert "1.1.1.4" in ips and "malware_upload" in ips["1.1.1.4"]["threat_types"]
        assert "1.1.1.5" in ips and "bot_attack" in ips["1.1.1.5"]["threat_types"]
        assert "1.1.1.6" in ips and "scanning" in ips["1.1.1.6"]["threat_types"]
        assert "1.1.1.7" in ips and ("brute_force" in ips["1.1.1.7"]["threat_types"] or "credential_stuffing" in ips["1.1.1.7"]["threat_types"])
        assert "1.1.1.8" in ips and "api_abuse" in ips["1.1.1.8"]["threat_types"]
        assert "1.1.1.9" in ips and "honeypot" in ips["1.1.1.9"]["threat_types"]

def test_allowlist_prevents_blocking():
    with TestClient(app) as client:
        headers = {"X-API-Key": "test-key"}
        
        # Add IP to allowlist
        client.post("/api/admin/allowlist", params={"value": "192.168.1.100", "note": "office"}, headers=headers)
        
        # Send an attack from that IP
        r = client.post("/api/ingest", json={"site_id": 1, "events": [{"ip": "192.168.1.100", "path": "/?id=1%20UNION%20SELECT%20username%20FROM%20users--"}]}, headers=headers)
        assert r.status_code == 200
        
        # Verify incident was created but NO block/remediation actions were taken
        incs = client.get("/api/incidents").json()
        target_inc = next((i for i in incs if i["source_ip"] == "192.168.1.100"), None)
        assert target_inc is not None
        assert len(target_inc.get("actions", [])) == 0

def test_rate_limiting():
    from app.services import rate_limiter
    # In-memory rate limiting check
    ip = "1.2.3.4"
    # Check limit window is respected
    for _ in range(settings.rate_limit_max_requests):
        res = rate_limiter.check_rate(ip)
        assert res["allowed"] is True
    # Next hit should be blocked
    res = rate_limiter.check_rate(ip)
    assert res["allowed"] is False or res["current"] > res["limit"]

def test_upload_quarantine():
    with TestClient(app) as client:
        headers = {"X-API-Key": "test-key"}
        
        # Test safe upload
        r = client.post("/api/ingest/upload", files={"file": ("report.pdf", b"safe PDF content", "application/pdf")}, headers=headers)
        assert r.status_code == 200
        assert r.json()["safe"] is True
        
        # Test dangerous upload (e.g. php file or executable)
        r = client.post("/api/ingest/upload", files={"file": ("malicious.php", b"<?php phpinfo();", "application/x-php")}, headers=headers)
        assert r.status_code == 200
        assert r.json()["safe"] is False
        assert r.json()["quarantined"] is True
        
        # Get quarantine list and check if file is present
        q_list = client.get("/api/admin/quarantine", headers=headers).json()
        assert len(q_list) >= 1
        q_item = q_list[0]
        assert q_item["original_name"] == "malicious.php"
        
        # Test release
        r = client.post(f"/api/admin/quarantine/{q_item['id']}/release", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "released"
        
        # Test delete
        r = client.delete(f"/api/admin/quarantine/{q_item['id']}", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

def test_dashboard_scoring_and_stats():
    with TestClient(app) as client:
        headers = {"X-API-Key": "test-key"}
        # Trigger stats and dashboard endpoints
        dash = client.get("/api/dashboard").json()
        assert "security_score" in dash
        assert "system_health" in dash
        
        stats = client.get("/api/dashboard/stats").json()
        assert "total_events" in stats
        assert "severity_distribution" in stats
        assert "incidents_by_day" in stats

def test_report_generation_format():
    with TestClient(app) as client:
        headers = {"X-API-Key": "test-key"}
        
        # Get an incident ID from the database
        incs = client.get("/api/incidents").json()
        assert len(incs) > 0
        inc_id = incs[0]["id"]
        
        # Fetch report
        r = client.get(f"/api/incidents/{inc_id}/report.html")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "AEGIS Lite" in r.text
        assert "Incident Report" in r.text

def test_admin_management_apis():
    with TestClient(app) as client:
        headers = {"X-API-Key": "test-key"}
        
        # Sites
        sites = client.get("/api/admin/sites", headers=headers).json()
        assert len(sites) >= 1
        site_id = sites[0]["id"]
        
        # Allowlist list
        allow = client.get("/api/admin/allowlist", headers=headers).json()
        assert len(allow) >= 1
        allow_id = allow[0]["id"]
        
        # Honeypots list
        hp = client.get("/api/admin/honeypots", headers=headers).json()
        assert len(hp) >= 1
        hp_id = hp[0]["id"]
        
        # Audit logs list
        audit = client.get("/api/admin/audit-log", headers=headers).json()
        assert len(audit) >= 1
        
        # Config list
        config = client.get("/api/admin/config", headers=headers).json()
        assert config["app_name"] == "AEGIS Lite"
        
        # Delete allowlist item
        assert client.delete(f"/api/admin/allowlist/{allow_id}", headers=headers).status_code == 200
        # Delete honeypot item
        assert client.delete(f"/api/admin/honeypots/{hp_id}", headers=headers).status_code == 200

def test_premium_features():
    with TestClient(app) as client:
        headers = {"X-API-Key": "test-key"}

        # 1. Test AI Advisor
        r = client.get("/api/admin/advisor", headers=headers)
        assert r.status_code == 200
        recs = r.json()
        assert isinstance(recs, list)
        if len(recs) > 0:
            assert "id" in recs[0]
            assert "title" in recs[0]
            assert "severity" in recs[0]

        # 2. Test One-Click Hardening
        r = client.post("/api/admin/harden", headers=headers)
        assert r.status_code == 200
        harden_res = r.json()
        assert harden_res["ok"] is True
        assert harden_res["mode"] == "auto"
        assert settings.response_mode == "auto"
        assert settings.rate_limit_max_requests == 50
        assert settings.failed_auth_threshold == 3

        # 3. Test Threat Feed
        r = client.get("/api/admin/threat-feed", headers=headers)
        assert r.status_code == 200
        feed = r.json()
        assert isinstance(feed, list)
        assert len(feed) >= 1
        assert "ip" in feed[0]
        assert "type" in feed[0]
        assert "status" in feed[0]


def test_user_logins_and_rbac():
    with TestClient(app) as client:
        # 1. Test login for admin
        r = client.post("/api/auth/login", json={"email": "admin@aegis.internal", "password": "admin123"})
        assert r.status_code == 200
        admin_token = r.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # 2. Test login for read-only
        r = client.post("/api/auth/login", json={"email": "readonly@aegis.internal", "password": "readonly123"})
        assert r.status_code == 200
        ro_token = r.json()["access_token"]
        ro_headers = {"Authorization": f"Bearer {ro_token}"}

        # 3. Test RBAC: accessing backups with admin token works
        r = client.get("/api/admin/backups", headers=admin_headers)
        assert r.status_code == 200

        # 4. Test RBAC: accessing backups with read-only token gets a 403
        r = client.get("/api/admin/backups", headers=ro_headers)
        assert r.status_code == 403


def test_backups_snapshots_creation():
    with TestClient(app) as client:
        # Login to get admin token
        r = client.post("/api/auth/login", json={"email": "admin@aegis.internal", "password": "admin123"})
        admin_token = r.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Clean existing test backups directory if any
        if os.path.exists("./backups"):
            try:
                shutil.rmtree("./backups")
            except OSError:
                pass

        # Create backup
        r = client.post("/api/admin/backups", headers=admin_headers)
        assert r.status_code == 200
        res = r.json()
        assert res["ok"] is True
        assert "filename" in res

        # List backups
        r = client.get("/api/admin/backups", headers=admin_headers)
        assert r.status_code == 200
        backups = r.json()
        assert len(backups) >= 1
        assert any(b["name"] == res["filename"] for b in backups)

        # Delete backup
        r = client.delete(f"/api/admin/backups/{res['filename']}", headers=admin_headers)
        assert r.status_code == 200
        assert r.json()["ok"] is True


def test_bug_hunter_triggering():
    with TestClient(app) as client:
        # Login to get analyst/admin token
        r = client.post("/api/auth/login", json={"email": "analyst@aegis.internal", "password": "analyst123"})
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Trigger bug hunter
        r = client.post("/api/admin/scanner/trigger?site_id=1", headers=headers)
        assert r.status_code == 200
        assert r.json()["ok"] is True

        # Check status
        r = client.get("/api/admin/scanner/status", headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] in ("running", "finished")


def test_auto_rollback_logic():
    # Setup test DB session
    db = SessionLocal()
    try:
        # Update site ID 1 to have an invalid/broken URL
        site = db.get(Site, 1)
        old_url = site.url
        site.url = "http://broken-site-dns-fail-xxxx.com"
        db.commit()
        
        # Temporarily force auto response mode
        old_mode = settings.response_mode
        settings.response_mode = "auto"
        
        with TestClient(app) as client:
            headers = {"X-API-Key": "test-key"}
            
            # Send an attack (SQL Injection) targeting site_id 1
            # This triggers ingest -> detect -> respond -> verification (unhealthy URL) -> rollback
            r = client.post("/api/ingest", json={
                "site_id": 1,
                "events": [{"ip": "9.9.9.9", "path": "/?id=1%20UNION%20SELECT%201--"}]
            }, headers=headers)
            assert r.status_code == 200
            
            # Query the database for the actions created
            actions = db.query(Action).filter(Action.params.like("%9.9.9.9%")).all()
            assert len(actions) > 0
            
            # Since the URL is invalid and checks fail, the actions should have been rolled back
            assert any(a.status == "rolled_back" for a in actions)
            
            # Also, verify that the remediation_rollback audit log exists
            from app.models import AuditLog
            log = db.query(AuditLog).filter(AuditLog.action == "remediation_rollback").first()
            assert log is not None
            assert "9.9.9.9" in log.details["ip"]

        # Restore site URL and response mode
        site = db.get(Site, 1)
        site.url = old_url
        db.commit()
        settings.response_mode = old_mode
    finally:
        db.close()



