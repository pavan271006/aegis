"""Compliance code slice (the *implementable* part — the certifications are
programs, not code):

  - Tamper-evident audit log: each entry is hash-chained to the previous, so any
    edit/delete is detectable (`verify_chain`).
  - GDPR: subject data export (portability) + erasure (right to be forgotten).
  - Retention engine: per-table TTL enforcement (scheduler-driven).
  - Backup validation: take a backup AND prove it restores (the legacy local-zip
    'backup' was never verified)."""
import datetime as dt
import hashlib
import json
import os
import subprocess
import tempfile
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text

from .deps import Principal, require
from .settings import get_settings

router = APIRouter(prefix="/api/v2/compliance", tags=["compliance"])

# Only these tables may be targeted by retention/erasure (defense vs. injection).
RETENTION_WHITELIST = {"events": "ts", "incidents": "created_at", "actions": "created_at",
                       "monitoring_checks": "ts", "audit_log": "ts", "sightings": "created_at"}


# ── tamper-evident audit ───────────────────────────────────────────────────
def append_audit(db, actor: str, action: str, details: dict) -> str:
    last = db.execute(text(
        "SELECT entry_hash FROM audit_log ORDER BY ts DESC, id DESC LIMIT 1")).scalar() or ""
    ts = dt.datetime.now(dt.timezone.utc)
    canonical = json.dumps({"ts": ts.isoformat(), "actor": actor, "action": action,
                            "details": details}, sort_keys=True, separators=(",", ":"))
    entry_hash = hashlib.sha256((last + canonical).encode()).hexdigest()
    # audit_log is RLS-scoped; stamp the current org so the WITH CHECK passes and
    # each tenant keeps its own hash chain.
    db.execute(text("""
        INSERT INTO audit_log(ts,actor,action,details,prev_hash,entry_hash,org_id)
        VALUES (:ts,:a,:act, cast(:d AS json), :p,:h,
                current_setting('app.current_org', true)::uuid)"""),
               {"ts": ts, "a": actor, "act": action, "d": json.dumps(details),
                "p": last, "h": entry_hash})
    return entry_hash


@router.get("/audit/verify")
def verify_chain(user: Principal = Depends(require("admin"))):
    rows = user.db.execute(text(
        "SELECT id,ts,actor,action,details,prev_hash,entry_hash FROM audit_log ORDER BY ts,id")).all()
    prev = ""
    for r in rows:
        ts_val = r[1]
        if isinstance(ts_val, str):
            import dateutil.parser
            ts_str = dateutil.parser.parse(ts_val).isoformat()
        else:
            ts_str = ts_val.isoformat()
            
        canonical = json.dumps({"ts": ts_str, "actor": r[2], "action": r[3],
                                "details": r[4]}, sort_keys=True, separators=(",", ":"))
        expect = hashlib.sha256((prev + canonical).encode()).hexdigest()
        if r[5] != prev or r[6] != expect:
            return {"ok": False, "broken_at_id": r[0], "checked": len(rows)}
        prev = r[6]
    return {"ok": True, "entries": len(rows)}


# ── GDPR ────────────────────────────────────────────────────────────────────
@router.get("/gdpr/export")
def gdpr_export(email: str, user: Principal = Depends(require("owner"))):
    db = user.db
    u = db.execute(text("SELECT id,email,role,created_at FROM users WHERE email=:e"),
                   {"e": email.lower()}).first()
    if not u:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subject not found")
    
    # Check membership inside caller's organization only
    m = db.execute(text("SELECT org_id,role,status FROM memberships WHERE user_id=:u AND org_id=:org"),
                   {"u": u[0], "org": user.org_id}).first()
    if not m:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subject not found in this organization")

    audit = db.execute(text("SELECT ts,action,details FROM audit_log WHERE details::text ILIKE :e LIMIT 1000"),
                       {"e": f"%{email}%"}).all()
    return {"subject": {"id": u[0], "email": u[1], "role": u[2],
                        "created_at": u[3].isoformat() if u[3] else None},
            "memberships": [{"org_id": str(m[0]), "role": m[1], "status": m[2]}],
            "audit_references": [{"ts": a[0].isoformat(), "action": a[1]} for a in audit]}


@router.post("/gdpr/erase")
def gdpr_erase(email: str, user: Principal = Depends(require("owner"))):
    db = user.db
    u = db.execute(text("SELECT id FROM users WHERE email=:e"), {"e": email.lower()}).first()
    if not u:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subject not found")
    uid = u[0]
    
    # Verify membership inside caller's organization
    m = db.execute(text("SELECT id FROM memberships WHERE user_id=:u AND org_id=:org"),
                   {"u": uid, "org": user.org_id}).first()
    if not m:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subject not found in this organization")

    # Delete tenant-scoped resources: membership and refresh sessions for this organization
    for stmt in (
        "DELETE FROM refresh_sessions WHERE user_id=:u AND org_id=:org",
        "DELETE FROM memberships WHERE user_id=:u AND org_id=:org",
    ):
        db.execute(text(stmt), {"u": uid, "org": user.org_id})

    append_audit(db, user.email, "gdpr_erase", {"subject_id": uid})
    return {"ok": True, "erased_user_id": uid}


# ── retention engine ───────────────────────────────────────────────────────
def enforce_retention(db) -> dict:
    """Run per-org retention policies (scheduler). Returns deleted counts."""
    policies = db.execute(text("SELECT table_name, ttl_days FROM retention_policies")).all()
    deleted = {}
    for table, ttl in policies:
        col = RETENTION_WHITELIST.get(table)
        if not col:
            continue
        res = db.execute(text(
            f"DELETE FROM {table} WHERE {col} < now() - (:d||' days')::interval"), {"d": ttl})
        deleted[table] = res.rowcount
    return deleted


@router.post("/retention/run")
def retention_run(user: Principal = Depends(require("admin"))):
    return {"deleted": enforce_retention(user.db)}


# ── backup validation ──────────────────────────────────────────────────────
@router.post("/backup/validate")
def validate_backup(user: Principal = Depends(require("admin"))):
    return run_backup_validation()


def run_backup_validation() -> dict:
    """pg_dump the database, then prove the archive restores (TOC + object count).
    Deep mode (restore into a scratch DB) is gated behind AEGIS_BACKUP_SCRATCH_DB."""
    url = urlsplit(get_settings().database_url.replace("postgresql+psycopg2", "postgresql"))
    env = {**os.environ, "PGPASSWORD": url.password or ""}
    db_name = url.path.lstrip("/")
    base = ["-h", url.hostname or "localhost", "-p", str(url.port or 5432),
            "-U", url.username or "postgres"]
    with tempfile.NamedTemporaryFile(suffix=".dump", delete=False) as f:
        dump_path = f.name
    try:
        subprocess.run(["pg_dump", *base, "-Fc", "-f", dump_path, db_name],
                       env=env, check=True, capture_output=True, timeout=600)
        toc = subprocess.run(["pg_restore", "--list", dump_path],
                             check=True, capture_output=True, timeout=120, text=True)
        objects = sum(1 for line in toc.stdout.splitlines() if line and not line.startswith(";"))
        size = os.path.getsize(dump_path)
        ok = size > 0 and objects > 0
        report = {"ok": ok, "dump_bytes": size, "restorable_objects": objects,
                  "verified_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        if os.getenv("AEGIS_BACKUP_SCRATCH_DB"):
            scratch = os.environ["AEGIS_BACKUP_SCRATCH_DB"]
            subprocess.run(["pg_restore", *base, "-d", scratch, "--clean", "--if-exists", dump_path],
                           env=env, check=True, capture_output=True, timeout=600)
            report["scratch_restore"] = "ok"
        return report
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": (e.stderr or b"").decode()[:500]}
    finally:
        try:
            os.unlink(dump_path)
        except OSError:
            pass
