"""Detection content management + false-positive management.

Content: versioned rules with a definition (e.g. {"pattern": "<regex>"}), unit
tests (sample + expected verdict) runnable in CI, and one-click rollback.
FP mgmt: suppression rules (drop known-good before it becomes an incident),
a TP/FP feedback loop that updates a per-rule confidence, and a confidence gate
the responder can use to require human approval below a threshold."""
import datetime as dt
import re
import uuid as _uuid_mod

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text

from .deps import Principal, require

router = APIRouter(prefix="/api/v2/detections", tags=["detections"])


# ── content management ─────────────────────────────────────────────────────
class RuleIn(BaseModel):
    key: str
    name: str
    type: str = "signature"
    definition: dict


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, user: Principal = Depends(require("admin"))):
    db = user.db
    rule_id = str(_uuid_mod.uuid4())
    db.execute(text("""
        INSERT INTO detection_rules(id,org_id,key,name,type,enabled,current_version)
        VALUES (:id,:o,:k,:n,:t,1,1)"""),
        {"id": rule_id, "o": str(user.org_id), "k": body.key, "n": body.name, "t": body.type})
    db.execute(text("""
        INSERT INTO rule_versions(id,org_id,rule_id,version,definition,author,note)
        VALUES (:vid,:o,:r,1,:d,:a,'initial')"""),
        {"vid": str(_uuid_mod.uuid4()), "o": str(user.org_id), "r": rule_id,
         "d": _json(body.definition), "a": user.email})
    return {"id": rule_id, "version": 1}


@router.post("/rules/{rule_id}/versions")
def new_version(rule_id: str, definition: dict, note: str = "",
                user: Principal = Depends(require("admin"))):
    db = user.db
    cur = db.execute(text("SELECT current_version FROM detection_rules WHERE id=:r"),
                     {"r": rule_id}).scalar()
    if cur is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    v = cur + 1
    db.execute(text("""INSERT INTO rule_versions(id,org_id,rule_id,version,definition,author,note)
                       VALUES (:id,:o,:r,:v,:d,:a,:n)"""),
               {"id": str(_uuid_mod.uuid4()), "o": str(user.org_id), "r": rule_id,
                "v": v, "d": _json(definition), "a": user.email, "n": note})
    db.execute(text("UPDATE detection_rules SET current_version=:v WHERE id=:r"),
               {"v": v, "r": rule_id})
    return {"version": v}


@router.post("/rules/{rule_id}/rollback")
def rollback(rule_id: str, to_version: int, user: Principal = Depends(require("admin"))):
    db = user.db
    exists = db.execute(text("SELECT 1 FROM rule_versions WHERE rule_id=:r AND version=:v"),
                        {"r": rule_id, "v": to_version}).scalar()
    if not exists:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")
    db.execute(text("UPDATE detection_rules SET current_version=:v WHERE id=:r"),
               {"v": to_version, "r": rule_id})
    return {"current_version": to_version}


# ── testing (CI-runnable) ──────────────────────────────────────────────────
@router.post("/rules/{rule_id}/tests")
def add_test(rule_id: str, name: str, sample: dict, expect_match: bool,
             user: Principal = Depends(require("admin"))):
    user.db.execute(text("""INSERT INTO rule_tests(id,org_id,rule_id,name,sample,expect_match)
                            VALUES (:id,:o,:r,:n,:s,:e)"""),
                    {"id": str(_uuid_mod.uuid4()), "o": str(user.org_id), "r": rule_id,
                     "n": name, "s": _json(sample), "e": expect_match})
    return {"ok": True}


@router.post("/rules/{rule_id}/test")
def run_tests(rule_id: str, user: Principal = Depends(require("analyst"))):
    db = user.db
    import json as _json_mod
    definition_raw = db.execute(text("""
        SELECT v.definition FROM detection_rules d
        JOIN rule_versions v ON v.rule_id=d.id AND v.version=d.current_version
        WHERE d.id=:r"""), {"r": rule_id}).scalar()
    if isinstance(definition_raw, str):
        definition_raw = _json_mod.loads(definition_raw)
    pattern = (definition_raw or {}).get("pattern", "")
    rx = re.compile(pattern, re.I) if pattern else None
    tests = db.execute(text("SELECT id,name,sample,expect_match FROM rule_tests WHERE rule_id=:r"),
                       {"r": rule_id}).all()
    results, passed = [], 0
    for tid, name, sample, expect in tests:
        if isinstance(sample, str):
            import json as _jm; sample = _jm.loads(sample)
        target = " ".join(str(v) for v in (sample or {}).values())
        matched = bool(rx.search(target)) if rx else False
        ok = matched == expect
        passed += ok
        db.execute(text("UPDATE rule_tests SET last_result=:res WHERE id=:i"),
                   {"res": "pass" if ok else "fail", "i": str(tid)})
        results.append({"name": name, "expected": expect, "matched": matched, "pass": ok})
    return {"total": len(tests), "passed": passed, "results": results}


# ── false-positive management ──────────────────────────────────────────────
class SuppressIn(BaseModel):
    match: dict          # {source_ip?, path?, threat_type?}
    reason: str = ""
    ttl_hours: int | None = None


@router.post("/suppressions")
def add_suppression(body: SuppressIn, user: Principal = Depends(require("analyst"))):
    expires_at = None
    if body.ttl_hours is not None:
        expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=body.ttl_hours)
    user.db.execute(text("""
        INSERT INTO suppression_rules(id,org_id,match,reason,created_by,expires_at,enabled)
        VALUES (:id,:o,:m,:r,:u,:exp,1)"""),
        {"id": str(_uuid_mod.uuid4()), "o": str(user.org_id), "m": _json(body.match),
         "r": body.reason, "u": user.user_id, "exp": expires_at})
    return {"ok": True}


def is_suppressed(db, finding: dict) -> bool:
    """Called by the ingest pipeline before persisting an incident."""
    now = dt.datetime.now(dt.timezone.utc)
    rules = db.execute(text("""
        SELECT match FROM suppression_rules
        WHERE enabled AND (expires_at IS NULL OR expires_at > :now)"""),
        {"now": now}).all()
    import json as _json_mod
    for (m,) in rules:
        if isinstance(m, str):
            m = _json_mod.loads(m)
        if all(finding.get(k) == v for k, v in (m or {}).items()):
            return True
    return False


class FeedbackIn(BaseModel):
    rule_key: str
    verdict: str             # 'tp' | 'fp'
    incident_id: int | None = None   # rule-level feedback may have no incident


@router.post("/feedback")
def feedback(body: FeedbackIn, user: Principal = Depends(require("analyst"))):
    if body.verdict not in ("tp", "fp"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "verdict must be tp|fp")
    db = user.db
    db.execute(text("""INSERT INTO rule_feedback(id,org_id,incident_id,rule_key,verdict,user_id)
                       VALUES (:id,:o,:i,:k,:v,:u)"""),
               {"id": str(_uuid_mod.uuid4()), "o": str(user.org_id),
                "i": body.incident_id, "k": body.rule_key,
                "v": body.verdict, "u": user.user_id})
    col = "tp" if body.verdict == "tp" else "fp"
    inc_tp = 1 if col == "tp" else 0
    init_tp = 1 if col == "tp" else 0
    init_fp = 1 if col == "fp" else 0
    db.execute(text(f"""
        INSERT INTO rule_confidence(org_id,rule_key,tp,fp,confidence)
        VALUES (:o,:k,:itp,:ifp,0.5)
        ON CONFLICT (org_id,rule_key) DO UPDATE
          SET {col} = rule_confidence.{col} + 1,
              confidence = CAST(rule_confidence.tp + :inc_tp AS REAL)
                           / NULLIF(rule_confidence.tp + rule_confidence.fp + 1, 0)"""),
        {"o": str(user.org_id), "k": body.rule_key,
         "itp": init_tp, "ifp": init_fp, "inc_tp": inc_tp})
    return {"ok": True}


def confidence(db, org_id: str, rule_key: str) -> float:
    val = db.execute(text("SELECT confidence FROM rule_confidence WHERE rule_key=:k"),
                     {"k": rule_key}).scalar()
    return float(val) if val is not None else 0.5


def _json(d) -> str:
    import json
    return json.dumps(d)
