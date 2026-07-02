"""MITRE ATT&CK mapping: detection -> technique, incident enrichment, coverage
heatmap, and an executive ATT&CK report. Reference data is global; the seed below
covers AEGIS's detection classes (extend by importing the full MITRE STIX bundle)."""
from fastapi import APIRouter, Depends
from sqlalchemy import text

from .deps import Principal, require
from .tenancy import system_session

router = APIRouter(prefix="/api/v2/attack", tags=["attack"])

# technique_id -> (name, tactic, is_sub, parent)
TECHNIQUES = {
    "T1190": ("Exploit Public-Facing Application", "initial-access", False, None),
    "T1110": ("Brute Force", "credential-access", False, None),
    "T1110.004": ("Brute Force: Credential Stuffing", "credential-access", True, "T1110"),
    "T1059": ("Command and Scripting Interpreter", "execution", False, None),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "execution", True, "T1059"),
    "T1595": ("Active Scanning", "reconnaissance", False, None),
    "T1498": ("Network Denial of Service", "impact", False, None),
    "T1105": ("Ingress Tool Transfer", "command-and-control", False, None),
    "T1083": ("File and Directory Discovery", "discovery", False, None),
}
# AEGIS detection key -> [(technique_id, confidence)]
DETECTION_MAP = {
    "sql_injection": [("T1190", 0.9)],
    "xss": [("T1059.007", 0.7)],
    "path_traversal": [("T1190", 0.6), ("T1083", 0.5)],
    "brute_force": [("T1110", 0.95)],
    "credential_stuffing": [("T1110.004", 0.95)],
    "scanning": [("T1595", 0.9)],
    "bot_attack": [("T1595", 0.6)],
    "api_abuse": [("T1190", 0.5)],
    "ddos_pattern": [("T1498", 0.8)],
    "rate_anomaly": [("T1498", 0.4)],
    "malware_upload": [("T1105", 0.8)],
    "honeypot": [("T1595", 0.7)],
}


def seed() -> None:
    with system_session() as db:
        for tid, (name, tactic, is_sub, parent) in TECHNIQUES.items():
            db.execute(text("""
                INSERT INTO attack_techniques(technique_id,name,tactic,is_subtechnique,parent_id,url)
                VALUES (:t,:n,:ta,:s,:p,:u)
                ON CONFLICT (technique_id) DO UPDATE SET name=:n, tactic=:ta"""),
                {"t": tid, "n": name, "ta": tactic, "s": is_sub, "p": parent,
                 "u": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"})
        for key, maps in DETECTION_MAP.items():
            for tid, conf in maps:
                db.execute(text("""
                    INSERT INTO detection_attack_map(detection_key,technique_id,confidence)
                    VALUES (:k,:t,:c) ON CONFLICT DO NOTHING"""),
                    {"k": key, "t": tid, "c": conf})


def techniques_for(threat_types: list[str]) -> list[dict]:
    """Used by the ingest pipeline to tag an incident with ATT&CK techniques."""
    out, seen = [], set()
    for tt in threat_types or []:
        for tid, conf in DETECTION_MAP.get(tt, []):
            if tid in seen:
                continue
            seen.add(tid)
            name, tactic, *_ = TECHNIQUES[tid]
            out.append({"technique_id": tid, "name": name, "tactic": tactic, "confidence": conf})
    return out


@router.get("/techniques")
def list_techniques(user: Principal = Depends(require("read_only"))):
    rows = user.db.execute(text("SELECT technique_id,name,tactic,is_subtechnique FROM attack_techniques")).all()
    return [{"technique_id": r[0], "name": r[1], "tactic": r[2], "sub": r[3]} for r in rows]


@router.get("/coverage")
def coverage(days: int = 30, user: Principal = Depends(require("read_only"))):
    """Heatmap: per technique, how many incidents in the window mapped to it."""
    if "sqlite" in user.db.bind.url.drivername:
        query = "SELECT threat_types FROM incidents WHERE created_at >= datetime('now', '-' || :d || ' days')"
    else:
        query = "SELECT threat_types FROM incidents WHERE created_at >= now() - (:d || ' days')::interval"
    incs = user.db.execute(text(query), {"d": days}).all()
    counts: dict[str, int] = {}
    for (types,) in incs:
        if isinstance(types, str):          # SQLite returns JSON columns as strings
            import json as _j
            try:
                types = _j.loads(types)
            except (ValueError, TypeError):
                types = []
        for t in techniques_for(types or []):
            counts[t["technique_id"]] = counts.get(t["technique_id"], 0) + 1
    cells = []
    for tid, (name, tactic, is_sub, _p) in TECHNIQUES.items():
        cells.append({"technique_id": tid, "name": name, "tactic": tactic,
                      "observed": counts.get(tid, 0),
                      "detection": tid in {m[0] for ms in DETECTION_MAP.values() for m in ms}})
    return {"window_days": days, "cells": cells,
            "tactics": sorted({c["tactic"] for c in cells})}


@router.get("/report")
def executive_report(days: int = 30, user: Principal = Depends(require("read_only"))):
    cov = coverage(days, user)
    by_tactic: dict[str, int] = {}
    for c in cov["cells"]:
        by_tactic[c["tactic"]] = by_tactic.get(c["tactic"], 0) + c["observed"]
    top = sorted(cov["cells"], key=lambda c: c["observed"], reverse=True)[:10]
    return {"window_days": days, "activity_by_tactic": by_tactic,
            "top_techniques": [t for t in top if t["observed"] > 0],
            "techniques_with_detection": sum(c["detection"] for c in cov["cells"]),
            "techniques_total": len(cov["cells"])}
