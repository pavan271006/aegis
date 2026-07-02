"""Threat Intelligence Platform: poll STIX 2.x feeds over TAXII 2.1, store
indicators + threat actors, match observed IOCs from incidents, and record
sightings that enrich the incident with actor/campaign attribution."""
import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text

from . import crypto
from .deps import Principal, require

router = APIRouter(prefix="/api/v2/tip", tags=["tip"])

# Minimal STIX pattern extractors -> (indicator_type, value)
_PATTERNS = [
    ("ipv4", re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'")),
    ("domain", re.compile(r"domain-name:value\s*=\s*'([^']+)'")),
    ("url", re.compile(r"url:value\s*=\s*'([^']+)'")),
    ("sha256", re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'", re.I)),
]


def _parse_pattern(pattern: str):
    for typ, rx in _PATTERNS:
        m = rx.search(pattern or "")
        if m:
            return typ, m.group(1)
    return None, None


# ── polling ────────────────────────────────────────────────────────────────
def poll_feed(db, feed_row) -> int:
    """Pull a TAXII collection and upsert indicators/actors. Returns #ingested."""
    from taxii2client.v21 import Collection  # lazy (optional dependency)
    import json

    auth = crypto.decrypt(feed_row.auth_enc).decode() if feed_row.auth_enc else ""
    headers = {"Authorization": auth} if auth else {}
    col = Collection(f"{feed_row.api_root.rstrip('/')}/collections/{feed_row.collection}/",
                     headers=headers)
    count = 0
    for obj in col.get_objects().get("objects", []):
        if obj.get("type") == "threat-actor":
            db.execute(text("""
                INSERT INTO threat_actors(org_id,stix_id,name,aliases,description,source)
                VALUES (:o,:s,:n,:a,:d,:src) ON CONFLICT DO NOTHING"""),
                {"o": str(feed_row.org_id), "s": obj["id"], "n": obj.get("name", ""),
                 "a": obj.get("aliases", []), "d": obj.get("description", ""), "src": feed_row.name})
        elif obj.get("type") == "indicator":
            typ, val = _parse_pattern(obj.get("pattern", ""))
            if not typ:
                continue
            db.execute(text("""
                INSERT INTO indicators(org_id,type,value,confidence,source,valid_until,labels)
                VALUES (:o,:t,:v,:c,:s,:vu,:l)
                ON CONFLICT (org_id,type,value)
                DO UPDATE SET confidence=:c, valid_until=:vu"""),
                {"o": str(feed_row.org_id), "t": typ, "v": val,
                 "c": int(obj.get("confidence", 50)), "s": feed_row.name,
                 "vu": obj.get("valid_until"), "l": obj.get("labels", [])})
            count += 1
    import datetime as _dt
    db.execute(text("UPDATE taxii_feeds SET last_poll_at=:now WHERE id=:i"),
               {"i": str(feed_row.id), "now": _dt.datetime.now(_dt.timezone.utc)})
    return count


# ── matching + enrichment (called from ingest / incident view) ─────────────
def match(db, observables: list[tuple[str, str]]) -> list[dict]:
    """observables = [(type, value), ...] -> matching indicators (RLS-scoped)."""
    hits = []
    for typ, val in observables:
        import datetime as _dt
        rows = db.execute(text("""
            SELECT id,type,value,confidence,source,labels FROM indicators
            WHERE type=:t AND value=:v AND (valid_until IS NULL OR valid_until > :now)"""),
            {"t": typ, "v": val, "now": _dt.datetime.now(_dt.timezone.utc)}).all()
        for r in rows:
            hits.append({"indicator_id": str(r[0]), "type": r[1], "value": r[2],
                         "confidence": r[3], "source": r[4], "labels": list(r[5] or [])})
    return hits


def enrich_incident(db, incident_id: int, source_ip: str) -> list[dict]:
    hits = match(db, [("ipv4", source_ip)])
    for h in hits:
        db.execute(text("""
            INSERT INTO sightings(org_id,indicator_id,incident_id,observed,context)
            SELECT org_id,:ind,:inc,:obs,'{}' FROM indicators WHERE id=:ind"""),
            {"ind": h["indicator_id"], "inc": incident_id, "obs": source_ip})
    return hits


# ── endpoints ───────────────────────────────────────────────────────────────
class FeedIn(BaseModel):
    name: str
    api_root: str
    collection: str
    auth: str | None = None


@router.post("/feeds")
def add_feed(body: FeedIn, user: Principal = Depends(require("admin"))):
    enc = crypto.encrypt(body.auth.encode()) if body.auth else None
    user.db.execute(text("""
        INSERT INTO taxii_feeds(org_id,name,api_root,collection,auth_enc)
        VALUES (:o,:n,:r,:c,:a)"""),
        {"o": user.org_id, "n": body.name, "r": body.api_root, "c": body.collection, "a": enc})
    return {"ok": True}


@router.post("/poll")
def poll_now(user: Principal = Depends(require("admin"))):
    feeds = user.db.execute(text(
        "SELECT id,org_id,name,api_root,collection,auth_enc FROM taxii_feeds WHERE enabled")).all()
    total = 0
    for f in feeds:
        class _F: pass
        fr = _F()
        fr.id, fr.org_id, fr.name, fr.api_root, fr.collection, fr.auth_enc = f
        try:
            total += poll_feed(user.db, fr)
        except Exception as e:   # noqa: BLE001
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"feed {fr.name}: {e}")
    return {"ingested": total}


@router.get("/indicators")
def search_indicators(type: str | None = None, value: str | None = None,
                      user: Principal = Depends(require("read_only"))):
    sql = "SELECT type,value,confidence,source,valid_until FROM indicators WHERE 1=1"
    params = {}
    if type:
        sql += " AND type=:t"; params["t"] = type
    if value:
        sql += " AND value LIKE :v"; params["v"] = f"%{value}%"
    rows = user.db.execute(text(sql + " ORDER BY confidence DESC LIMIT 200"), params).all()
    return [{"type": r[0], "value": r[1], "confidence": r[2], "source": r[3],
             # SQLite returns DateTime columns as strings; Postgres as datetimes.
             "valid_until": r[4].isoformat() if hasattr(r[4], "isoformat") else (r[4] or None)}
            for r in rows]


@router.get("/actors")
def actors(user: Principal = Depends(require("read_only"))):
    rows = user.db.execute(text("SELECT name,aliases,description,source FROM threat_actors LIMIT 200")).all()
    def _aliases(v):
        if isinstance(v, str):              # SQLite returns JSON columns as strings
            import json as _j
            try:
                return list(_j.loads(v) or [])
            except (ValueError, TypeError):
                return []
        return list(v or [])
    return [{"name": r[0], "aliases": _aliases(r[1]), "description": r[2], "source": r[3]} for r in rows]
