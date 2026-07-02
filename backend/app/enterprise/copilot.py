"""Security Copilot: natural-language Q&A, incident explanations, and daily
summaries grounded in the tenant's OWN data (RAG).

Guardrails (non-negotiable):
  - retrieval is RLS-scoped -> a tenant can only ever see its own incidents/cases;
  - the model is read-only: NO tools, NO actions, it can only explain/summarize;
  - provider-agnostic gateway (OpenAI / Anthropic / Azure OpenAI) via env, so no
    secret is hard-coded and the LLM call fails closed if unconfigured;
  - every answer cites the source records it used."""
import os

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text

from .deps import Principal, require

router = APIRouter(prefix="/api/v2/copilot", tags=["copilot"])

SYSTEM = (
    "You are AEGIS Copilot, a read-only security analyst assistant. You may only "
    "explain, summarize, and answer questions using the CONTEXT provided. Never "
    "invent data, never recommend or take blocking/remediation actions, never "
    "reveal secrets or tokens. If the context is insufficient, say so. Cite the "
    "incident/case IDs you used."
)


# ── provider gateway ───────────────────────────────────────────────────────
def _complete(messages: list[dict]) -> str:
    provider = os.getenv("AEGIS_LLM_PROVIDER", "")
    key = os.getenv("AEGIS_LLM_API_KEY", "")
    model = os.getenv("AEGIS_LLM_MODEL", "")
    if not provider or not key:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Copilot LLM provider not configured")
    if provider == "anthropic":
        sys = next((m["content"] for m in messages if m["role"] == "system"), "")
        r = httpx.post("https://api.anthropic.com/v1/messages", timeout=40, headers={
            "x-api-key": key, "anthropic-version": "2023-06-01"},
            json={"model": model or "claude-sonnet-4-6", "max_tokens": 800, "system": sys,
                  "messages": [m for m in messages if m["role"] != "system"]})
        r.raise_for_status()
        return r.json()["content"][0]["text"]
    # OpenAI / Azure-compatible
    base = os.getenv("AEGIS_LLM_BASE_URL", "https://api.openai.com/v1")
    r = httpx.post(f"{base}/chat/completions", timeout=40,
                   headers={"Authorization": f"Bearer {key}"},
                   json={"model": model or "gpt-4o-mini", "messages": messages,
                         "max_tokens": 800, "temperature": 0.2})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _guard_output(text_out: str) -> str:
    # Strip anything resembling a token/secret that slipped into context.
    import re
    return re.sub(r"(?i)(bearer|api[_-]?key|secret)\s*[:=]\s*\S+", r"\1: [redacted]", text_out)[:4000]


# ── retrieval (tenant-scoped) ──────────────────────────────────────────────
def _recent_incidents(db, days: int, like: str | None = None, limit: int = 25):
    import datetime as _dt
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days)
    sql = ("SELECT id, source_ip, severity, status, threat_types, created_at, report "
           "FROM incidents WHERE created_at >= :cutoff")
    params: dict = {"cutoff": cutoff}
    if like:
        sql += " AND (source_ip LIKE :q OR CAST(threat_types AS TEXT) LIKE :q)"
        params["q"] = f"%{like}%"
    sql += " ORDER BY created_at DESC LIMIT :lim"
    params["lim"] = limit
    return db.execute(text(sql), params).all()


def _ctx_block(rows) -> tuple[str, list[str]]:
    lines, ids = [], []
    for r in rows:
        ids.append(str(r[0]))
        rpt = r[6] or {}
        lines.append(f"- incident {r[0]}: ip={r[1]} sev={r[2]} status={r[3]} "
                     f"threats={r[4]} root_cause={rpt.get('root_cause','')[:200]}")
    return "\n".join(lines), ids


# ── endpoints ───────────────────────────────────────────────────────────────
class AskIn(BaseModel):
    question: str
    days: int = 7


@router.post("/ask")
def ask(body: AskIn, user: Principal = Depends(require("read_only"))):
    rows = _recent_incidents(user.db, body.days, like=_keyword(body.question))
    ctx, ids = _ctx_block(rows)
    answer = _complete([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"CONTEXT:\n{ctx}\n\nQUESTION: {body.question}"},
    ])
    return {"answer": _guard_output(answer), "sources": ids}


@router.post("/explain/{incident_id}")
def explain(incident_id: int, user: Principal = Depends(require("read_only"))):
    row = user.db.execute(text(
        "SELECT id,source_ip,severity,status,threat_types,report FROM incidents WHERE id=:i"),
        {"i": incident_id}).first()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    rpt = row[5] or {}
    ctx = (f"incident {row[0]}: ip={row[1]} severity={row[2]} status={row[3]} "
           f"threats={row[4]} actions={rpt.get('actions_taken','')} "
           f"verification={rpt.get('verification_result','')} root_cause={rpt.get('root_cause','')}")
    answer = _complete([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"CONTEXT:\n{ctx}\n\nQUESTION: Why was this blocked? "
                                    f"Explain in plain language for an operator."},
    ])
    return {"answer": _guard_output(answer), "sources": [str(incident_id)]}


@router.post("/summary")
def summary(days: int = 1, user: Principal = Depends(require("read_only"))):
    rows = _recent_incidents(user.db, days, limit=50)
    ctx, ids = _ctx_block(rows)
    answer = _complete([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"CONTEXT:\n{ctx}\n\nQUESTION: Summarize the security "
                                    f"activity in the last {days} day(s): notable threats, "
                                    f"affected assets, and what needs analyst attention."},
    ])
    return {"answer": _guard_output(answer), "sources": ids}


def _keyword(q: str) -> str | None:
    import re
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", q)        # an IP in the question
    if m:
        return m.group(1)
    for w in ("sql", "xss", "brute", "credential", "bot", "ddos", "scan", "honeypot"):
        if w in q.lower():
            return w
    return None
