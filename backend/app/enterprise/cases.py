"""Incident case management: ownership/assignment, SLA timers, escalation,
investigation notes, an append-only timeline, and a declarative playbook engine.

State changes emit a `case.*` event to the SIEM forwarder and a timeline entry,
so the SOC's external tooling stays in sync and the case is audit-defensible."""
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import siem
from .deps import Principal, require
from .models_p3 import (
    Case, CaseEvent, CaseIncident, CaseNote, EscalationRule, Playbook,
    PlaybookRun, SlaPolicy,
)

router = APIRouter(prefix="/api/v2/cases", tags=["cases"])


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _event(db: Session, case: Case, type_: str, actor: str, data: dict | None = None):
    db.add(CaseEvent(org_id=case.org_id, case_id=case.id, type=type_, actor=actor, data=data or {}))
    siem.emit(str(case.org_id), f"case.{type_}",
              {"case_id": str(case.id), "title": case.title, "severity": case.severity,
               "status": case.status, "actor": actor, **(data or {})})


def _apply_sla(db: Session, case: Case):
    pol = (db.query(SlaPolicy)
             .filter(SlaPolicy.severity == case.severity).first())
    if pol:
        case.sla_response_due = case.opened_at + dt.timedelta(minutes=pol.first_response_mins)
        case.sla_resolve_due = case.opened_at + dt.timedelta(minutes=pol.resolution_mins)


# ── endpoints ───────────────────────────────────────────────────────────────
class CaseIn(BaseModel):
    title: str
    severity: str = "medium"
    priority: str = "p3"
    from_incident: int | None = None
    assignee_id: int | None = None


@router.post("", status_code=201)
def create_case(body: CaseIn, user: Principal = Depends(require("analyst"))):
    db = user.db
    case = Case(org_id=user.org_id, title=body.title, severity=body.severity,
                priority=body.priority, created_by=user.user_id, assignee_id=body.assignee_id)
    db.add(case)
    db.flush()
    _apply_sla(db, case)
    _event(db, case, "created", user.email, {"from_incident": body.from_incident})
    if body.from_incident:
        db.add(CaseIncident(case_id=case.id, incident_id=body.from_incident, org_id=user.org_id))
    return _case_dto(case)


@router.get("")
def list_cases(status_filter: str | None = None, assignee_id: int | None = None,
               breached: bool | None = None, user: Principal = Depends(require("read_only"))):
    q = user.db.query(Case)
    if status_filter:
        q = q.filter(Case.status == status_filter)
    if assignee_id:
        q = q.filter(Case.assignee_id == assignee_id)
    if breached is not None:
        q = q.filter(Case.sla_breached.is_(breached))
    return [_case_dto(c) for c in q.order_by(Case.opened_at.desc()).limit(200).all()]


@router.get("/{case_id}")
def get_case(case_id: str, user: Principal = Depends(require("read_only"))):
    case = _get(user.db, case_id)
    notes = (user.db.query(CaseNote).filter(CaseNote.case_id == case.id)
             .order_by(CaseNote.created_at.asc()).all())
    return {**_case_dto(case),
            "notes": [{"author_id": n.author_id, "body": n.body, "internal": n.internal,
                       "at": n.created_at.isoformat()} for n in notes]}


@router.get("/{case_id}/timeline")
def timeline(case_id: str, user: Principal = Depends(require("read_only"))):
    case = _get(user.db, case_id)
    evs = (user.db.query(CaseEvent).filter(CaseEvent.case_id == case.id)
           .order_by(CaseEvent.created_at.asc()).all())
    return [{"type": e.type, "actor": e.actor, "data": e.data, "at": e.created_at.isoformat()}
            for e in evs]


class AssignIn(BaseModel):
    assignee_id: int


@router.post("/{case_id}/assign")
def assign(case_id: str, body: AssignIn, user: Principal = Depends(require("analyst"))):
    case = _get(user.db, case_id)
    case.assignee_id = body.assignee_id
    _event(user.db, case, "assign", user.email, {"assignee_id": body.assignee_id})
    return _case_dto(case)


class StatusIn(BaseModel):
    status: str


@router.post("/{case_id}/status")
def change_status(case_id: str, body: StatusIn, user: Principal = Depends(require("analyst"))):
    valid = {"open", "investigating", "contained", "resolved", "closed"}
    if body.status not in valid:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid status")
    case = _get(user.db, case_id)
    prev = case.status
    case.status = body.status
    now = _now()
    if prev == "open" and not case.first_response_at:
        case.first_response_at = now            # stops the response-SLA clock
    if body.status == "resolved" and not case.resolved_at:
        case.resolved_at = now
    if body.status == "closed":
        case.closed_at = now
    _event(user.db, case, "status", user.email, {"from": prev, "to": body.status})
    return _case_dto(case)


class NoteIn(BaseModel):
    body: str
    internal: bool = True


@router.post("/{case_id}/notes")
def add_note(case_id: str, body: NoteIn, user: Principal = Depends(require("analyst"))):
    case = _get(user.db, case_id)
    user.db.add(CaseNote(org_id=case.org_id, case_id=case.id, author_id=user.user_id,
                         body=body.body, internal=body.internal))
    _event(user.db, case, "note", user.email, {"internal": body.internal})
    return {"ok": True}


@router.post("/{case_id}/run-playbook")
def run_playbook(case_id: str, playbook_id: str, user: Principal = Depends(require("analyst"))):
    case = _get(user.db, case_id)
    pb = user.db.get(Playbook, playbook_id)
    if not pb or not pb.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "playbook not found")
    run = PlaybookRun(org_id=case.org_id, playbook_id=pb.id, case_id=case.id)
    user.db.add(run)
    user.db.flush()
    _execute_playbook(user.db, run, pb, case, user.email)
    return {"run_id": str(run.id), "status": run.status, "log": run.log}


# ── playbook engine (declarative steps) ────────────────────────────────────
def _execute_playbook(db: Session, run: PlaybookRun, pb: Playbook, case: Case, actor: str):
    log = []
    for i, step in enumerate(pb.steps or []):
        run.current_step = i
        action = step.get("action")
        try:
            if action == "note":
                db.add(CaseNote(org_id=case.org_id, case_id=case.id, author_id=None,
                                body=step.get("body", ""), internal=True))
            elif action == "assign":
                case.assignee_id = step.get("user_id")
            elif action == "status":
                case.status = step.get("to", case.status)
            elif action == "notify":
                siem.emit(str(case.org_id), "case.notify",
                          {"case_id": str(case.id), "channel": step.get("channel")})
            elif action == "siem":
                siem.emit(str(case.org_id), step.get("type", "case.custom"),
                          {"case_id": str(case.id), **step.get("payload", {})})
            else:
                log.append({"step": i, "skipped": action})
                continue
            log.append({"step": i, "action": action, "ok": True})
        except Exception as e:  # noqa: BLE001
            log.append({"step": i, "action": action, "error": str(e)[:200]})
            run.status = "failed"
            break
    else:
        run.status = "completed"
    run.log = log
    run.finished_at = _now()
    _event(db, case, "playbook", actor, {"playbook": pb.name, "status": run.status})


# ── SLA + escalation sweep (called by the scheduler, system-wide) ──────────
def run_escalations(db: Session) -> int:
    """Per-org sweep: flag SLA breaches, fire escalation rules. Returns count."""
    now = _now()
    breached = (db.query(Case)
                .filter(Case.status.notin_(("resolved", "closed")),
                        Case.sla_breached.is_(False),
                        ((Case.sla_response_due.isnot(None) & (Case.sla_response_due < now)
                          & Case.first_response_at.is_(None))
                         | (Case.sla_resolve_due.isnot(None) & (Case.sla_resolve_due < now))))
                .all())
    rules = db.query(EscalationRule).filter(EscalationRule.enabled.is_(True)).all()
    for case in breached:
        case.sla_breached = True
        _event(db, case, "escalate", "system", {"reason": "sla_breached"})
        for rule in rules:
            act = rule.action or {}
            if act.get("reassign"):
                case.assignee_id = act["reassign"]
            if act.get("severity_bump"):
                case.severity = "high"
        try:
            from . import telemetry
            telemetry.DETECTIONS.labels(str(case.org_id), "sla_breach").inc()
        except Exception:
            pass
    return len(breached)


# ── helpers ─────────────────────────────────────────────────────────────────
def _get(db: Session, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if not case:                       # RLS already prevents cross-tenant reads
        raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
    return case


def _case_dto(c: Case) -> dict:
    return {"id": str(c.id), "title": c.title, "status": c.status, "severity": c.severity,
            "priority": c.priority, "assignee_id": c.assignee_id,
            "opened_at": c.opened_at.isoformat() if c.opened_at else None,
            "first_response_at": c.first_response_at.isoformat() if c.first_response_at else None,
            "resolved_at": c.resolved_at.isoformat() if c.resolved_at else None,
            "sla_response_due": c.sla_response_due.isoformat() if c.sla_response_due else None,
            "sla_resolve_due": c.sla_resolve_due.isoformat() if c.sla_resolve_due else None,
            "sla_breached": c.sla_breached, "tags": c.tags}
