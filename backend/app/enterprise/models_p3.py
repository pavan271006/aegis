"""Phase-3 ORM: agent platform + incident case management."""
import datetime as dt
import uuid

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, Text, Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from ..database import Base
from ..config import settings

is_sqlite = settings.database_url.startswith("sqlite")
UUID_TYPE = Uuid(as_uuid=True)
JSON_TYPE = JSONB
if is_sqlite:
    from sqlalchemy import JSON
    JSON_TYPE = JSON


def _uuid():
    return uuid.uuid4()


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


# ── Agent platform ─────────────────────────────────────────────────────────
class AgentCA(Base):
    __tablename__ = "agent_cas"
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    ca_cert_pem = Column(Text, nullable=False)
    ca_key_enc = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Agent(Base):
    __tablename__ = "agents"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    hostname = Column(Text, default="")
    status = Column(Text, nullable=False, default="enrolled")
    cert_serial = Column(Text, unique=True)
    cert_fpr = Column(Text)
    version = Column(Text, default="")
    channel = Column(Text, nullable=False, default="stable")
    labels = Column(JSON_TYPE, nullable=False, default=dict)
    health = Column(JSON_TYPE, nullable=False, default=dict)
    enrolled_at = Column(DateTime(timezone=True))
    last_seen_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AgentEnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(Text, nullable=False, unique=True)
    label = Column(Text, default="")
    max_uses = Column(Integer, nullable=False, default=1)
    uses = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AgentRelease(Base):
    __tablename__ = "agent_releases"
    version = Column(Text, primary_key=True)
    channel = Column(Text, nullable=False, default="stable")
    url = Column(Text, nullable=False)
    sha256 = Column(Text, nullable=False)
    signature = Column(Text, nullable=False)
    notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)


# ── Case management ─────────────────────────────────────────────────────────
class Case(Base):
    __tablename__ = "cases"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    title = Column(Text, nullable=False)
    status = Column(Text, nullable=False, default="open")
    severity = Column(Text, nullable=False, default="medium")
    priority = Column(Text, nullable=False, default="p3")
    assignee_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    tags = Column(JSON_TYPE, nullable=False, default=list)
    opened_at = Column(DateTime(timezone=True), default=utcnow)
    first_response_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))
    closed_at = Column(DateTime(timezone=True))
    sla_response_due = Column(DateTime(timezone=True))
    sla_resolve_due = Column(DateTime(timezone=True))
    sla_breached = Column(Boolean, nullable=False, default=False)


class CaseIncident(Base):
    __tablename__ = "case_incidents"
    case_id = Column(UUID_TYPE, ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)


class CaseNote(Base):
    __tablename__ = "case_notes"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    case_id = Column(UUID_TYPE, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    body = Column(Text, nullable=False)
    internal = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class CaseEvent(Base):
    __tablename__ = "case_events"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    case_id = Column(UUID_TYPE, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    type = Column(Text, nullable=False)
    actor = Column(Text, default="system")
    data = Column(JSON_TYPE, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class SlaPolicy(Base):
    __tablename__ = "sla_policies"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    severity = Column(Text, nullable=False)
    first_response_mins = Column(Integer, nullable=False)
    resolution_mins = Column(Integer, nullable=False)


class EscalationRule(Base):
    __tablename__ = "escalation_rules"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    condition = Column(JSON_TYPE, nullable=False, default=dict)
    after_mins = Column(Integer, nullable=False, default=0)
    action = Column(JSON_TYPE, nullable=False, default=dict)
    enabled = Column(Boolean, nullable=False, default=True)


class Playbook(Base):
    __tablename__ = "playbooks"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    trigger = Column(JSON_TYPE, nullable=False, default=dict)
    steps = Column(JSON_TYPE, nullable=False, default=list)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    playbook_id = Column(UUID_TYPE, ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    case_id = Column(UUID_TYPE, ForeignKey("cases.id", ondelete="CASCADE"))
    status = Column(Text, nullable=False, default="running")
    current_step = Column(Integer, nullable=False, default=0)
    log = Column(JSON_TYPE, nullable=False, default=list)
    started_at = Column(DateTime(timezone=True), default=utcnow)
    finished_at = Column(DateTime(timezone=True))
