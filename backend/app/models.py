"""ORM models. Types are kept portable so the same models run on SQLite (dev)
and PostgreSQL (prod). The canonical Postgres DDL is in db/init.sql."""
import datetime as dt

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text, Uuid,
)
from sqlalchemy.orm import relationship

from .database import Base
from .config import settings

def org_id_column():
    # as_uuid=False stores org_id as a plain string (no uuid.UUID bind processor that
    # calls .hex on the value) — portable across SQLite and Postgres, and consistent
    # with the enterprise models (see enterprise/models*.py UUID_TYPE).
    if settings.database_url.startswith("sqlite"):
        return Column(Uuid(as_uuid=False), nullable=True)
    return Column(Uuid(as_uuid=False), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class Site(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    url = Column(String(500), nullable=False)
    cf_zone_id = Column(String(120), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)
    org_id = org_id_column()

    incidents = relationship("Incident", back_populates="site")


class Event(Base):
    """A single observed request (from logs, webhook, or CrowdSec)."""
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)
    ip = Column(String(64), index=True)
    method = Column(String(10))
    path = Column(Text)
    status = Column(Integer)
    user_agent = Column(Text)
    geo = Column(String(120), default="")
    source = Column(String(40), default="log")   # log | webhook | crowdsec | honeypot
    org_id = org_id_column()


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True)
    source_ip = Column(String(64), index=True)
    threat_types = Column(JSON)                  # ["sql_injection", ...]
    severity = Column(String(10), index=True)    # low | medium | high
    status = Column(String(20), default="open")  # open | contained | resolved
    request_count = Column(Integer, default=0)
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    root_cause = Column(Text, default="")
    timeline = Column(JSON)                       # ordered list of steps
    report = Column(JSON)                         # full explainable report
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    org_id = org_id_column()

    site = relationship("Site", back_populates="incidents")
    actions = relationship("Action", back_populates="incident")


class Action(Base):
    """An autonomous (or queued) remediation action."""
    __tablename__ = "actions"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    type = Column(String(40))                     # block_ip | rate_limit | quarantine | revoke_session
    provider = Column(String(40))                 # cloudflare | crowdsec | internal
    mode = Column(String(20))                     # dry-run | approval | auto
    status = Column(String(30))                   # planned | pending_approval | applied | failed | expired
    params = Column(JSON)
    rule_ref = Column(String(200), default="")    # provider rule id, for rollback
    verified = Column(Boolean, default=False)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    org_id = org_id_column()

    incident = relationship("Incident", back_populates="actions")


class AuditLog(Base):
    """Tamper-evident-ish record of everything the system or founder did."""
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)
    actor = Column(String(40), default="system")  # system | founder
    action = Column(String(80))
    details = Column(JSON)
    org_id = org_id_column()
    prev_hash = Column(Text, nullable=True)
    entry_hash = Column(Text, nullable=True)


class MonitoringCheck(Base):
    __tablename__ = "monitoring_checks"
    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)
    up = Column(Boolean)
    status_code = Column(Integer)
    response_ms = Column(Integer)
    ssl_days_left = Column(Integer)
    missing_headers = Column(JSON)
    org_id = org_id_column()


class Allowlist(Base):
    """Self-protection: never block these (your own IPs, monitoring, office)."""
    __tablename__ = "allowlist"
    id = Column(Integer, primary_key=True)
    value = Column(String(64), unique=True)        # IP or CIDR
    note = Column(String(200), default="")
    org_id = org_id_column()


class Honeypot(Base):
    """Fake paths. Any hit is automatically malicious -> instant high-signal."""
    __tablename__ = "honeypots"
    id = Column(Integer, primary_key=True)
    path = Column(String(300), unique=True)        # e.g. /.env, /wp-admin/setup
    note = Column(String(200), default="")
    org_id = org_id_column()


class QuarantinedFile(Base):
    """Files quarantined by the upload safety check."""
    __tablename__ = "quarantined_files"
    id = Column(Integer, primary_key=True)
    original_name = Column(String(500))
    quarantine_path = Column(String(500))
    content_type = Column(String(100), default="")
    size_bytes = Column(Integer, default=0)
    reason = Column(Text, default="")
    status = Column(String(20), default="quarantined")  # quarantined | released | deleted
    uploaded_by_ip = Column(String(64), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)
    org_id = org_id_column()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    role = Column(String(20), default="read_only")  # admin | analyst | read_only
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    
    # Enterprise fields
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    password_changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    failed_logins = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    is_superuser = Column(Boolean, default=False, nullable=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True)
    url = Column(String(500), nullable=False)
    parameter = Column(String(120), default="")
    vuln_type = Column(String(50))  # sqli | xss | idor
    severity = Column(String(10), default="high")
    evidence = Column(Text, default="")
    status = Column(String(20), default="open")  # open | resolved | false_positive
    created_at = Column(DateTime(timezone=True), default=utcnow)
    org_id = org_id_column()


class PostureTrend(Base):
    __tablename__ = "posture_trends"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)
    score = Column(Integer, nullable=False)
    org_id = org_id_column()

