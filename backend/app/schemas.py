"""Pydantic v2 request/response schemas."""
import datetime as dt
from typing import Any, Optional

from pydantic import BaseModel


class EventIn(BaseModel):
    ip: str
    method: str = "GET"
    path: str = "/"
    status: int = 200
    user_agent: str = ""
    ts: Optional[dt.datetime] = None
    source: str = "webhook"


class IngestRequest(BaseModel):
    site_id: int = 1
    # Either structured events...
    events: list[EventIn] = []
    # ...or raw combined-format log lines.
    log_lines: list[str] = []


class IngestResult(BaseModel):
    events_ingested: int
    incidents_created: int
    incident_ids: list[int]


class ActionOut(BaseModel):
    id: int
    type: str
    provider: str
    mode: str
    status: str
    verified: bool
    expires_at: Optional[dt.datetime] = None

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: int
    source_ip: str
    threat_types: Any
    severity: str
    status: str
    request_count: int
    first_seen: Optional[dt.datetime] = None
    last_seen: Optional[dt.datetime] = None
    root_cause: str
    report: Any
    created_at: dt.datetime
    actions: list[ActionOut] = []

    class Config:
        from_attributes = True


class DashboardOut(BaseModel):
    security_score: int
    threats_blocked: int
    active_incidents: int
    vulnerabilities_found: int
    system_health: str
    recent_reports: list[IncidentOut]


class SiteIn(BaseModel):
    name: str
    url: str
    cf_zone_id: str = ""


class AuditLogOut(BaseModel):
    id: int
    ts: dt.datetime
    actor: str
    action: str
    details: Any

    class Config:
        from_attributes = True


class MonitoringCheckOut(BaseModel):
    id: int
    site_id: int
    ts: dt.datetime
    up: Optional[bool]
    status_code: Optional[int]
    response_ms: Optional[int]
    ssl_days_left: Optional[int]
    missing_headers: Any

    class Config:
        from_attributes = True


class AllowlistOut(BaseModel):
    id: int
    value: str
    note: str

    class Config:
        from_attributes = True


class HoneypotOut(BaseModel):
    id: int
    path: str
    note: str

    class Config:
        from_attributes = True


class SiteOut(BaseModel):
    id: int
    name: str
    url: str
    cf_zone_id: str
    created_at: dt.datetime

    class Config:
        from_attributes = True


class QuarantineOut(BaseModel):
    id: int
    original_name: str
    content_type: str
    size_bytes: int
    reason: str
    status: str
    uploaded_by_ip: str
    created_at: dt.datetime

    class Config:
        from_attributes = True


class StatsOut(BaseModel):
    total_events: int
    total_incidents: int
    total_blocked: int
    events_24h: int
    incidents_24h: int
    top_threat_types: list
    top_source_ips: list
    severity_distribution: dict
    incidents_by_day: list

    class Config:
        from_attributes = True


class UserIn(BaseModel):
    email: str
    password: str
    role: str = "read_only"


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: dt.datetime

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class VulnerabilityOut(BaseModel):
    id: int
    site_id: int
    url: str
    parameter: str
    vuln_type: str
    severity: str
    evidence: str
    status: str
    created_at: dt.datetime

    class Config:
        from_attributes = True


class PostureTrendOut(BaseModel):
    ts: dt.datetime
    score: int

    class Config:
        from_attributes = True

