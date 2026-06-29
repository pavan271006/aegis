"""Phase-4 ORM models: ATT&CK techniques, Threat Intel Platform, detection content, compliance."""
import datetime as dt
import uuid

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, Text, Float, String
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from ..database import Base
from ..config import settings

is_sqlite = settings.database_url.startswith("sqlite")
UUID_TYPE = UUID(as_uuid=True)
JSON_TYPE = JSONB
if is_sqlite:
    from sqlalchemy import JSON
    JSON_TYPE = JSON
    # SQLite does not support ARRAY type, so represent aliases/labels as JSON
    ARRAY_TEXT_TYPE = JSON
else:
    from sqlalchemy.dialects.postgresql import ARRAY
    ARRAY_TEXT_TYPE = ARRAY(Text)

def _uuid():
    return uuid.uuid4()

def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    technique_id = Column(Text, primary_key=True)
    name = Column(Text, nullable=False)
    tactic = Column(Text, nullable=False)
    url = Column(Text)
    is_subtechnique = Column(Boolean, nullable=False, default=False)
    parent_id = Column(Text)


class DetectionAttackMap(Base):
    __tablename__ = "detection_attack_map"
    detection_key = Column(Text, primary_key=True)
    technique_id = Column(Text, ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"), primary_key=True)
    confidence = Column(Float, nullable=False, default=1.0)


class TaxiiFeed(Base):
    __tablename__ = "taxii_feeds"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    api_root = Column(Text, nullable=False)
    collection = Column(Text, nullable=False)
    auth_enc = Column(LargeBinary)
    enabled = Column(Boolean, nullable=False, default=True)
    last_poll_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ThreatActor(Base):
    __tablename__ = "threat_actors"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    stix_id = Column(Text)
    name = Column(Text, nullable=False)
    aliases = Column(ARRAY_TEXT_TYPE, nullable=False, default=list)
    description = Column(Text, default="")
    source = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Indicator(Base):
    __tablename__ = "indicators"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    type = Column(Text, nullable=False)
    value = Column(Text, nullable=False)
    confidence = Column(Integer, nullable=False, default=50)
    source = Column(Text, default="")
    actor_id = Column(UUID_TYPE, ForeignKey("threat_actors.id", ondelete="SET NULL"))
    labels = Column(ARRAY_TEXT_TYPE, nullable=False, default=list)
    valid_until = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Sighting(Base):
    __tablename__ = "sightings"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    indicator_id = Column(UUID_TYPE, ForeignKey("indicators.id", ondelete="CASCADE"))
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"))
    observed = Column(Text, nullable=False)
    context = Column(JSON_TYPE, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    key = Column(Text, nullable=False)
    name = Column(Text, nullable=False)
    type = Column(Text, nullable=False, default="signature")
    enabled = Column(Boolean, nullable=False, default=True)
    current_version = Column(Integer, nullable=False, default=1)


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(UUID_TYPE, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)
    definition = Column(JSON_TYPE, nullable=False)
    author = Column(Text, default="")
    note = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)


class RuleTest(Base):
    __tablename__ = "rule_tests"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(UUID_TYPE, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    sample = Column(JSON_TYPE, nullable=False)
    expect_match = Column(Boolean, nullable=False)
    last_result = Column(Text)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    match = Column(JSON_TYPE, nullable=False)
    reason = Column(Text, default="")
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    expires_at = Column(DateTime(timezone=True))
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class RuleFeedback(Base):
    __tablename__ = "rule_feedback"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"))
    rule_key = Column(Text, nullable=False)
    verdict = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class RuleConfidence(Base):
    __tablename__ = "rule_confidence"
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    rule_key = Column(Text, primary_key=True)
    tp = Column(Integer, nullable=False, default=0)
    fp = Column(Integer, nullable=False, default=0)
    confidence = Column(Float, nullable=False, default=0.5)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    table_name = Column(Text, nullable=False)
    ttl_days = Column(Integer, nullable=False)
