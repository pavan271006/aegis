"""Phase-2 ORM models: IdP connections (SSO), SCIM tokens, SIEM connections."""
import datetime as dt
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, LargeBinary, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import relationship

from ..database import Base


def _uuid():
    return uuid.uuid4()


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class IdpConnection(Base):
    __tablename__ = "idp_connections"
    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    kind = Column(Text, nullable=False)               # oidc | saml
    name = Column(Text, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    # OIDC
    issuer = Column(Text)
    client_id = Column(Text)
    client_secret_enc = Column(LargeBinary)
    # SAML
    idp_metadata_xml = Column(Text)
    sp_entity_id = Column(Text)
    acs_url = Column(Text)
    # shared
    default_role = Column(Text, nullable=False, default="read_only")
    attr_mapping = Column(JSONB, nullable=False, default=dict)
    email_domains = Column(ARRAY(Text), nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ScimToken(Base):
    __tablename__ = "scim_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(Text, nullable=False, unique=True)
    label = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)
    last_used_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))


class SiemConnection(Base):
    __tablename__ = "siem_connections"
    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    kind = Column(Text, nullable=False)   # splunk_hec|sentinel|elastic|syslog|chronicle|webhook
    name = Column(Text, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    endpoint = Column(Text, nullable=False)
    secret_enc = Column(LargeBinary)
    format = Column(Text, nullable=False, default="json")   # json | cef
    options = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    last_ok_at = Column(DateTime(timezone=True))
    last_error = Column(Text)
