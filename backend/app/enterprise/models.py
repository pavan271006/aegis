"""Phase-1 ORM models. Reuses the existing declarative Base so they live in the
same metadata as the legacy models (users, sites, incidents, ...)."""
import datetime as dt
import uuid

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text, LargeBinary, Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import relationship

from ..database import Base
from ..config import settings

is_sqlite = settings.database_url.startswith("sqlite")
UUID_TYPE = Uuid(as_uuid=False)  # store as plain string; no .hex bind-processor issues on SQLite
JSON_TYPE = JSONB
if is_sqlite:
    from sqlalchemy import JSON, String
    JSON_TYPE = JSON
    INET_TYPE = String(45)
else:
    INET_TYPE = INET


def _uuid():
    return str(uuid.uuid4())


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    name = Column(Text, nullable=False)
    slug = Column(Text, nullable=False, unique=True)
    plan = Column(Text, nullable=False, default="free")
    status = Column(Text, nullable=False, default="active")
    settings = Column(JSON_TYPE, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    memberships = relationship("Membership", back_populates="organization")


class Membership(Base):
    """Tenant-scoped RBAC: a user's role *within a specific org*."""
    __tablename__ = "memberships"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False, default="read_only")  # owner|admin|analyst|read_only
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    organization = relationship("Organization", back_populates="memberships")


class RefreshSession(Base):
    __tablename__ = "refresh_sessions"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    org_id = Column(UUID_TYPE, ForeignKey("organizations.id", ondelete="CASCADE"))
    token_hash = Column(Text, nullable=False, unique=True)
    parent_id = Column(UUID_TYPE, ForeignKey("refresh_sessions.id", ondelete="SET NULL"))
    user_agent = Column(Text, default="")
    ip = Column(INET_TYPE)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    last_used_at = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))


class SigningKey(Base):
    __tablename__ = "signing_keys"
    kid = Column(Text, primary_key=True)
    alg = Column(Text, nullable=False, default="RS256")
    public_pem = Column(Text, nullable=False)
    private_pem_enc = Column(LargeBinary, nullable=False)
    status = Column(Text, nullable=False, default="active")  # active|retiring|revoked
    created_at = Column(DateTime(timezone=True), default=utcnow)
    not_after = Column(DateTime(timezone=True))


class MfaCredential(Base):
    __tablename__ = "mfa_credentials"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type = Column(Text, nullable=False, default="totp")
    secret_enc = Column(LargeBinary, nullable=False)
    confirmed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class MfaBackupCode(Base):
    __tablename__ = "mfa_backup_codes"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code_hash = Column(Text, nullable=False)
    used_at = Column(DateTime(timezone=True))


class PasswordHistory(Base):
    __tablename__ = "password_history"
    id = Column(UUID_TYPE, primary_key=True, default=_uuid)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    hashed_password = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
