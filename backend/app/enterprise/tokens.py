"""Access tokens (RS256 JWT, short-lived) + opaque refresh tokens with rotation,
reuse-detection and revocation. Replaces the hand-rolled HMAC JWT entirely."""
import datetime as dt
import hashlib
import secrets
import uuid

import jwt  # PyJWT
from sqlalchemy.orm import Session

from . import keys
from .models import RefreshSession
from .settings import get_settings


# ── Access tokens ────────────────────────────────────────────────────────
def issue_access(db: Session, *, user_id: int, email: str, org_id: str,
                 role: str, mfa: bool) -> str:
    s = get_settings()
    key = keys.get_active(db)
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "iss": s.issuer, "aud": s.audience,
        "sub": str(user_id), "email": email,
        "org": str(org_id), "role": role, "mfa": mfa,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(seconds=s.access_ttl_seconds)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, keys.private_pem(key), algorithm="RS256",
                      headers={"kid": key.kid})


def verify_access(db: Session, token: str) -> dict:
    s = get_settings()
    header = jwt.get_unverified_header(token)
    key = db.get(__import__("app.enterprise.models", fromlist=["SigningKey"]).SigningKey,
                 header.get("kid"))
    if key is None or key.status == "revoked":
        raise jwt.InvalidTokenError("unknown or revoked signing key")
    return jwt.decode(token, key.public_pem, algorithms=["RS256"],
                      audience=s.audience, issuer=s.issuer)


# ── Refresh tokens (opaque, hashed at rest, single-use, rotated) ─────────
def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_refresh(db: Session, *, user_id: int, org_id,
                  ip: str = "", ua: str = "", parent_id=None) -> str:
    s = get_settings()
    token = secrets.token_urlsafe(48)
    _org_id = uuid.UUID(str(org_id))   # normalise to uuid.UUID for Uuid(as_uuid=True) bind processor
    row = RefreshSession(
        user_id=user_id, org_id=_org_id, token_hash=_hash(token),
        parent_id=parent_id, user_agent=ua[:300], ip=ip or None,
        expires_at=dt.datetime.now(dt.timezone.utc)
        + dt.timedelta(seconds=s.refresh_ttl_seconds),
    )
    db.add(row)
    db.flush()
    return token


def rotate_refresh(db: Session, token: str, *, ip: str = "", ua: str = ""):
    """Validate + rotate. Detects reuse of an already-rotated token and revokes
    the whole chain (token-theft response)."""
    now = dt.datetime.now(dt.timezone.utc)
    row = db.query(RefreshSession).filter(RefreshSession.token_hash == _hash(token)).first()
    if row is None or row.expires_at < now:
        return None
    if row.revoked_at is not None:
        # Reuse of a rotated/revoked token => compromise. Kill the user's chain.
        _revoke_user(db, row.user_id)
        db.commit()
        return None
    row.revoked_at = now
    row.last_used_at = now
    new = issue_refresh(db, user_id=row.user_id, org_id=str(row.org_id),
                        ip=ip, ua=ua, parent_id=row.id)
    return row, new


def revoke(db: Session, token: str) -> None:
    row = db.query(RefreshSession).filter(RefreshSession.token_hash == _hash(token)).first()
    if row and row.revoked_at is None:
        row.revoked_at = dt.datetime.now(dt.timezone.utc)


def _revoke_user(db: Session, user_id: int) -> None:
    db.query(RefreshSession).filter(
        RefreshSession.user_id == user_id,
        RefreshSession.revoked_at.is_(None),
    ).update({"revoked_at": dt.datetime.now(dt.timezone.utc)})


def revoke_all_for_user(db: Session, user_id: int) -> None:
    """Global logout / forced session revocation (e.g. after password reset)."""
    _revoke_user(db, user_id)
    db.commit()
