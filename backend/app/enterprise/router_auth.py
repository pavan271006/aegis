"""Enterprise auth endpoints (v2). Replaces /api/auth/*.

Flow:  POST /login  -> (mfa_required ? challenge : tokens)
       POST /mfa    -> tokens
       POST /refresh-> rotated tokens
       POST /logout -> revoke refresh
       GET  /orgs / POST /switch -> multi-org access
       MFA enrollment + JWKS.
"""
import datetime as dt
import os

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr

from ..models import User
from . import keys, mfa, passwords, tokens
from .deps import Principal, require
from .models import Membership, Organization
from .ratelimit import auth_throttle, limit
from .settings import get_settings
from .tenancy import tenant_session

router = APIRouter(prefix="/api/v2/auth", tags=["auth-v2"])
SENTINEL = "00000000-0000-0000-0000-000000000000"


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    org: str | None = None


class MfaIn(BaseModel):
    challenge: str
    code: str


class RefreshIn(BaseModel):
    refresh_token: str


def _default_org(db, user_id: int, requested: str | None) -> Membership | None:
    import uuid
    q = db.query(Membership).filter(Membership.user_id == user_id,
                                    Membership.status == "active")
    if requested:
        # Check if requested is a slug (e.g. "default")
        org = db.query(Organization).filter(Organization.slug == requested).first()
        if org:
            return q.filter(Membership.org_id == org.id).first()
        # Fallback to direct org_id query if it looks like a valid UUID string
        try:
            # as_uuid=False: pass normalised string, not uuid.UUID object
            return q.filter(Membership.org_id == str(uuid.UUID(requested))).first()
        except ValueError:
            return None
    return q.order_by(Membership.created_at.asc()).first()


def _issue_pair(db, user: User, m: Membership, mfa_ok: bool, request: Request) -> dict:
    access = tokens.issue_access(db, user_id=user.id, email=user.email,
                                 org_id=str(m.org_id), role=m.role, mfa=mfa_ok)
    ip = request.client.host if (request and request.client) else ""
    ua = request.headers.get("user-agent", "") if request else ""
    refresh = tokens.issue_refresh(db, user_id=user.id, org_id=str(m.org_id),
                                   ip=ip, ua=ua)
    return {"access_token": access, "refresh_token": refresh,
            "token_type": "bearer", "org_id": str(m.org_id), "role": m.role,
            "expires_in": get_settings().access_ttl_seconds}


def _mfa_challenge(db, user: User, m: Membership) -> str:
    key = keys.get_active(db)
    now = dt.datetime.now(dt.timezone.utc)
    return jwt.encode(
        {"sub": str(user.id), "org": str(m.org_id), "scope": "mfa",
         "iat": int(now.timestamp()), "exp": int((now + dt.timedelta(minutes=5)).timestamp())},
        keys.private_pem(key), algorithm="RS256", headers={"kid": key.kid})


@router.post("/login", dependencies=[Depends(limit(20, 60))])
def login(body: LoginIn, request: Request):
    with tenant_session(SENTINEL) as db:
        email_lower = body.email.lower()
        auth_throttle(email_lower, request.client.host)
        user = db.query(User).filter(User.email == email_lower,
                                     User.is_active.is_(True)).first()
        now = dt.datetime.now(dt.timezone.utc)
        if user and user.locked_until and user.locked_until > now:
            raise HTTPException(status.HTTP_423_LOCKED, "account temporarily locked")

        if not user or not passwords.verify_password(body.password, user.hashed_password):
            if user:   # constant-ish work + lockout counter
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= get_settings().max_failed_logins:
                    user.locked_until = now + dt.timedelta(minutes=get_settings().lockout_minutes)
                db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid email or password")

        user.failed_logins = 0
        m = _default_org(db, user.id, body.org)
        if not m:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "no active organization membership")

        if passwords.needs_rehash(user.hashed_password):
            user.hashed_password = passwords.hash_password(body.password)

        if user.mfa_enabled or mfa.required_for(m.role):
            return {"mfa_required": True, "challenge": _mfa_challenge(db, user, m)}
        return _issue_pair(db, user, m, mfa_ok=False, request=request)


def mint_dev_session(request: Request | None = None) -> dict | None:
    """DEV ONLY — return a full owner token pair for the first seeded active user
    when AEGIS_DEV_NOAUTH=1, else None. Used by /dev-login and by the server-side
    token injection that makes the local console authed on first paint."""
    if os.getenv("AEGIS_DEV_NOAUTH") != "1":
        return None
    with tenant_session(SENTINEL) as db:
        user = (db.query(User).filter(User.is_active.is_(True))
                .order_by(User.id.asc()).first())
        if not user:
            return None
        m = _default_org(db, user.id, None)
        if not m:
            return None
        return _issue_pair(db, user, m, mfa_ok=True, request=request)


@router.post("/dev-login")
def dev_login(request: Request):
    """DEV ONLY — no credentials. Returns 404 when AEGIS_DEV_NOAUTH is off."""
    tokens = mint_dev_session(request)
    if not tokens:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return tokens


@router.post("/mfa", dependencies=[Depends(limit(20, 60))])
def complete_mfa(body: MfaIn, request: Request):
    with tenant_session(SENTINEL) as db:
        try:
            claims = jwt.decode(
                body.challenge, keys.get_active(db).public_pem, algorithms=["RS256"],
                options={"verify_aud": False, "verify_iss": False})
        except jwt.PyJWTError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired challenge")
        if claims.get("scope") != "mfa":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "wrong token scope")
        if not mfa.verify(db, int(claims["sub"]), body.code):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid MFA code")
        user = db.get(User, int(claims["sub"]))
        m = db.query(Membership).filter(Membership.user_id == user.id,
                                        Membership.org_id == claims["org"]).first()
        return _issue_pair(db, user, m, mfa_ok=True, request=request)


@router.post("/refresh", dependencies=[Depends(limit(60, 60))])
def refresh(body: RefreshIn, request: Request):
    with tenant_session(SENTINEL) as db:
        result = tokens.rotate_refresh(db, body.refresh_token,
                                       ip=request.client.host,
                                       ua=request.headers.get("user-agent", ""))
        if not result:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or reused refresh token")
        old, new_refresh = result
        user = db.get(User, old.user_id)
        m = db.query(Membership).filter(Membership.user_id == old.user_id,
                                        Membership.org_id == old.org_id).first()
        access = tokens.issue_access(db, user_id=user.id, email=user.email,
                                     org_id=str(old.org_id), role=m.role, mfa=True)
        return {"access_token": access, "refresh_token": new_refresh,
                "token_type": "bearer", "expires_in": get_settings().access_ttl_seconds}


@router.post("/logout")
def logout(body: RefreshIn):
    with tenant_session(SENTINEL) as db:
        tokens.revoke(db, body.refresh_token)
    return {"ok": True}


@router.get("/orgs")
def list_orgs(user: Principal = Depends(require())):
    with tenant_session(SENTINEL) as db:
        rows = db.query(Membership).filter(Membership.user_id == user.user_id,
                                           Membership.status == "active").all()
        return [{"org_id": str(m.org_id), "role": m.role} for m in rows]


@router.post("/switch")
def switch_org(org: str, request: Request, user: Principal = Depends(require())):
    with tenant_session(SENTINEL) as db:
        m = db.query(Membership).filter(Membership.user_id == user.user_id,
                                        Membership.org_id == org,
                                        Membership.status == "active").first()
        if not m:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of that org")
        u = db.get(User, user.user_id)
        return _issue_pair(db, u, m, mfa_ok=user.mfa, request=request)


# ── MFA enrollment (self-service) ────────────────────────────────────────
@router.post("/mfa/enroll")
def mfa_enroll(user: Principal = Depends(require())):
    with tenant_session(SENTINEL) as db:
        _, uri = mfa.begin_enrollment(db, user.user_id, user.email)
        codes = mfa.generate_backup_codes(db, user.user_id)
        return {"otpauth_uri": uri, "backup_codes": codes}


@router.post("/mfa/confirm")
def mfa_confirm(code: str, user: Principal = Depends(require())):
    with tenant_session(SENTINEL) as db:
        if not mfa.confirm(db, user.user_id, code):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
        u = db.get(User, user.user_id)
        u.mfa_enabled = True
    return {"ok": True}


# ── JWKS (public keys; consumers validate access tokens offline) ─────────
@router.get("/.well-known/jwks.json")
def jwks():
    with tenant_session(SENTINEL) as db:
        return keys.jwks(db)
