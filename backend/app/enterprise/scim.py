"""SCIM 2.0 provisioning endpoints (RFC 7644). Lets Okta/Entra/Workspace push
user lifecycle (create / update / deactivate) into an org's membership.

Auth: `Authorization: Bearer <scim_token>` -> resolves the org; all work happens
inside that org's RLS-scoped session. Users are global identities; SCIM `active`
toggles the org *membership* (per-tenant deprovisioning)."""
import datetime as dt
import hashlib

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..models import User
from .models import Membership
from .models_p2 import ScimToken
from .tenancy import tenant_session

router = APIRouter(prefix="/scim/v2", tags=["scim"])
SENTINEL = "00000000-0000-0000-0000-000000000000"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


def scim_org(authorization: str = Header(default="")) -> str:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing SCIM bearer token")
    token_hash = hashlib.sha256(authorization.split(" ", 1)[1].encode()).hexdigest()
    with tenant_session(SENTINEL) as db:
        row = (db.query(ScimToken)
                 .filter(ScimToken.token_hash == token_hash,
                         ScimToken.revoked_at.is_(None)).first())
        if not row:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid SCIM token")
        row.last_used_at = dt.datetime.now(dt.timezone.utc)
        return str(row.org_id)


def _user_resource(user: User, m: Membership, base: str) -> dict:
    return {
        "schemas": [USER_SCHEMA],
        "id": str(user.id),
        "userName": user.email,
        "active": (m.status == "active") if m else False,
        "emails": [{"value": user.email, "primary": True}],
        "roles": [{"value": m.role}] if m else [],
        "meta": {"resourceType": "User", "location": f"{base}/Users/{user.id}"},
    }


@router.get("/Users")
def list_users(request: Request, org: str = Depends(scim_org),
               filter: str | None = None, startIndex: int = 1, count: int = 100):
    base = str(request.base_url).rstrip("/") + "/scim/v2"
    with tenant_session(SENTINEL) as db:
        q = (db.query(User, Membership)
               .join(Membership, Membership.user_id == User.id)
               .filter(Membership.org_id == org))
        if filter and "userName eq" in filter:
            email = filter.split('"')[1].lower()
            q = q.filter(User.email == email)
        rows = q.offset(max(startIndex - 1, 0)).limit(count).all()
        return {
            "schemas": [LIST_SCHEMA],
            "totalResults": q.count(),
            "startIndex": startIndex, "itemsPerPage": len(rows),
            "Resources": [_user_resource(u, m, base) for u, m in rows],
        }


@router.post("/Users", status_code=201)
def create_user(body: dict, request: Request, org: str = Depends(scim_org)):
    base = str(request.base_url).rstrip("/") + "/scim/v2"
    email = (body.get("userName") or "").lower().strip()
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "userName required")
    role = (body.get("roles") or [{}])[0].get("value", "read_only")
    with tenant_session(SENTINEL) as db:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(email=email, hashed_password="!scim", role="read_only", is_active=True)
            db.add(user)
            db.flush()
        m = db.query(Membership).filter(Membership.user_id == user.id,
                                        Membership.org_id == org).first()
        if not m:
            m = Membership(user_id=user.id, org_id=org, role=role,
                           status="active" if body.get("active", True) else "inactive")
            db.add(m)
            db.flush()
        return _user_resource(user, m, base)


@router.patch("/Users/{user_id}")
def patch_user(user_id: int, body: dict, request: Request, org: str = Depends(scim_org)):
    """Primary use: Okta/Entra setting active=false to deprovision the user."""
    base = str(request.base_url).rstrip("/") + "/scim/v2"
    with tenant_session(SENTINEL) as db:
        m = db.query(Membership).filter(Membership.user_id == user_id,
                                        Membership.org_id == org).first()
        if not m:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not provisioned in this org")
        for op in body.get("Operations", []):
            if op.get("path") == "active" or "active" in (op.get("value") or {}):
                val = op.get("value")
                active = val if isinstance(val, bool) else val.get("active", True)
                m.status = "active" if active else "inactive"
        user = db.get(User, user_id)
        return _user_resource(user, m, base)


@router.delete("/Users/{user_id}", status_code=204)
def delete_user(user_id: int, org: str = Depends(scim_org)):
    with tenant_session(SENTINEL) as db:
        m = db.query(Membership).filter(Membership.user_id == user_id,
                                        Membership.org_id == org).first()
        if m:
            m.status = "inactive"      # soft-deprovision; keep audit trail
    return None
