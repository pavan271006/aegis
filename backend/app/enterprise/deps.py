"""Secure-by-default FastAPI dependencies.

`require()` is the single entry point every protected route uses. It:
  1. validates the RS256 access token (JWKS, exp/aud/iss),
  2. resolves the caller's org + role from the token,
  3. opens an RLS-scoped DB session for that org,
  4. enforces the minimum role + (optionally) that MFA was satisfied.

There is no "open by default" path — a route without `require()` returns 401."""
from dataclasses import dataclass
from typing import Iterator

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import tokens
from .tenancy import tenant_session

_bearer = HTTPBearer(auto_error=False)
_ROLE_RANK = {"read_only": 0, "analyst": 1, "admin": 2, "owner": 3}


@dataclass
class Principal:
    user_id: int
    email: str
    org_id: str
    role: str
    mfa: bool
    db: Session


def _decode(creds: HTTPAuthorizationCredentials | None) -> dict:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    # Decode needs a DB session only to look up the signing key; use a short one.
    with tenant_session("00000000-0000-0000-0000-000000000000") as s:
        try:
            return tokens.verify_access(s, creds.credentials)
        except jwt.PyJWTError as e:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid or expired token: {str(e)}",
                                headers={"WWW-Authenticate": "Bearer"})


def require(min_role: str = "read_only", mfa_required: bool = False):
    """Dependency factory. Usage: `user: Principal = Depends(require("admin"))`."""
    def dependency(
        creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> Iterator[Principal]:
        claims = _decode(creds)
        role = claims.get("role", "read_only")
        if _ROLE_RANK.get(role, -1) < _ROLE_RANK.get(min_role, 99):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"requires role >= {min_role}")
        if mfa_required and not claims.get("mfa", False):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "MFA required")
        org_id = claims["org"]
        with tenant_session(org_id) as db:
            yield Principal(
                user_id=int(claims["sub"]), email=claims.get("email", ""),
                org_id=org_id, role=role, mfa=claims.get("mfa", False), db=db,
            )
    return dependency
