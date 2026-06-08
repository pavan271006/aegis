"""SSO: per-tenant OIDC (Entra ID / Okta / Google Workspace / any OIDC) and SAML
with Just-In-Time provisioning into the org's membership.

Design: each org configures one or more `idp_connections`. On callback we verify
the assertion, find-or-create the global user, ensure an active membership with a
role mapped from IdP claims/attributes, then mint AEGIS access+refresh tokens
(reusing the Phase-1 token service) and hand them to the SPA callback page."""
import json
import secrets
import time

import httpx
import jwt
import redis
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from ..models import User
from . import crypto, tokens
from .models import Membership
from .models_p2 import IdpConnection
from .settings import get_settings
from .tenancy import tenant_session

router = APIRouter(prefix="/api/v2/sso", tags=["sso"])
SENTINEL = "00000000-0000-0000-0000-000000000000"
_r = redis.Redis.from_url(get_settings().redis_url, decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0)
FRONTEND_CALLBACK = "/sso/callback"   # SPA route that consumes the tokens


# ── helpers ──────────────────────────────────────────────────────────────
def _conn(db: Session, conn_id: str) -> IdpConnection:
    c = db.get(IdpConnection, conn_id)
    if not c or not c.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IdP connection not found")
    return c


def _map_role(conn: IdpConnection, claims: dict) -> str:
    """Map IdP groups/claims to an AEGIS role; fall back to the connection default."""
    mapping = conn.attr_mapping or {}
    groups = claims.get(mapping.get("groups_claim", "groups"), []) or []
    if isinstance(groups, str):
        groups = [groups]
    for grp in groups:
        if grp in mapping.get("role_by_group", {}):
            return mapping["role_by_group"][grp]
    return conn.default_role


def _jit_provision(db: Session, conn: IdpConnection, email: str, claims: dict) -> dict:
    email = (email or "").lower().strip()
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "IdP returned no email")
    if conn.email_domains and email.split("@")[-1] not in conn.email_domains:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "email domain not permitted")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(email=email, hashed_password="!sso", role="read_only", is_active=True)
        db.add(user)
        db.flush()
    role = _map_role(conn, claims)
    m = db.query(Membership).filter(Membership.user_id == user.id,
                                    Membership.org_id == conn.org_id).first()
    if not m:
        m = Membership(user_id=user.id, org_id=conn.org_id, role=role)
        db.add(m)
    else:
        m.role = role          # keep role in sync with IdP on every login
    db.flush()
    access = tokens.issue_access(db, user_id=user.id, email=user.email,
                                 org_id=str(conn.org_id), role=role, mfa=True)
    refresh = tokens.issue_refresh(db, user_id=user.id, org_id=str(conn.org_id))
    return {"access_token": access, "refresh_token": refresh}


def _handoff(pair: dict) -> RedirectResponse:
    # Hand tokens to the SPA via a one-time code (avoids tokens in URL/history).
    code = secrets.token_urlsafe(24)
    _r.setex(f"sso:handoff:{code}", 120, json.dumps(pair))
    return RedirectResponse(f"{FRONTEND_CALLBACK}?code={code}")


@router.post("/exchange")
def exchange(code: str):
    raw = _r.getdel(f"sso:handoff:{code}")
    if not raw:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired code")
    return json.loads(raw)


# ── OIDC ──────────────────────────────────────────────────────────────────
def _discover(issuer: str) -> dict:
    r = httpx.get(issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=5)
    r.raise_for_status()
    return r.json()


@router.get("/{conn_id}/oidc/login")
def oidc_login(conn_id: str, request: Request):
    with tenant_session(SENTINEL) as db:
        conn = _conn(db, conn_id)
        meta = _discover(conn.issuer)
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(16)
        redirect_uri = str(request.url_for("oidc_callback"))
        _r.setex(f"sso:state:{state}", 600,
                 json.dumps({"conn": str(conn.id), "nonce": nonce, "redirect": redirect_uri}))
        params = {
            "response_type": "code", "client_id": conn.client_id,
            "redirect_uri": redirect_uri, "scope": "openid email profile",
            "state": state, "nonce": nonce,
        }
        url = httpx.URL(meta["authorization_endpoint"], params=params)
        return RedirectResponse(str(url))


@router.get("/oidc/callback", name="oidc_callback")
def oidc_callback(code: str, state: str):
    ctx = _r.getdel(f"sso:state:{state}")
    if not ctx:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired state (CSRF)")
    ctx = json.loads(ctx)
    with tenant_session(SENTINEL) as db:
        conn = _conn(db, ctx["conn"])
        meta = _discover(conn.issuer)
        secret = crypto.decrypt(conn.client_secret_enc).decode() if conn.client_secret_enc else ""
        tok = httpx.post(meta["token_endpoint"], data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": ctx["redirect"], "client_id": conn.client_id,
            "client_secret": secret,
        }, timeout=8).json()
        id_token = tok.get("id_token")
        if not id_token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no id_token from IdP")
        # Validate id_token signature against the IdP JWKS.
        jwks = jwt.PyJWKClient(meta["jwks_uri"])
        signing = jwks.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(id_token, signing.key, algorithms=["RS256", "ES256"],
                            audience=conn.client_id,
                            options={"verify_at_hash": False})
        if claims.get("nonce") != ctx["nonce"]:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "nonce mismatch")
        pair = _jit_provision(db, conn, claims.get("email"), claims)
        return _handoff(pair)


# ── SAML (python3-saml; native xmlsec dependency) ─────────────────────────
def _saml_settings(conn: IdpConnection) -> dict:
    return {
        "strict": True, "debug": False,
        "sp": {"entityId": conn.sp_entity_id, "assertionConsumerService":
               {"url": conn.acs_url, "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}},
        # IdP section is parsed from idp_metadata_xml by OneLogin's parser.
    }


@router.get("/{conn_id}/saml/metadata")
def saml_metadata(conn_id: str):
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    with tenant_session(SENTINEL) as db:
        conn = _conn(db, conn_id)
        s = OneLogin_Saml2_Settings(_saml_settings(conn), sp_validation_only=True)
        meta = s.get_sp_metadata()
        return Response(content=meta, media_type="application/xml")


@router.post("/{conn_id}/saml/acs", name="saml_acs")
async def saml_acs(conn_id: str, request: Request):
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    form = await request.form()
    with tenant_session(SENTINEL) as db:
        conn = _conn(db, conn_id)
        settings = _saml_settings(conn)
        settings.update(OneLogin_Saml2_IdPMetadataParser.parse(conn.idp_metadata_xml))
        req = {"https": "on", "http_host": request.url.hostname,
               "script_name": request.url.path, "post_data": dict(form)}
        auth = OneLogin_Saml2_Auth(req, settings)
        auth.process_response()
        if auth.get_errors():
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SAML validation failed")
        attrs = auth.get_attributes()
        email = auth.get_nameid()
        claims = {"groups": attrs.get("groups", [])}
        pair = _jit_provision(db, conn, email, claims)
        return _handoff(pair)
