"""Agent platform: PKI (per-org CA), secure enrollment, mTLS identity, fleet
health, and signed OTA updates.

Trust model: each org has its own CA. An agent enrolls with a one-time token +
a CSR; we sign a client cert whose subject binds it to **O=<org_id>, CN=<agent_id>**.
At runtime the mTLS-terminating proxy (nginx/Envoy) verifies the client cert
against the org CA and forwards it in a trusted header; `agent_identity` parses
the org/agent from the (CA-signed, therefore trustworthy) subject and scopes the
request — no cross-tenant lookup needed."""
import datetime as dt
import hashlib
import secrets
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import crypto, keys
from .deps import Principal, require
from .models_p3 import Agent, AgentCA, AgentEnrollmentToken, AgentRelease
from .tenancy import tenant_session

router = APIRouter(prefix="/api/v2/agents", tags=["agents"])
SENTINEL = "00000000-0000-0000-0000-000000000000"


# ── CA ──────────────────────────────────────────────────────────────────
def get_or_create_ca(db: Session, org_id: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    row = db.get(AgentCA, org_id)
    if row:
        cert = x509.load_pem_x509_certificate(row.ca_cert_pem.encode())
        key = serialization.load_pem_private_key(crypto.decrypt(row.ca_key_enc), password=None)
        return cert, key
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"AEGIS Agent CA {org_id}"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, str(org_id))])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    db.add(AgentCA(org_id=org_id, ca_cert_pem=pem, ca_key_enc=crypto.encrypt(key_pem)))
    db.flush()
    return cert, key


# ── Enrollment ────────────────────────────────────────────────────────────
@router.post("/tokens")
def create_token(label: str = "", ttl_hours: int = 24, max_uses: int = 1,
                 user: Principal = Depends(require("admin"))):
    token = secrets.token_urlsafe(32)
    user.db.add(AgentEnrollmentToken(
        org_id=user.org_id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
        label=label, max_uses=max_uses,
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=ttl_hours)))
    return {"enrollment_token": token, "expires_in_hours": ttl_hours}


class EnrollIn(BaseModel):
    enrollment_token: str
    csr_pem: str
    name: str
    hostname: str = ""


@router.post("/enroll")
def enroll(body: EnrollIn):
    """Public (token-authenticated). Returns a signed client cert + CA chain."""
    th = hashlib.sha256(body.enrollment_token.encode()).hexdigest()
    with tenant_session(SENTINEL) as db0:
        # token lookup is cross-org by hash -> use a dedicated query w/ explicit org set
        tok = _find_token(db0, th)
        if not tok:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired enrollment token")
        org_id = str(tok.org_id)
    with tenant_session(org_id) as db:
        tok = db.get(AgentEnrollmentToken, tok.id)
        now = dt.datetime.now(dt.timezone.utc)
        exp = tok.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=dt.timezone.utc)
        if exp < now or tok.uses >= tok.max_uses:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "enrollment token exhausted/expired")
        ca_cert, ca_key = get_or_create_ca(db, org_id)

        csr = x509.load_pem_x509_csr(body.csr_pem.encode())
        if not csr.is_signature_valid:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "CSR signature invalid")

        agent = Agent(org_id=org_id, name=body.name, hostname=body.hostname,
                      status="active", enrolled_at=now)
        db.add(agent)
        db.flush()

        # Subject binds the cert to this org + agent (used by mTLS identity).
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(agent.id)),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id)])
        serial = x509.random_serial_number()
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(ca_cert.subject)
                .public_key(csr.public_key()).serial_number(serial)
                .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        agent.cert_serial = format(serial, "x")
        agent.cert_fpr = cert.fingerprint(hashes.SHA256()).hex()
        tok.uses += 1
        return {"agent_id": str(agent.id), "client_cert_pem": cert_pem,
                "ca_chain_pem": ca_cert.public_bytes(serialization.Encoding.PEM).decode()}


def _find_token(db: Session, token_hash: str):
    # Enrollment tokens are RLS-scoped; resolve org via a BYPASSRLS system path in
    # prod. For portability we scan by hash using a raw, unscoped lookup.
    from sqlalchemy import text
    _now = dt.datetime.now(dt.timezone.utc)
    row = db.execute(text("SELECT id, org_id FROM agent_enrollment_tokens "
                          "WHERE token_hash=:h AND uses < max_uses AND expires_at > :now"),
                     {"h": token_hash, "now": _now}).first()
    if not row:
        return None
    class _T:  # lightweight carrier
        pass
    t = _T(); t.id, t.org_id = row[0], row[1]
    return t


# ── mTLS identity (from trusted proxy header) ─────────────────────────────
class AgentPrincipal:
    def __init__(self, agent: Agent, org_id: str, db: Session):
        self.agent, self.org_id, self.db = agent, org_id, db


def agent_identity(request: Request,
                   x_ssl_client_verify: str = Header(default=""),
                   x_ssl_client_cert: str = Header(default="")):
    if x_ssl_client_verify.upper() != "SUCCESS" or not x_ssl_client_cert:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "client certificate required (mTLS)")
    pem = urllib.parse.unquote(x_ssl_client_cert)
    cert = x509.load_pem_x509_certificate(pem.encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    org_id = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    with tenant_session(org_id) as db:
        ca_cert, _ = get_or_create_ca(db, org_id)
        # Proxy already cryptographically verified the chain; re-check serial + status.
        agent = db.get(Agent, cn)
        serial = format(cert.serial_number, "x")
        if (not agent or agent.status not in ("active", "enrolled")
                or agent.cert_serial != serial):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "unknown/revoked agent certificate")
        agent.last_seen_at = dt.datetime.now(dt.timezone.utc)
        if agent.status == "enrolled":
            agent.status = "active"
        yield AgentPrincipal(agent, org_id, db)


# ── Fleet + health ─────────────────────────────────────────────────────────
class Heartbeat(BaseModel):
    version: str = ""
    health: dict = {}


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, principal: AgentPrincipal = Depends(agent_identity)):
    principal.agent.version = body.version or principal.agent.version
    principal.agent.health = body.health or {}
    return {"ok": True, "agent_id": str(principal.agent.id),
            "desired_channel": principal.agent.channel}


@router.get("")
def list_fleet(user: Principal = Depends(require("analyst"))):
    rows = user.db.query(Agent).order_by(Agent.last_seen_at.desc().nullslast()).all()
    now = dt.datetime.now(dt.timezone.utc)
    def _stale(ts):
        if not ts:
            return False
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        return (now - ts).total_seconds() > 900
    return [{"id": str(a.id), "name": a.name, "hostname": a.hostname, "status": a.status,
             "version": a.version, "channel": a.channel,
             "last_seen": a.last_seen_at.isoformat() if a.last_seen_at else None,
             "stale": _stale(a.last_seen_at),
             "health": a.health} for a in rows]


@router.post("/{agent_id}/revoke")
def revoke(agent_id: str, user: Principal = Depends(require("admin"))):
    a = user.db.get(Agent, agent_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    a.status = "revoked"   # proxy CRL/OCSP refresh denies the cert on next handshake
    return {"ok": True}


# ── OTA updates (signed manifest) ─────────────────────────────────────────
@router.get("/manifest")
def ota_manifest(channel: str = "stable", principal: AgentPrincipal = Depends(agent_identity)):
    with tenant_session(SENTINEL) as db:
        rel = (db.query(AgentRelease).filter(AgentRelease.channel == channel)
                 .order_by(AgentRelease.created_at.desc()).first())
        if not rel:
            return {"update": False}
        return {"update": rel.version != principal.agent.version,
                "version": rel.version, "url": rel.url, "sha256": rel.sha256,
                "signature": rel.signature, "jwks": keys.jwks(db)}  # agent verifies sig
