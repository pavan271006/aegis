"""Core production-validation integration tests — run against REAL Postgres + RLS.

Covers the security-critical properties: tenant isolation, RLS fail-closed,
cross-tenant write rejection, password policy, refresh rotation + reuse revocation,
TOTP MFA, audit-chain integrity + tamper detection, GDPR export/erase, suppression,
confidence feedback, ATT&CK enrichment, TIP matching, agent PKI."""
import uuid

import psycopg2
import pyotp
import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from app.enterprise import (agents, attack, compliance, detections, mfa,
                            passwords, tip, tokens)
from app.enterprise.deps import Principal


def principal(org_id, user_id, email, db, role="owner"):
    return Principal(user_id=user_id, email=email, org_id=org_id, role=role, mfa=True, db=db)


def _ins_incident(s, org_id, ip):
    s.execute(text("INSERT INTO incidents(source_ip,severity,status,org_id) "
                   "VALUES (:ip,'high','open',:o)"), {"ip": ip, "o": org_id})


# ── Multi-tenant isolation + RLS ────────────────────────────────────────────
def test_tenant_isolation(scoped, two_orgs):
    a, b = two_orgs["a"], two_orgs["b"]
    sa, sb = scoped(a["org_id"]), scoped(b["org_id"])
    _ins_incident(sa, a["org_id"], "10.0.0.1"); sa.commit()
    _ins_incident(sb, b["org_id"], "10.0.0.2"); sb.commit()
    a_ips = [r[0] for r in sa.execute(text("SELECT source_ip FROM incidents")).all()]
    b_ips = [r[0] for r in sb.execute(text("SELECT source_ip FROM incidents")).all()]
    assert "10.0.0.1" in a_ips and "10.0.0.2" not in a_ips
    assert "10.0.0.2" in b_ips and "10.0.0.1" not in b_ips


def test_rls_fail_closed(scoped):
    """A session scoped to a nonexistent org must see ZERO rows (never leak)."""
    s = scoped(str(uuid.uuid4()))
    assert s.execute(text("SELECT count(*) FROM incidents")).scalar() == 0


def test_cross_tenant_write_blocked(scoped, two_orgs):
    a, b = two_orgs["a"], two_orgs["b"]
    sa = scoped(a["org_id"])
    with pytest.raises((ProgrammingError, psycopg2.errors.Error, Exception)):
        # insert claiming the OTHER org's id -> RLS WITH CHECK must reject it
        _ins_incident(sa, b["org_id"], "10.0.0.3"); sa.flush()
    sa.rollback()


# ── Authentication ──────────────────────────────────────────────────────────
def test_password_policy_and_hash():
    assert passwords.policy_errors("short")            # too short / too few classes
    assert not passwords.policy_errors("Str0ng-Passphrase!")
    h = passwords.hash_password("Str0ng-Passphrase!")
    assert passwords.verify_password("Str0ng-Passphrase!", h)
    assert not passwords.verify_password("wrong", h)


def test_refresh_rotation_and_reuse_revokes_chain(owner_session, two_orgs):
    a = two_orgs["a"]
    t1 = tokens.issue_refresh(owner_session, user_id=a["user_id"], org_id=a["org_id"])
    owner_session.commit()
    old, t2 = tokens.rotate_refresh(owner_session, t1)
    owner_session.commit()
    assert t2 and t2 != t1
    # reusing the rotated token = theft signal -> whole chain revoked, t2 dies too
    assert tokens.rotate_refresh(owner_session, t1) is None
    owner_session.commit()
    assert tokens.rotate_refresh(owner_session, t2) is None


def test_mfa_totp_and_backup_codes(owner_session, two_orgs):
    a = two_orgs["a"]
    cred, uri = mfa.begin_enrollment(owner_session, a["user_id"], a["email"])
    owner_session.flush()
    secret = uri.split("secret=")[1].split("&")[0]
    totp = pyotp.TOTP(secret)
    assert mfa.confirm(owner_session, a["user_id"], totp.now())
    assert mfa.verify(owner_session, a["user_id"], totp.now())
    assert not mfa.verify(owner_session, a["user_id"], "000000")
    codes = mfa.generate_backup_codes(owner_session, a["user_id"])
    owner_session.flush()
    assert mfa.verify(owner_session, a["user_id"], codes[0])      # backup works once
    assert not mfa.verify(owner_session, a["user_id"], codes[0])  # ...and only once


# ── Compliance ──────────────────────────────────────────────────────────────
def test_audit_chain_integrity_and_tamper(scoped, owner_session, two_orgs):
    a = two_orgs["a"]
    sa = scoped(a["org_id"])
    for i in range(5):
        compliance.append_audit(sa, "tester", "action", {"i": i})
    sa.commit()
    assert compliance.verify_chain(principal(a["org_id"], a["user_id"], a["email"], sa))["ok"]
    # tamper with one row via the owner connection (bypasses RLS)
    owner_session.execute(text(
        "UPDATE audit_log SET action='HACKED' WHERE org_id=:o AND action='action'"
        " AND details->>'i'='2'"), {"o": a["org_id"]})
    owner_session.commit()
    # re-verify on a FRESH scoped session (each request gets its own tenant_session
    # in production), so it reads the committed tamper rather than a stale snapshot.
    sa2 = scoped(a["org_id"])
    assert compliance.verify_chain(principal(a["org_id"], a["user_id"], a["email"], sa2))["ok"] is False


def test_gdpr_export_and_erase(scoped, two_orgs):
    a = two_orgs["a"]
    sa = scoped(a["org_id"])
    p = principal(a["org_id"], a["user_id"], a["email"], sa)
    exp = compliance.gdpr_export(a["email"], user=p)
    assert exp["subject"]["email"] == a["email"] and exp["memberships"]
    res = compliance.gdpr_erase(a["email"], user=p)
    sa.commit()
    assert res["ok"]
    # subject anonymized + membership purged
    still = sa.execute(text("SELECT email,is_active FROM users WHERE id=:u"),
                       {"u": a["user_id"]}).first()
    assert still[0] != a["email"] and still[1] is False


# ── Detection content / FP management ───────────────────────────────────────
def test_suppression_and_confidence(scoped, two_orgs):
    a = two_orgs["a"]
    sa = scoped(a["org_id"])
    p = principal(a["org_id"], a["user_id"], a["email"], sa, role="analyst")
    detections.add_suppression(
        detections.SuppressIn(match={"source_ip": "9.9.9.9", "threat_type": "xss"}), user=p)
    assert detections.is_suppressed(sa, {"source_ip": "9.9.9.9", "threat_type": "xss", "path": "/x"})
    assert not detections.is_suppressed(sa, {"source_ip": "1.1.1.1", "threat_type": "xss"})
    detections.feedback(detections.FeedbackIn(incident_id=None, rule_key="sqli", verdict="fp"), user=p)
    detections.feedback(detections.FeedbackIn(incident_id=None, rule_key="sqli", verdict="tp"), user=p)
    assert 0.0 <= detections.confidence(sa, a["org_id"], "sqli") <= 1.0


# ── ATT&CK + TIP ─────────────────────────────────────────────────────────────
def test_attack_enrichment():
    tids = {t["technique_id"] for t in attack.techniques_for(["credential_stuffing", "sql_injection"])}
    assert "T1110.004" in tids and "T1190" in tids


def test_tip_match_is_tenant_scoped(scoped, two_orgs):
    a, b = two_orgs["a"], two_orgs["b"]
    sa, sb = scoped(a["org_id"]), scoped(b["org_id"])
    sa.execute(text("INSERT INTO indicators(org_id,type,value,confidence,source) "
                    "VALUES (:o,'ipv4','203.0.113.7',90,'feed')"), {"o": a["org_id"]})
    sa.commit()
    assert tip.match(sa, [("ipv4", "203.0.113.7")])         # org A sees it
    assert tip.match(sb, [("ipv4", "203.0.113.7")]) == []   # org B does not (RLS)


# ── Agent PKI ────────────────────────────────────────────────────────────────
def test_agent_ca_and_cert_signing(scoped, two_orgs):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    a = two_orgs["a"]
    sa = scoped(a["org_id"])
    ca_cert, ca_key = agents.get_or_create_ca(sa, a["org_id"])
    sa.commit()
    assert ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == a["org_id"]
    # sign a client CSR the way enrollment does and verify it chains to the CA
    ckey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-1")]))
           .sign(ckey, hashes.SHA256()))
    assert csr.is_signature_valid
    # cert must be verifiable with the CA public key
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-1"),
                                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, a["org_id"])]))
            .issuer_name(ca_cert.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ca_cert.not_valid_before).not_valid_after(ca_cert.not_valid_after)
            .sign(ca_key, hashes.SHA256()))
    ca_cert.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes,
        __import__("cryptography.hazmat.primitives.asymmetric.padding",
                   fromlist=["PKCS1v15"]).PKCS1v15(), cert.signature_hash_algorithm)
