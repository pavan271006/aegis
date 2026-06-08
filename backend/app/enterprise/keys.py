"""RS256 signing-key management with rotation + JWKS.

Private keys are stored encrypted (envelope) and never leave the process in the
clear. Rotation keeps the previous key in `retiring` state so already-issued
access tokens still validate until they expire."""
import datetime as dt
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk
from sqlalchemy.orm import Session

from . import crypto
from .models import SigningKey
from .settings import get_settings


def _generate() -> SigningKey:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    s = get_settings()
    return SigningKey(
        kid=uuid.uuid4().hex,
        alg="RS256",
        public_pem=public_pem,
        private_pem_enc=crypto.encrypt(private_pem),
        status="active",
        not_after=dt.datetime.now(dt.timezone.utc)
        + dt.timedelta(days=s.signing_key_rotation_days),
    )


def get_active(db: Session) -> SigningKey:
    while True:
        key = (db.query(SigningKey)
                 .filter(SigningKey.status == "active")
                 .order_by(SigningKey.created_at.desc()).first())
        if key is None:
            key = _generate()
            db.add(key)
            db.flush()
            return key
        try:
            private_pem(key)
            return key
        except Exception:
            key.status = "revoked"
            db.flush()


def private_pem(key: SigningKey) -> bytes:
    return crypto.decrypt(key.private_pem_enc)


def rotate(db: Session) -> SigningKey:
    """Promote a fresh key to active; demote the current one to retiring."""
    for k in db.query(SigningKey).filter(SigningKey.status == "active").all():
        k.status = "retiring"
    new = _generate()
    db.add(new)
    db.flush()
    return new


def jwks(db: Session) -> dict:
    """Public JWKS for active + retiring keys (token consumers validate offline)."""
    keys = []
    for k in db.query(SigningKey).filter(SigningKey.status.in_(("active", "retiring"))).all():
        pub = jwk.JWK.from_pem(k.public_pem.encode())
        j = pub.export(as_dict=True)
        j.update({"kid": k.kid, "use": "sig", "alg": k.alg})
        keys.append(j)
    return {"keys": keys}
