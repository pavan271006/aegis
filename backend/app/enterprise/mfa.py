"""TOTP MFA + single-use backup codes. Secrets encrypted at rest (envelope)."""
import datetime as dt
import hashlib
import secrets

import pyotp
from sqlalchemy.orm import Session

from . import crypto
from .models import MfaBackupCode, MfaCredential
from .settings import get_settings


def begin_enrollment(db: Session, user_id: int, email: str) -> tuple[MfaCredential, str]:
    """Create an unconfirmed TOTP secret; return the otpauth:// provisioning URI."""
    secret = pyotp.random_base32()
    cred = MfaCredential(user_id=user_id, type="totp", secret_enc=crypto.encrypt(secret.encode()))
    db.add(cred)
    db.flush()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="AEGIS")
    return cred, uri


def confirm(db: Session, user_id: int, code: str) -> bool:
    cred = (db.query(MfaCredential)
              .filter(MfaCredential.user_id == user_id, MfaCredential.confirmed_at.is_(None))
              .order_by(MfaCredential.created_at.desc()).first())
    if not cred or not _check(cred, code):
        return False
    cred.confirmed_at = dt.datetime.now(dt.timezone.utc)
    return True


def verify(db: Session, user_id: int, code: str) -> bool:
    cred = (db.query(MfaCredential)
              .filter(MfaCredential.user_id == user_id, MfaCredential.confirmed_at.isnot(None))
              .first())
    if cred and _check(cred, code):
        return True
    return _consume_backup(db, user_id, code)


def _check(cred: MfaCredential, code: str) -> bool:
    secret = crypto.decrypt(cred.secret_enc).decode()
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_backup_codes(db: Session, user_id: int, n: int = 10) -> list[str]:
    db.query(MfaBackupCode).filter(MfaBackupCode.user_id == user_id,
                                   MfaBackupCode.used_at.is_(None)).delete()
    codes = []
    for _ in range(n):
        code = f"{secrets.randbelow(10**10):010d}"
        db.add(MfaBackupCode(user_id=user_id, code_hash=_hash(code)))
        codes.append(code)
    return codes


def _consume_backup(db: Session, user_id: int, code: str) -> bool:
    row = (db.query(MfaBackupCode)
             .filter(MfaBackupCode.user_id == user_id,
                     MfaBackupCode.code_hash == _hash(code),
                     MfaBackupCode.used_at.is_(None)).first())
    if not row:
        return False
    row.used_at = dt.datetime.now(dt.timezone.utc)
    return True


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def required_for(role: str) -> bool:
    return role in get_settings().mfa_required_roles
