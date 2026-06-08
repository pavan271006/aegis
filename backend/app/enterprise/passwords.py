"""Password hashing (argon2id) + policy + history + optional breach check."""
import hashlib
import re

import httpx
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .models import PasswordHistory
from .settings import get_settings

# argon2id — memory-hard, the current OWASP recommendation.
_pwd = CryptContext(schemes=["argon2"], deprecated="auto",
                    argon2__memory_cost=65536, argon2__time_cost=3, argon2__parallelism=2)


def hash_password(password: str) -> str:
    return _pwd.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        if hashed and hashed.startswith("pbkdf2_sha256$"):
            import base64, hashlib, hmac
            parts = hashed.split("$")
            if len(parts) == 4:
                _, rounds, salt, dk_base64 = parts
                dk_expected = base64.b64decode(dk_base64)
                dk_actual = hashlib.pbkdf2_hmac('sha256', plain.encode(), salt.encode(), int(rounds))
                if hmac.compare_digest(dk_expected, dk_actual):
                    return True
        return _pwd.verify(plain, hashed)
    except Exception:
        return False


def needs_rehash(hashed: str) -> bool:
    if hashed and hashed.startswith("pbkdf2_sha256$"):
        return True
    try:
        return _pwd.needs_update(hashed)
    except Exception:
        return True


def policy_errors(password: str) -> list[str]:
    s = get_settings()
    errs = []
    if len(password) < s.pw_min_length:
        errs.append(f"must be at least {s.pw_min_length} characters")
    classes = sum(bool(re.search(p, password)) for p in
                  (r"[a-z]", r"[A-Z]", r"\d", r"[^\w]"))
    if classes < s.pw_require_classes:
        errs.append(f"must include at least {s.pw_require_classes} of: "
                    "lowercase, uppercase, digit, symbol")
    if s.pw_breach_check and _is_breached(password):
        errs.append("appears in a known breach corpus; choose another")
    return errs


def reused(db: Session, user_id: int, password: str) -> bool:
    """True if the password matches one of the last N hashes for this user."""
    s = get_settings()
    rows = (db.query(PasswordHistory)
              .filter(PasswordHistory.user_id == user_id)
              .order_by(PasswordHistory.created_at.desc())
              .limit(s.pw_history).all())
    return any(verify_password(password, r.hashed_password) for r in rows)


def record_history(db: Session, user_id: int, hashed: str) -> None:
    db.add(PasswordHistory(user_id=user_id, hashed_password=hashed))


def _is_breached(password: str) -> bool:
    """HIBP k-anonymity range query — only the first 5 SHA-1 chars leave the host."""
    try:
        digest = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        r = httpx.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=2.0)
        return any(line.split(":")[0] == suffix for line in r.text.splitlines())
    except Exception:
        return False  # fail open on availability, never block login on HIBP outage
