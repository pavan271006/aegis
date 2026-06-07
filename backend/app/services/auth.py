import base64
import hashlib
import hmac
import json
import os
import time
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from ..config import settings
...
SECRET_KEY = settings.api_key or "aegis-super-secret"
ALGORITHM = "HS256"
TOKEN_EXPIRE_SECONDS = 86400 # 24 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    """Secure PBKDF2 password hashing (standard library, zero dependencies).

    Uses a cryptographically-random per-password salt so that two identical
    passwords never produce the same hash (defeats rainbow-table / hash-lookup
    attacks). The salt is stored alongside the digest in the standard
    ``algo$rounds$salt$digest`` format and read back during verification.
    """
    salt = base64.b64encode(os.urandom(16))
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return f"pbkdf2_sha256$100000${salt.decode()}${base64.b64encode(dk).decode()}"


def verify_password(plain: str, hashed: str) -> bool:
    if not hashed or "$" not in hashed:
        return False
    parts = hashed.split("$")
    if len(parts) != 4:
        return False
    _, rounds, salt, dk_base64 = parts
    dk_expected = base64.b64decode(dk_base64)
    dk_actual = hashlib.pbkdf2_hmac('sha256', plain.encode(), salt.encode(), int(rounds))
    return hmac.compare_digest(dk_expected, dk_actual)


def create_access_token(data: dict) -> str:
    """Create a standard JWT token using built-in hmac and base64."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    payload["exp"] = int(time.time()) + TOKEN_EXPIRE_SECONDS
    
    def b64_encode(d: dict) -> str:
        s = json.dumps(d, separators=(',', ':')).encode()
        return base64.urlsafe_b64encode(s).decode().rstrip("=")

    h_b64 = b64_encode(header)
    p_b64 = b64_encode(payload)
    msg = f"{h_b64}.{p_b64}".encode()
    
    sig = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{sig_b64}"


def decode_token(token: str) -> dict:
    if not token or token.count(".") != 2:
        return None
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
        msg = f"{h_b64}.{p_b64}".encode()
        
        # Verify signature
        sig_expected = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest()
        sig_actual = base64.urlsafe_b64decode(sig_b64 + "=" * (4 - len(sig_b64) % 4))
        
        if not hmac.compare_digest(sig_expected, sig_actual):
            return None
            
        payload_data = base64.urlsafe_b64decode(p_b64 + "=" * (4 - len(p_b64) % 4))
        payload = json.loads(payload_data.decode())
        
        if payload.get("exp", 0) < time.time():
            return None # Expired
            
        return payload
    except Exception:
        return None


def get_current_user(token: str = Depends(oauth2_scheme), x_api_key: str = Header(default="")):
    """Retrieves current user or falls back to valid API key as Admin."""
    from ..database import SessionLocal
    from ..models import User

    if x_api_key == settings.api_key and settings.api_key:
        # Remote shipper / system actor
        return User(email="system@aegis.internal", role="admin", is_active=True)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    payload = decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == payload["sub"], User.is_active == True).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    finally:
        db.close()


def check_role(allowed_roles: list[str]):
    def dependency(user: get_current_user = Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {user.role} role lacks permissions."
            )
        return user
    return dependency
