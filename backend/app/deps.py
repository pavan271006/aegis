"""Shared dependencies. A simple shared API key guards write/admin endpoints —
enough for a single-founder deployment behind HTTPS."""
from fastapi import Header, HTTPException

from .config import settings


def require_key(x_api_key: str = Header(default="")):
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")
    return True
