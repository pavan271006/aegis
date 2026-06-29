"""Tenant isolation at the database layer.

The app connects as the least-privilege `aegis_app` role (subject to FORCE RLS).
On every request we open a transaction and `SET LOCAL app.current_org = <org>`.
The RLS policies created in migration 0001 then transparently scope EVERY query
to that org — so even a forgotten `WHERE org_id=...` in application code cannot
leak another tenant's data. Defense in depth, enforced by Postgres."""
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .settings import get_settings

def _build_engine():
    url = get_settings().database_url
    if "sqlite" in url:
        # SQLite doesn't support pool_size/max_overflow; needs check_same_thread=False
        # so FastAPI's thread pool can reuse connections across async tasks.
        return create_engine(url, connect_args={"check_same_thread": False}, future=True)
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)

_engine = _build_engine()
_Session = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)


@contextmanager
def tenant_session(org_id: str):
    """Yield a Session whose every statement is RLS-scoped to `org_id`."""
    session = _Session()
    try:
        # SET LOCAL is transaction-scoped; bind the org for this unit of work.
        if "sqlite" not in _engine.url.drivername:
            session.execute(text("SET LOCAL app.current_org = :org"), {"org": str(org_id)})
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def system_session():
    """Unscoped session for cross-tenant system work (provisioning, billing).
    Use sparingly and audit every call site."""
    session = _Session()
    try:
        if "sqlite" not in _engine.url.drivername:
            session.execute(text("SET LOCAL app.current_org = '00000000-0000-0000-0000-000000000000'"))
        # System role must be explicitly granted BYPASSRLS for this to see all rows;
        # otherwise it operates on a sentinel empty tenant (fail-closed by default).
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
