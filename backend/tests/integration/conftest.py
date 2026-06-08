"""Integration-test harness.

Spins up a REAL PostgreSQL (via the pip-bundled `pgserver`, so it runs in CI with
no system Postgres), builds the legacy base schema + all enterprise migrations,
and exposes two kinds of session:

  * `owner_session`  — superuser/owner, bypasses RLS, used for test setup.
  * `scoped(org_id)` — connects as the least-privilege `aegis_app` role with
                       `SET app.current_org`, so RLS is actually enforced (this is
                       how the application connects in production).

Env is set at import time (before any app/enterprise module binds an engine)."""
import os
import tempfile

import pytest

# ── env BEFORE importing any app/enterprise module ──────────────────────────
_PGDATA = os.path.join(tempfile.gettempdir(), "aegis_it_pg")
os.makedirs(_PGDATA, exist_ok=True)

import pgserver  # noqa: E402

_SRV = pgserver.get_server(_PGDATA)
# Clean slate every run so migrations apply against an empty database.
_SRV.psql("DROP DATABASE IF EXISTS aegis_it;")
_SRV.psql("CREATE DATABASE aegis_it;")

_OWNER_URL = f"postgresql+psycopg2://postgres:@/aegis_it?host={_PGDATA}"
_APP_URL = f"postgresql+psycopg2://aegis_app:@/aegis_it?host={_PGDATA}"
os.environ["DATABASE_URL"] = _OWNER_URL
os.environ["AEGIS_DATABASE_URL"] = _APP_URL
os.environ["AEGIS_KEK"] = "integration-test-kek-" + "x" * 40
os.environ.setdefault("AEGIS_REDIS_URL", "redis://127.0.0.1:6379/0")

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

_owner_engine = create_engine(_OWNER_URL, future=True)
_app_engine = create_engine(_APP_URL, future=True)
_OwnerSession = sessionmaker(bind=_owner_engine, future=True, expire_on_commit=False)
_AppSession = sessionmaker(bind=_app_engine, future=True, expire_on_commit=False)


_LEGACY = {"sites", "events", "incidents", "actions", "audit_log", "monitoring_checks",
           "allowlist", "honeypots", "quarantined_files", "users", "vulnerabilities",
           "posture_trends"}


@pytest.fixture(scope="session", autouse=True)
def _build_schema():
    from app.database import Base
    from app import models  # noqa: F401  (register legacy ORM)
    # Only the LEGACY tables come from create_all; the enterprise tables are owned
    # by the Alembic migrations (mirrors the production bootstrap order).
    legacy = [t for t in Base.metadata.sorted_tables if t.name in _LEGACY]
    Base.metadata.create_all(bind=_owner_engine, tables=legacy)
    from alembic import command
    from alembic.config import Config
    cfg = Config("alembic.ini")
    cfg.set_main_option("script_location", "migrations")
    command.upgrade(cfg, "head")
    yield


@pytest.fixture
def owner_session():
    s = _OwnerSession()
    try:
        yield s
        s.rollback()
    finally:
        s.close()


@pytest.fixture
def scoped():
    """Return a factory: scoped(org_id) -> RLS-enforced session.

    The GUC is connection-bound, so we PIN a dedicated connection for the
    session's lifetime (mirrors how production binds SET LOCAL to one
    transaction). Without pinning, a pooled session can swap connections on
    commit and silently lose its tenant scope -> RLS returns zero rows."""
    from sqlalchemy.orm import Session
    pinned = []

    def _make(org_id):
        conn = _app_engine.connect()
        s = Session(bind=conn)
        # Drive the SET through the session and commit it, so the session (not the
        # raw connection) owns the transaction and later commits truly persist.
        # `SET` (session-level) survives commits on this pinned connection.
        s.execute(text("SET app.current_org = :o"), {"o": str(org_id)})
        s.commit()
        pinned.append((s, conn))
        return s

    yield _make
    for s, conn in pinned:
        s.close()
        conn.close()


@pytest.fixture
def two_orgs(owner_session):
    """Create two orgs + an owner user/membership in each. Returns dicts."""
    from app.models import User
    from app.enterprise.models import Membership, Organization
    from app.enterprise import passwords
    out = {}
    for tag in ("a", "b"):
        org = Organization(name=tag.upper(), slug=f"org-{tag}-" + os.urandom(3).hex(), plan="enterprise")
        owner_session.add(org)
        owner_session.flush()
        u = User(email=f"owner-{org.slug}@test.io",
                 hashed_password=passwords.hash_password("Sup3r-Secret-Pw!"),
                 role="owner", is_active=True)
        owner_session.add(u)
        owner_session.flush()
        owner_session.add(Membership(user_id=u.id, org_id=org.id, role="owner"))
        out[tag] = {"org_id": str(org.id), "user_id": u.id, "email": u.email}
    owner_session.commit()
    return out
