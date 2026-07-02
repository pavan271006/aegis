"""AEGIS Lite — FastAPI application entrypoint."""
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import SessionLocal, init_db
from .models import Honeypot, Site
from .routers.api import (admin_router, dashboard_router, incidents_router,
                          ingest_router, monitoring_router, auth_router)


def seed():
    """Create a default site, common honeypot paths, and default RBAC users on first boot."""
    db = SessionLocal()
    try:
        from .models import User
        from .services.auth import hash_password

        if db.query(Site).count() == 0:
            db.add(Site(name="Default site", url="https://example.com"))
        if db.query(Honeypot).count() == 0:
            for p in ["/.env", "/wp-admin/setup-config.php", "/.git/config",
                      "/phpmyadmin", "/api/v1/admin/debug", "/backup.zip"]:
                db.add(Honeypot(path=p, note="auto-seeded decoy"))
        
        if db.query(User).count() == 0:
            db.add(User(email="admin@aegis.internal", hashed_password=hash_password("admin123"), role="admin"))
            db.add(User(email="analyst@aegis.internal", hashed_password=hash_password("analyst123"), role="analyst"))
            db.add(User(email="readonly@aegis.internal", hashed_password=hash_password("readonly123"), role="read_only"))
            
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    import os
    enterprise = os.getenv("AEGIS_ENTERPRISE") == "1"
    init_db()
    # Legacy single-tenant seeding inserts a default site + global honeypots (both
    # RLS-protected tenant tables) and weak default users. Under multi-tenancy those
    # inserts have no org context and are (correctly) rejected by RLS — and the weak
    # default creds are undesirable. In enterprise mode, seeding is per-org via the
    # bootstrap + onboarding flows, so skip the legacy seed entirely.
    if not enterprise:
        seed()
        from .services import scheduler
        scheduler.start()
    yield
    if not enterprise:
        from .services import scheduler
        scheduler.stop()


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

# Enterprise mode mounts its own CORS middleware (explicit allowlist, credentials=True).
# Only add the wildcard middleware in non-enterprise / lite mode.
if not os.getenv("AEGIS_ENTERPRISE") == "1":
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )

import os as _os
if _os.getenv("AEGIS_ENTERPRISE") == "1":
    app.include_router(ingest_router)
else:
    for r in (ingest_router, incidents_router, dashboard_router, monitoring_router, admin_router, auth_router):
        app.include_router(r)


# ── Enterprise stack (Phases 1-4): OPT-IN. Activates only when AEGIS_ENTERPRISE=1
# AND Postgres + Redis are configured. Off by default, so this import/merge never
# affects the legacy single-tenant (SQLite) deployment. When on, it mounts the v2
# auth/SSO/SCIM/SIEM/agent/case/ATT&CK/TIP/Copilot/compliance routers, the CORS
# allowlist, security headers, and observability. See docs/DEPLOY-ENTERPRISE.md.
import os as _os
if _os.getenv("AEGIS_ENTERPRISE") == "1":
    from .enterprise import wire as _wire_enterprise
    _wire_enterprise(app)


@app.get("/health")
def health():
    return {"status": "ok", "mode": settings.response_mode}


# ── Single-site hosting: serve the built frontend from the API server ─────────
# Mounted LAST so every API route above takes precedence. The console uses hash
# routing, so serving index.html at "/" + static /assets is enough (no SPA path
# fallback needed). Only active when frontend/dist exists.
from fastapi.staticfiles import StaticFiles          # noqa: E402
from fastapi.responses import HTMLResponse           # noqa: E402
from starlette.requests import Request as _Request    # noqa: E402
import json as _json                                 # noqa: E402
import secrets as _secrets                           # noqa: E402

_frontend_dist = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.isdir(_frontend_dist):
    _assets_dir = os.path.join(_frontend_dist, "assets")
    if os.path.isdir(_assets_dir):
        app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")
    _index_html = os.path.join(_frontend_dist, "index.html")

    @app.get("/", response_class=HTMLResponse)
    def _console(request: _Request):
        with open(_index_html, encoding="utf-8") as fh:
            html = fh.read()
        # DEV single-site: inject a fresh owner session so the console is authed on
        # first paint — no login screen, no async round-trip, immune to caching.
        if os.getenv("AEGIS_ENTERPRISE") == "1" and os.getenv("AEGIS_DEV_NOAUTH") == "1":
            try:
                from .enterprise.router_auth import mint_dev_session
                tokens = mint_dev_session(request)
            except Exception:
                tokens = None
            if tokens:
                nonce = _secrets.token_urlsafe(16)
                boot = (
                    f'<script nonce="{nonce}">try{{'
                    f'localStorage.setItem("aegis_access",{_json.dumps(tokens["access_token"])});'
                    f'localStorage.setItem("aegis_refresh",{_json.dumps(tokens["refresh_token"])});'
                    f'localStorage.setItem("aegis_org",{_json.dumps(tokens["org_id"])});'
                    f'}}catch(e){{}}</script>'
                )
                html = html.replace("</head>", boot + "</head>", 1)
                resp = HTMLResponse(html)
                # This response carries one inline bootstrap script → allow it via nonce.
                resp.headers["Content-Security-Policy"] = (
                    f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
                    "connect-src 'self'; frame-ancestors 'none'"
                )
                resp.headers["Cache-Control"] = "no-store"   # always serve a fresh token
                return resp
        resp = HTMLResponse(html)
        resp.headers["Cache-Control"] = "no-store"
        return resp
