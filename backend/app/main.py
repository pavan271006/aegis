"""AEGIS Lite — FastAPI application entrypoint."""
from contextlib import asynccontextmanager

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
    init_db()
    seed()
    from .services import scheduler
    scheduler.start()
    yield
    scheduler.stop()


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

for r in (ingest_router, incidents_router, dashboard_router, monitoring_router, admin_router, auth_router):
    app.include_router(r)


@app.get("/health")
def health():
    return {"status": "ok", "mode": settings.response_mode}
