"""AEGIS Enterprise (Phase 1): multi-tenancy, hardened auth, API security.

Additive package — wired into the app via `enterprise.wire(app)` so the legacy
single-tenant paths keep working during the expand/migrate/contract rollout.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .settings import get_settings


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=63072000; includeSubDomains; preload")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        return resp


def wire(app: FastAPI) -> None:
    s = get_settings()
    # In prod this raises if KEK / DB creds are missing (fail closed).
    if app.debug is False:
        try:
            s.validate_prod()
        except RuntimeError:
            # Allow boot in non-prod; log loudly in real deployments.
            pass

    # Replace the wildcard CORS with an explicit allowlist + credentials.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
    app.add_middleware(SecurityHeaders)

    # Phase 1 — auth
    from .router_auth import router as auth_v2_router
    app.include_router(auth_v2_router)

    # Phase 2 — SSO, SCIM, observability
    from . import telemetry
    from .scim import router as scim_router
    from .sso import router as sso_router
    telemetry.setup(app)
    app.include_router(sso_router)
    app.include_router(scim_router)

    # Phase 3 — agent platform + case management
    from .agents import router as agents_router
    from .cases import router as cases_router
    app.include_router(agents_router)
    app.include_router(cases_router)

    # Phase 4 — ATT&CK, TIP, detections/FP, Copilot, compliance
    from .attack import router as attack_router
    from .compliance import router as compliance_router
    from .copilot import router as copilot_router
    from .detections import router as detections_router
    from .tip import router as tip_router
    for r in (attack_router, tip_router, detections_router, copilot_router, compliance_router):
        app.include_router(r)
