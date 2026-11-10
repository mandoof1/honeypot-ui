from fastapi import APIRouter
from app.api import auth, sessions, alerts, dashboard, nodes, export, settings, honeypot, iocs, payloads, audit

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(sessions.router, prefix="/sessions", tags=["Sessions"])
router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
router.include_router(iocs.router, prefix="/iocs", tags=["Indicators"])
router.include_router(payloads.router, prefix="/payloads", tags=["Payloads"])
router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
router.include_router(nodes.router, prefix="/nodes", tags=["Honeypot Nodes"])
router.include_router(export.router, prefix="/export", tags=["Export"])
router.include_router(settings.router, prefix="/settings", tags=["Settings"])
router.include_router(honeypot.router, prefix="/honeypot", tags=["Honeypot Engine"])
router.include_router(audit.router, prefix="/audit-logs", tags=["Audit"])

#: Suffix that marks a route as engine-facing: authenticated with an engine
#: token rather than a user session, and the only kind the ingest role serves.
INTERNAL_SUFFIX = "-internal"


def build_router(role: str = "full") -> APIRouter:
    """The API routes for one role.

    ``full`` is everything above. ``ingest`` is for the multi-worker service
    on the engine network: it keeps only the routes whose path ends in
    ``-internal`` (session ingest, node registration, heartbeat). Everything
    a person uses, sign-in included, is simply not there, so a foothold on
    the engine network cannot reach it through that service.
    """
    if role != "ingest":
        return router

    internal = APIRouter()
    for route in router.routes:
        path = getattr(route, "path", "")
        if path.rstrip("/").endswith(INTERNAL_SUFFIX):
            internal.routes.append(route)
    return internal
