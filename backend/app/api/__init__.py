from fastapi import APIRouter
from app.api import auth, sessions, alerts, dashboard, nodes, export, settings, honeypot

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(sessions.router, prefix="/sessions", tags=["Sessions"])
router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
router.include_router(nodes.router, prefix="/nodes", tags=["Honeypot Nodes"])
router.include_router(export.router, prefix="/export", tags=["Export"])
router.include_router(settings.router, prefix="/settings", tags=["Settings"])
router.include_router(honeypot.router, prefix="/honeypot", tags=["Honeypot Engine"])
