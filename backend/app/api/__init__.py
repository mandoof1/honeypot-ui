from fastapi import APIRouter
from fastapi.routing import APIRoute

from app.api import auth, sessions, alerts, dashboard, nodes, export, settings, honeypot, iocs, payloads, audit, attack

#: Every router, where it is mounted, and its tag.
_MOUNTS = [
    (auth.router, "/auth", "Authentication"),
    (sessions.router, "/sessions", "Sessions"),
    (alerts.router, "/alerts", "Alerts"),
    (iocs.router, "/iocs", "Indicators"),
    (payloads.router, "/payloads", "Payloads"),
    (dashboard.router, "/dashboard", "Dashboard"),
    (nodes.router, "/nodes", "Honeypot Nodes"),
    (export.router, "/export", "Export"),
    (settings.router, "/settings", "Settings"),
    (honeypot.router, "/honeypot", "Honeypot Engine"),
    (audit.router, "/audit-logs", "Audit"),
    (attack.router, "/attack", "ATT&CK"),
]

#: Suffix that marks a route as engine-facing: authenticated with an engine
#: token rather than a user session, and the only kind the ingest role serves.
INTERNAL_SUFFIX = "-internal"


def _engine_routes_only(source: APIRouter) -> APIRouter:
    """A copy of ``source`` holding just its ``-internal`` routes."""
    internal = APIRouter()
    for route in source.routes:
        if not isinstance(route, APIRoute):
            continue
        if not route.path.rstrip("/").endswith(INTERNAL_SUFFIX):
            continue
        internal.add_api_route(
            route.path,
            route.endpoint,
            methods=sorted(route.methods or []),
            response_model=route.response_model,
            status_code=route.status_code,
            dependencies=list(route.dependencies),
            name=route.name,
        )
    return internal


def build_router(role: str = "full") -> APIRouter:
    """The API routes for one role.

    ``full`` is everything above. ``ingest`` is for the multi-worker service
    on the engine network: it keeps only the routes whose path ends in
    ``-internal`` (session ingest, node registration, heartbeat). Everything
    a person uses, sign-in included, is simply not there, so a foothold on
    the engine network cannot reach it through that service.
    """
    api = APIRouter()
    for source, prefix, tag in _MOUNTS:
        if role == "ingest":
            source = _engine_routes_only(source)
            if not source.routes:
                continue
        api.include_router(source, prefix=prefix, tags=[tag])
    return api


router = build_router("full")
