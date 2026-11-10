"""HoneySentinel AI backend application."""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api import build_router
from app.core import hardening
from app.core.config import get_settings
from app.core.database import init_db
from app.core.rate_limit import limiter
from app.core.body_limit import BodySizeLimit
from app.core.security import engine_token_in_headers

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def configure_logging() -> None:
    """(Re)apply the application's logging setup.

    Called at import and again after migrations: Alembic's fileConfig
    replaces the root handlers and raises the root level to WARN, which
    silenced every INFO line the backend process produced after startup.
    """
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, force=True)
    logging.getLogger().setLevel(logging.INFO)


configure_logging()
logger = logging.getLogger(__name__)

settings = get_settings()


def _make_lifespan(role: str):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Run migrations and optional seeding before serving traffic.

        Startup failures propagate. The previous version wrapped the whole module
        in try/except and called sys.exit(1), which hid the real traceback and made
        the process look like a clean exit to the platform supervisor.
        """
        logger.info("Starting %s v%s (role: %s)", settings.PROJECT_NAME, settings.VERSION, role)
        # Before anything that can start a payload analysis: from here on,
        # another process of the same user (the analysis child) cannot read
        # this one's environment or memory through /proc or ptrace.
        if hardening.make_non_dumpable():
            logger.info("Process marked non-dumpable")
        else:
            logger.info("Could not mark the process non-dumpable (not Linux, or prctl refused)")

        if settings.RUN_MIGRATIONS_ON_STARTUP:
            await init_db()
            configure_logging()
        else:
            logger.info(
                "Skipping migrations (RUN_MIGRATIONS_ON_STARTUP=false); the "
                "schema must already be at head."
            )

        from app.services import scheduler
        from app.services.investigation_jobs import report_jobs

        if role == "ingest":
            # Several of these run side by side; each would start its own
            # copy of every worker, and none of them serves the dashboard.
            logger.info("Ingest role: background workers and seeding are not started")
        else:
            await _auto_seed()
            await scheduler.start()
        logger.info("Startup complete")
        yield
        logger.info("Shutting down")
        if role != "ingest":
            await scheduler.stop()
            await report_jobs.shutdown()

    return lifespan


async def _auto_seed():
    """Seed demo data only when explicitly requested."""
    if not settings.SEED_ON_STARTUP:
        return

    from sqlalchemy import select

    from app.core.database import async_session_factory
    from app.models import User

    async with async_session_factory() as db:
        result = await db.execute(select(User).limit(1))
        if result.scalar_one_or_none() is None:
            from app.seed import seed_database

            logger.info("Empty database detected; seeding demo dataset")
            await seed_database()


async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please try again later."},
    )


async def security_headers(request: Request, call_next):
    """Baseline hardening headers on every API response."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Cache-Control", "no-store, no-cache, must-revalidate"
    )
    return response


@limiter.limit("60/minute")
async def health_check(request: Request):
    """Liveness plus the state an operator actually needs to see.

    The old version returned a constant, so Docker reported the API healthy
    with the database down. This pings the database (the one dependency
    without which nothing works) and reports the queues; a database failure
    is a 503 so the container health check and the dashboard both notice.
    `request` must be annotated as Request: without the annotation FastAPI
    treated it as a required query parameter and /health returned 422.
    """
    from sqlalchemy import text

    from app.ai.decider import decider
    from app.ai.llm import chimera
    from app.core.database import async_session_factory
    from app.services import enrichment, outbox, scheduler

    role = getattr(request.app.state, "api_role", "full")
    body = {
        "status": "healthy",
        "version": settings.VERSION,
        "role": role,
        "database": "ok",
        "enrichment": {"configured": chimera.enabled, "model": chimera.model_name if chimera.enabled else None},
        "triage": {"configured": decider.enabled, "model": decider.model_name if decider.enabled else None},
        "notifications": {},
        "workers": bool(settings.BACKGROUND_WORKERS) and role != "ingest",
    }
    try:
        async with async_session_factory() as db:
            await db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Health check: database unavailable (%s)", exc)
        body["status"] = "degraded"
        body["database"] = "error"
        return JSONResponse(status_code=503, content=body)
    # Queue depths are informative, not a liveness condition.
    try:
        async with async_session_factory() as db:
            body["enrichment"]["pending"] = await enrichment.pending_count(db)
            body["triage"]["pending"] = await enrichment.triage_pending_count(db)
            body["notifications"] = await outbox.backlog(db)
    except Exception as exc:
        body["notifications"] = {"error": str(exc)[:120]}
    started = scheduler.started_at()
    if started is not None:
        from datetime import datetime, timezone

        body["uptime_seconds"] = int((datetime.now(timezone.utc) - started).total_seconds())
    return body


def create_app(role: Optional[str] = None) -> FastAPI:
    """Build the application for one API_ROLE.

    ``full`` (the default) is the dashboard API. ``ingest`` mounts only the
    engine-facing ``-internal`` routes and the health check, and starts no
    background worker: it is what the multi-worker ingest service runs, on a
    network the engines can reach, so nothing a person signs in to is
    reachable from there.
    """
    role = (role or settings.api_role).strip().lower()
    if role not in ("full", "ingest"):
        raise RuntimeError(f"API_ROLE must be 'full' or 'ingest', not {role!r}")

    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="AI-Integrated Honeypot System - HoneySentinel",
        lifespan=_make_lifespan(role),
    )
    application.state.api_role = role

    if role == "full":
        # Browsers only ever talk to the full API; the ingest service has no
        # cross-origin caller to allow.
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_credentials=True,
            # X-MFA-Required tells the login form to ask for an authenticator code;
            # a cross-origin frontend cannot read it unless it is exposed.
            expose_headers=["Content-Disposition", "X-Export-Count", "X-Export-Truncated", "X-MFA-Required"],
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "ngrok-skip-browser-warning"],
        )

    application.state.limiter = limiter
    application.add_middleware(SlowAPIMiddleware)
    # Outside the rate limiter and the routes, so an oversized body is refused
    # before anything reads it, and a request to an engine route without a
    # valid engine token is refused before its body is read at all.
    application.add_middleware(
        BodySizeLimit,
        max_bytes=settings.MAX_REQUEST_BODY_BYTES,
        internal_max_bytes=settings.MAX_INTERNAL_BODY_BYTES,
        internal_gate=engine_token_in_headers,
    )

    application.add_exception_handler(RateLimitExceeded, rate_limit_handler)
    application.middleware("http")(security_headers)
    application.add_api_route("/health", health_check, methods=["GET"])
    application.include_router(build_router(role), prefix=settings.API_V1_PREFIX)
    return application


app = create_app()
