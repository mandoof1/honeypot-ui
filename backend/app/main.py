"""HoneySentinel AI backend application."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api import router as api_router
from app.core.config import get_settings
from app.core.database import init_db
from app.core.rate_limit import limiter

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run migrations and optional seeding before serving traffic.

    Startup failures propagate. The previous version wrapped the whole module
    in try/except and called sys.exit(1), which hid the real traceback and made
    the process look like a clean exit to the platform supervisor.
    """
    logger.info("Starting %s v%s", settings.PROJECT_NAME, settings.VERSION)
    if settings.RUN_MIGRATIONS_ON_STARTUP:
        await init_db()
        configure_logging()
    else:
        logger.info(
            "Skipping migrations (RUN_MIGRATIONS_ON_STARTUP=false); the "
            "schema must already be at head."
        )
    await _auto_seed()
    from app.services import scheduler

    await scheduler.start()
    logger.info("Startup complete")
    yield
    logger.info("Shutting down")
    await scheduler.stop()


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


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Integrated Honeypot System - HoneySentinel",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    # X-MFA-Required tells the login form to ask for an authenticator code;
    # a cross-origin frontend cannot read it unless it is exposed.
    expose_headers=["Content-Disposition", "X-Export-Count", "X-Export-Truncated", "X-MFA-Required"],
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "ngrok-skip-browser-warning"],
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please try again later."},
    )


@app.middleware("http")
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


@app.get("/health")
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

    body = {
        "status": "healthy",
        "version": settings.VERSION,
        "database": "ok",
        "enrichment": {"configured": chimera.enabled, "model": chimera.model_name if chimera.enabled else None},
        "triage": {"configured": decider.enabled, "model": decider.model_name if decider.enabled else None},
        "notifications": {},
        "workers": bool(settings.BACKGROUND_WORKERS),
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


app.include_router(api_router, prefix=settings.API_V1_PREFIX)
