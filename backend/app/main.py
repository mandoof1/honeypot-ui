import sys
import traceback

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from fastapi.responses import JSONResponse

    from app.core.config import get_settings
    from app.core.database import init_db
    from app.api import router as api_router

    settings = get_settings()
    limiter = Limiter(key_func=get_remote_address)

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="AI-Integrated Honeypot System - HoneySentinel",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*", "ngrok-skip-browser-warning"],
    )

    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request, exc):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please try again later."},
        )

    @app.on_event("startup")
    async def startup():
        try:
            print(">>> startup: calling init_db", flush=True)
            await init_db()
            print(">>> startup: init_db done", flush=True)
            await _auto_seed()
            print(">>> startup: complete", flush=True)
        except Exception as e:
            print(f">>> STARTUP FAILED: {e}", flush=True)
            traceback.print_exc()
            sys.exit(1)

    async def _auto_seed():
        from app.models import User
        from app.core.security import get_password_hash
        from sqlalchemy import select
        from app.core.database import async_session_factory

        async with async_session_factory() as db:
            result = await db.execute(select(User).where(User.email == "admin@honeysentinel.io"))
            if not result.scalar_one_or_none():
                from app.seed import seed_database
                await seed_database()

    @app.get("/health")
    @limiter.limit("10/minute")
    async def health_check(request):
        return {"status": "healthy", "version": settings.VERSION}

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

except Exception as e:
    print(f">>> IMPORT/INIT FAILED: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)
