"""Shared test fixtures.

Tests run against an in-memory SQLite database so they need no external
services. Schema is created from the SQLAlchemy metadata rather than Alembic,
because the migrations target PostgreSQL-specific enum types.
"""

import os
import sys

import pytest
import pytest_asyncio

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-in-production")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-for-unit-tests")
os.environ.setdefault("HONEYPOT_INGEST_TOKEN", "test-ingest-token")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("GEOIP_DB_PATH", "/nonexistent/GeoLite2-City.mmdb")

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User, UserRole  # noqa: E402
from app.core.security import get_password_hash  # noqa: E402


def pytest_sessionfinish(session, exitstatus):
    """Close the application's own database engine.

    Some code paths (the analysis pipeline's background work, the app
    lifespan) use the module-level engine in app.core.database rather than
    the per-test one. Its pooled aiosqlite connection owns a non-daemon
    worker thread, so the interpreter waited on it forever after the last
    test: the suite passed and then never exited, which hangs any CI job.
    """
    import asyncio

    from app.core import database

    asyncio.run(database.engine.dispose())


@pytest.fixture(autouse=True)
def disable_rate_limiting():
    """Every test shares one client address, so the per-IP limits would
    otherwise bleed across tests. Rate limiting itself is covered explicitly
    in test_rate_limiting.py."""
    from app.core.rate_limit import limiter

    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session):
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def make_user(db_session):
    async def _make(
        email: str = "analyst@example.com",
        password: str = "correct-horse-battery",
        role: UserRole = UserRole.ANALYST,
        is_active: bool = True,
        is_verified: bool = True,
    ) -> User:
        user = User(
            email=email,
            hashed_password=get_password_hash(password),
            name="Test User",
            role=role,
            is_active=is_active,
            is_verified=is_verified,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _make


@pytest_asyncio.fixture
async def auth_headers(client, make_user):
    async def _headers(role: UserRole = UserRole.ANALYST, email=None):
        email = email or f"{role.value}@example.com"
        await make_user(email=email, role=role)
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "correct-horse-battery"},
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return _headers
