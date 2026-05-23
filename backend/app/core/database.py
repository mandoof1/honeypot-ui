from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db():
    """Run Alembic migrations to bring the database up to date."""
    import asyncio
    from alembic.config import Config
    from alembic import command
    import os

    alembic_cfg = Config(
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "alembic.ini")
    )
    alembic_cfg.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "alembic")
    )

    # Alembic's command.upgrade is synchronous — run in thread pool
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, lambda: command.upgrade(alembic_cfg, "head"))
