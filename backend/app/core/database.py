from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import get_settings
import logging
import os

logger = logging.getLogger(__name__)
settings = get_settings()

engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# backend/ directory (two levels up from app/core/database.py)
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
    import asyncio
    import traceback

    logger.info(f"BACKEND_DIR resolved to: {BACKEND_DIR}")
    alembic_ini = os.path.join(BACKEND_DIR, "alembic.ini")
    alembic_dir = os.path.join(BACKEND_DIR, "alembic")
    logger.info(f"alembic.ini: {alembic_ini} exists={os.path.exists(alembic_ini)}")
    logger.info(f"alembic dir: {alembic_dir} exists={os.path.exists(alembic_dir)}")

    try:
        from alembic.config import Config
        from alembic import command

        alembic_cfg = Config(alembic_ini)
        alembic_cfg.set_main_option("script_location", alembic_dir)
        alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL_SYNC)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: command.upgrade(alembic_cfg, "head"))
        logger.info("Alembic migrations complete.")

    except Exception as e:
        logger.error(f"Alembic failed: {e}")
        logger.error(traceback.format_exc())
        logger.warning("Falling back to create_all via async engine...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("create_all complete.")
