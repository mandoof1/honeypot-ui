from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import get_settings
import logging

logger = logging.getLogger(__name__)
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
    import asyncio
    import os
    import traceback

    logger.info("Running database migrations via Alembic...")
    try:
        from alembic.config import Config
        from alembic import command

        # Build path to alembic.ini relative to this file
        backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        alembic_ini = os.path.join(backend_dir, "alembic.ini")
        alembic_dir = os.path.join(backend_dir, "alembic")

        logger.info(f"alembic.ini path: {alembic_ini}")
        logger.info(f"alembic dir: {alembic_dir}")
        logger.info(f"DATABASE_URL_SYNC: {settings.DATABASE_URL_SYNC[:40]}...")

        alembic_cfg = Config(alembic_ini)
        alembic_cfg.set_main_option("script_location", alembic_dir)
        alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL_SYNC)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: command.upgrade(alembic_cfg, "head"))
        logger.info("Alembic migrations complete.")

    except Exception as e:
        logger.error(f"Alembic migration failed: {e}")
        logger.error(traceback.format_exc())
        logger.warning("Falling back to SQLAlchemy create_all...")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("create_all fallback complete.")
        except Exception as e2:
            logger.error(f"create_all also failed: {e2}")
            logger.error(traceback.format_exc())
            raise
