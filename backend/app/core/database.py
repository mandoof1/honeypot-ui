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

    logger.info("Running database migrations...")
    try:
        from alembic.config import Config
        from alembic import command

        alembic_cfg = Config(
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "alembic.ini")
        )
        alembic_cfg.set_main_option(
            "script_location",
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "alembic")
        )

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: command.upgrade(alembic_cfg, "head"))
        logger.info("Migrations complete.")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        logger.error(traceback.format_exc())
        # Fall back to create_all so the app still starts
        logger.warning("Falling back to create_all...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("create_all complete.")
