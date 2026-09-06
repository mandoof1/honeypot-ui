"""Exercise migration rollback and the duplicate race on PostgreSQL.

Set TEST_POSTGRES_URL to a test database using postgresql+asyncpg://. Each
run creates and removes its own schema; it never changes existing tables.
"""

import asyncio
import os
from uuid import uuid4

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Alert, HoneypotSession, IndicatorOfCompromise
from app.services.ingest import ingest_once
from app.services.related_activity import related_activity
from test_migrations import _load_migrations


@pytest.mark.skipif(not os.getenv("TEST_POSTGRES_URL"), reason="Set TEST_POSTGRES_URL for PostgreSQL integration")
async def test_postgres_migration_and_concurrent_delivery(monkeypatch):
    schema = "capture_test_" + uuid4().hex
    url = os.environ["TEST_POSTGRES_URL"]
    sync = create_engine(url.replace("postgresql+asyncpg://", "postgresql+psycopg2://"))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": schema}})
    legacy_uuid = str(uuid4())

    def migrate():
        with sync.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
            conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            migrations = _load_migrations()
            with Operations.context(MigrationContext.configure(conn)):
                for migration in migrations[:-1]:
                    migration.upgrade()
                conn.execute(text("""INSERT INTO honeypot_nodes(name,protocol,ip_address,port,mode,is_active)
                    VALUES('race-test','ssh','192.0.2.8',2222,'active',true)"""))
                conn.execute(text("""INSERT INTO honeypot_sessions(session_uuid,node_id,attacker_ip,status,started_at,created_at)
                    VALUES(:uuid,1,'192.0.2.20','completed','2026-01-01T10:00:00Z','2026-01-01T10:01:00Z')"""), {"uuid": legacy_uuid})
                migrations[-1].upgrade()
                migrations[-1].downgrade()
                migrations[-1].upgrade()

    try:
        await asyncio.to_thread(migrate)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        from app.services import ingest
        process = ingest.analysis_pipeline.process_session
        barrier = asyncio.Barrier(2)

        async def simultaneous(*args, **kwargs):
            await asyncio.wait_for(barrier.wait(), 10)
            return await process(*args, **kwargs)

        monkeypatch.setattr(ingest.analysis_pipeline, "process_session", simultaneous)
        data = {
            "capture_id": str(uuid4()), "protocol": "ssh", "attacker_ip": "192.0.2.20",
            "started_at": "2026-01-01T11:00:00Z", "ended_at": "2026-01-01T11:01:00Z",
            "commands": ["cat /etc/passwd"], "duration_seconds": 60,
            "capture_dropped": {"commands": 2},
        }

        async def send():
            async with factory() as db:
                return await ingest_once(db, data, 1)

        # Both workers pass the initial SELECT before either starts writing.
        first, second = await asyncio.wait_for(asyncio.gather(send(), send()), 60)
        assert first["session_id"] == second["session_id"]
        assert sorted([first["duplicate"], second["duplicate"]]) == [False, True]
        async with factory() as db:
            assert await db.scalar(select(func.count(HoneypotSession.id))) == 2  # Includes legacy evidence.
            legacy = await db.scalar(select(HoneypotSession).where(HoneypotSession.session_uuid == legacy_uuid))
            assert legacy.capture_dropped is None and legacy.ingest_digest is None
            captured = await db.get(HoneypotSession, first["session_id"])
            assert captured.capture_dropped == {"commands": 2}
            assert len(captured.ingest_digest) == 64
            relations = await related_activity(db, captured, 7, 20, False)
            assert [m["session"].id for m in relations["matches"]] == [legacy.id]
            assert relations["matches"][0]["same_source_ip"] is True
            for model in (Alert, IndicatorOfCompromise):
                ids = (await db.execute(select(model.session_id))).scalars().all()
                assert all(sid == captured.id for sid in ids)
            iocs = (await db.execute(select(IndicatorOfCompromise.ioc_type, IndicatorOfCompromise.value))).all()
            assert len(iocs) == len(set(iocs))
            assert await db.scalar(select(func.count(Alert.id))) <= 1
    finally:
        await engine.dispose()
        with sync.begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        sync.dispose()
