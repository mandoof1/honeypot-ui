import os
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import func, select

from app.models import Alert, AuditLog, HoneypotNode, HoneypotSession, IndicatorOfCompromise

HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}


@pytest.fixture
async def node(db_session):
    node = HoneypotNode(name="capture-test", protocol="ssh", ip_address="192.0.2.8", port=2222)
    db_session.add(node)
    await db_session.commit()
    return node


def evidence():
    return {
        "capture_id": str(uuid4()), "protocol": "ssh", "attacker_ip": "192.0.2.20",
        "started_at": "2026-01-01T10:00:00Z", "ended_at": "2026-01-01T10:01:00Z",
        "duration_seconds": 60, "commands": ["cat /etc/passwd"],
        "transcript": [{"command": "cat /etc/passwd", "output": "root:x:0:0"}],
        "capture_dropped": {"commands": 8},
    }


async def test_duplicate_delivery_creates_one_session_and_one_set_of_effects(client, db_session, node, monkeypatch):
    from app.api import sessions
    schedule = []
    monkeypatch.setattr(sessions.enrichment, "schedule", schedule.append)
    data = evidence()
    url = f"/api/v1/sessions/ingest-internal?node_id={node.id}"
    first = await client.post(url, json=data, headers=HEADERS)
    assert first.status_code == 200, first.text
    counts = [await db_session.scalar(select(func.count()).select_from(model)) for model in (
        HoneypotSession, IndicatorOfCompromise, Alert, AuditLog,
    )]
    # Key ordering is irrelevant to capture identity.
    second = await client.post(url, json=dict(reversed(list(data.items()))), headers=HEADERS)
    assert second.status_code == 200, second.text
    assert second.json()["duplicate"] is True
    assert first.json()["session_id"] == second.json()["session_id"]
    assert first.json()["session_uuid"] == data["capture_id"]
    assert first.json()["duplicate"] is False
    assert len(schedule) == 1
    assert counts == [await db_session.scalar(select(func.count()).select_from(model)) for model in (
        HoneypotSession, IndicatorOfCompromise, Alert, AuditLog,
    )]
    saved = await db_session.get(HoneypotSession, first.json()["session_id"])
    assert saved.ended_at.replace(tzinfo=timezone.utc) == datetime(2026, 1, 1, 10, 1, tzinfo=timezone.utc)


async def test_changed_evidence_or_node_is_conflict(client, db_session, node):
    data = evidence()
    url = f"/api/v1/sessions/ingest-internal?node_id={node.id}"
    assert (await client.post(url, json=data, headers=HEADERS)).status_code == 200
    response = await client.post(url, json={**data, "commands": ["changed"]}, headers=HEADERS)
    assert response.status_code == 409
    second_node = HoneypotNode(name="other", protocol="ssh", ip_address="192.0.2.9", port=2222)
    db_session.add(second_node)
    await db_session.commit()
    response = await client.post(f"/api/v1/sessions/ingest-internal?node_id={second_node.id}", json=data, headers=HEADERS)
    assert response.status_code == 409
    assert await db_session.scalar(select(func.count(HoneypotSession.id))) == 1


@pytest.mark.parametrize("capture_id", ["invalid", "../../escape", 42, {}])
async def test_invalid_capture_id_is_rejected(client, node, capture_id):
    response = await client.post(f"/api/v1/sessions/ingest-internal?node_id={node.id}", json={**evidence(), "capture_id": capture_id}, headers=HEADERS)
    assert response.status_code == 422


async def test_legacy_ingest_without_capture_id_still_works(client, node):
    data = evidence()
    del data["capture_id"]
    response = await client.post(f"/api/v1/sessions/ingest-internal?node_id={node.id}", json=data, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["session_uuid"]


async def test_capture_limits_are_visible_without_exposing_credentials(client, node, auth_headers):
    headers = await auth_headers()
    data = {**evidence(), "credentials": [{"username": "root", "password": "private-test-password", "success": False}]}
    response = await client.post(f"/api/v1/sessions/ingest-internal?node_id={node.id}", json=data, headers=HEADERS)
    sid = response.json()["session_id"]
    detail = await client.get(f"/api/v1/sessions/{sid}", headers=headers)
    assert detail.json()["capture_dropped"] == {"commands": 8}
    assert "private-test-password" not in detail.text
    transcript = await client.get(f"/api/v1/sessions/{sid}/transcript", headers=headers)
    assert transcript.json()["truncated"] is True


async def test_engine_retry_after_lost_receipt_is_idempotent(client, db_session, node, tmp_path, monkeypatch):
    """Real engine outbox -> real API -> database; only the lost response is simulated."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from honeypot.core import outbox as delivery
    from honeypot.core.outbox import DeliveryOutbox

    clock = [1000.0]
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: clock[0]))
    outbox = DeliveryOutbox(tmp_path / "delivery.sqlite3", "http://test/api/v1", HEADERS["X-Honeypot-Token"])
    capture = evidence()
    await outbox.enqueue(capture, node.id)
    first = True

    async def relay(request):
        nonlocal first
        response = await client.request(request.method, str(request.url), content=request.content, headers=request.headers)
        if first and request.method == "POST":
            first = False
            assert response.status_code == 200, response.text
            raise httpx.ReadTimeout("API committed but its receipt was lost")
        return response

    async with httpx.AsyncClient(transport=httpx.MockTransport(relay)) as sender:
        await outbox.deliver_one(sender, AsyncMock())
        assert (await outbox.stats())["retrying"] == 1
        clock[0] += 400
        restarted = DeliveryOutbox(outbox.path, outbox.api_url, outbox.token)
        await restarted.deliver_one(sender, AsyncMock())
        assert (await restarted.stats())["pending"] == 0
    assert await db_session.scalar(select(func.count(HoneypotSession.id))) == 1
