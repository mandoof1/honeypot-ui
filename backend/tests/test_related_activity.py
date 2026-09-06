from datetime import datetime, timedelta, timezone

import pytest

from app.models import HoneypotNode, HoneypotSession, IndicatorOfCompromise, UserRole


@pytest.fixture
async def activity(db_session):
    node = HoneypotNode(name="related-test", protocol="multi", ip_address="192.0.2.8", port=2222)
    db_session.add(node)
    await db_session.flush()
    now = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
    rows = []
    for i, ip, days, scanner in (
        (1, "192.0.2.10", 0, None), (2, "192.0.2.10", -1, None),
        (3, "192.0.2.30", 2, None), (4, "192.0.2.40", 3, None),
        (5, "192.0.2.10", 31, None), (6, "192.0.2.10", 1, "Censys"),
        (7, "192.0.2.70", -7, None),
    ):
        row = HoneypotSession(id=i, node_id=node.id, attacker_ip=ip, protocol="ssh" if i < 3 else "http", started_at=now + timedelta(days=days), scanner_operator=scanner)
        db_session.add(row)
        rows.append(row)
    await db_session.flush()
    for sid, kind, value in (
        (1, "url", "http://payload.example/a"), (1, "file_hash", "a" * 64),
        (1, "tool", "curl"), (1, "filename", "payload.sh"),
        (3, "url", "http://payload.example/a"), (3, "url", "http://payload.example/a"),
        (4, "tool", "curl"), (4, "filename", "payload.sh"),
        (4, "domain", "http://payload.example/a"),  # Same value, wrong type.
        (7, "file_hash", "a" * 64),
    ):
        db_session.add(IndicatorOfCompromise(session_id=sid, ioc_type=kind, value=value))
    await db_session.commit()
    return rows


async def test_relations_are_exact_explained_and_time_bounded(client, activity, auth_headers):
    headers = await auth_headers(UserRole.VIEWER)
    response = await client.get("/api/v1/sessions/1/related", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert [m["session"]["id"] for m in data["matches"]] == [3, 6, 2, 7]
    url_match = data["matches"][0]
    assert url_match["same_source_ip"] is False
    assert url_match["shared_indicator_count"] == 1
    assert url_match["shared_indicators"] == [{"type": "url", "value": "http://payload.example/a"}]
    assert data["matches"][2]["same_source_ip"] is True
    assert not data["truncated"]
    assert not data["indicators_truncated"]


async def test_scanner_toggle_limit_and_window(client, activity, auth_headers):
    headers = await auth_headers()
    response = await client.get("/api/v1/sessions/1/related?exclude_scanners=true&limit=1", headers=headers)
    assert [m["session"]["id"] for m in response.json()["matches"]] == [3]
    assert response.json()["truncated"] is True
    response = await client.get("/api/v1/sessions/1/related?exclude_scanners=true&window_days=1", headers=headers)
    assert [m["session"]["id"] for m in response.json()["matches"]] == [2]


async def test_related_route_requires_auth_and_valid_bounds(client, activity, auth_headers):
    assert (await client.get("/api/v1/sessions/1/related")).status_code == 401
    headers = await auth_headers()
    for query in ("limit=0", "limit=51", "window_days=0", "window_days=31"):
        assert (await client.get(f"/api/v1/sessions/1/related?{query}", headers=headers)).status_code == 422
    assert (await client.get("/api/v1/sessions/999/related", headers=headers)).status_code == 404


async def test_seed_indicator_limit_is_disclosed(client, db_session, activity, auth_headers):
    for i in range(110):
        db_session.add(IndicatorOfCompromise(session_id=1, ioc_type="domain", value=f"{i}.example"))
    await db_session.commit()
    response = await client.get("/api/v1/sessions/1/related", headers=await auth_headers())
    assert response.json()["indicators_truncated"] is True
