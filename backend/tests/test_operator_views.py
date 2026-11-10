"""The audit log and trend routes, the ingest-only role, and the summary cache."""

import os
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import get_settings
from app.core.database import get_db
from app.models import (
    AttackCategory,
    AuditLog,
    HoneypotNode,
    HoneypotSession,
    UserRole,
)

SHARED = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}


# --- GET /audit-logs ---------------------------------------------------------------

async def test_audit_log_is_for_administrators(client, auth_headers):
    assert (await client.get("/api/v1/audit-logs")).status_code in (401, 403)
    for role in (UserRole.VIEWER, UserRole.ANALYST):
        headers = await auth_headers(role)
        assert (await client.get("/api/v1/audit-logs", headers=headers)).status_code == 403


async def test_audit_log_lists_filters_and_pages(client, auth_headers, db_session, make_user):
    headers = await auth_headers(UserRole.ADMIN)
    other = await make_user(email="someone@example.com", role=UserRole.ANALYST)
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            AuditLog(user_id=other.id, action="credentials_viewed", resource_type="session",
                     resource_id=4, details={"why": "review"}, ip_address="45.83.64.80",
                     created_at=now - timedelta(days=3)),
            AuditLog(user_id=other.id, action="sessions_exported", created_at=now - timedelta(hours=2)),
            AuditLog(user_id=None, action="session_ingested_honeypot", created_at=now - timedelta(hours=1)),
        ]
    )
    await db_session.commit()

    everything = (await client.get("/api/v1/audit-logs", headers=headers)).json()
    assert set(everything) == {"items", "total"}
    assert everything["total"] == len(everything["items"]) == 4  # the three above and the sign-in
    assert set(everything["items"][0]) == {
        "id", "user_id", "user_email", "action", "resource_type", "resource_id",
        "details", "ip_address", "created_at",
    }
    stamps = [item["created_at"] for item in everything["items"]]
    assert stamps == sorted(stamps, reverse=True)

    viewed = (await client.get("/api/v1/audit-logs?action=credentials_viewed", headers=headers)).json()
    assert viewed["total"] == 1
    entry = viewed["items"][0]
    assert entry["user_email"] == "someone@example.com" and entry["user_id"] == other.id
    assert entry["details"] == {"why": "review"} and entry["ip_address"] == "45.83.64.80"
    assert entry["resource_type"] == "session" and entry["resource_id"] == 4

    by_user = (await client.get(f"/api/v1/audit-logs?user_id={other.id}", headers=headers)).json()
    assert by_user["total"] == 2

    since = (now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S")
    recent = (await client.get(f"/api/v1/audit-logs?since={since}", headers=headers)).json()
    assert {item["action"] for item in recent["items"]} == {
        "sessions_exported", "session_ingested_honeypot", "user_login",
    }
    system = next(i for i in recent["items"] if i["action"] == "session_ingested_honeypot")
    assert system["user_id"] is None and system["user_email"] is None

    page = (await client.get("/api/v1/audit-logs?limit=2&offset=1", headers=headers)).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    assert page["items"][0]["id"] == everything["items"][1]["id"]

    assert (await client.get("/api/v1/audit-logs?limit=201", headers=headers)).status_code == 422
    assert (await client.get("/api/v1/audit-logs/?limit=1", headers=headers)).status_code == 200


# --- GET /dashboard/trends ------------------------------------------------------------

async def _sessions_on(db_session, plan):
    node = HoneypotNode(name="trend-node", protocol="ssh", ip_address="10.0.0.9", port=2222)
    db_session.add(node)
    await db_session.flush()
    midday = datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0)
    for days_ago, category in plan:
        db_session.add(
            HoneypotSession(
                node_id=node.id, protocol="ssh", attacker_ip="45.83.64.90",
                started_at=midday - timedelta(days=days_ago), attack_category=category,
            )
        )
    await db_session.commit()
    return midday


@pytest.mark.parametrize("days", [7, 30, 90])
async def test_trends_has_one_entry_per_utc_day(client, auth_headers, db_session, days):
    midday = await _sessions_on(
        db_session,
        [
            (0, AttackCategory.EXPLOITATION), (0, AttackCategory.EXPLOITATION), (0, AttackCategory.BENIGN),
            (2, AttackCategory.RECONNAISSANCE), (2, None),
            (6, AttackCategory.EXFILTRATION),
            (200, AttackCategory.EXPLOITATION),  # outside every window
        ],
    )
    headers = await auth_headers(UserRole.VIEWER)
    body = (await client.get(f"/api/v1/dashboard/trends?days={days}", headers=headers)).json()

    assert body["bucket"] == "day" and body["timezone"] == "UTC"
    series = body["series"]
    assert len(series) == days
    expected_days = [
        (midday - timedelta(days=offset)).strftime("%Y-%m-%dT00:00:00Z")
        for offset in range(days - 1, -1, -1)
    ]
    assert [point["t"] for point in series] == expected_days
    assert set(series[0]) == {"t", "total", "benign", "reconnaissance", "exploitation", "exfiltration"}

    by_day = {point["t"]: point for point in series}
    today = by_day[expected_days[-1]]
    assert (today["total"], today["exploitation"], today["benign"]) == (3, 2, 1)
    two_ago = by_day[expected_days[-3]]
    # The uncategorised session counts toward the total only.
    assert (two_ago["total"], two_ago["reconnaissance"]) == (2, 1)
    assert by_day[expected_days[-7]]["exfiltration"] == 1
    # Quiet days are present, as zeros.
    quiet = by_day[expected_days[-2]]
    assert quiet == {"t": expected_days[-2], "total": 0, "benign": 0, "reconnaissance": 0,
                     "exploitation": 0, "exfiltration": 0}
    assert sum(point["total"] for point in series) == 6


async def test_trends_refuses_other_windows_and_needs_a_session(client, auth_headers):
    assert (await client.get("/api/v1/dashboard/trends")).status_code in (401, 403)
    headers = await auth_headers(UserRole.VIEWER)
    for bad in ("1", "14", "365", "0", "-7"):
        assert (await client.get(f"/api/v1/dashboard/trends?days={bad}", headers=headers)).status_code == 400
    assert (await client.get("/api/v1/dashboard/trends?days=week", headers=headers)).status_code == 422
    default = (await client.get("/api/v1/dashboard/trends", headers=headers)).json()
    assert len(default["series"]) == 7


# --- API_ROLE=ingest --------------------------------------------------------------------

def _paths(application):
    """Every path the application answers on, wherever it is mounted."""
    return set(application.openapi()["paths"])


def test_ingest_role_mounts_only_engine_routes_and_health():
    from app.main import app as full_app, create_app

    ingest_app = create_app("ingest")
    assert _paths(ingest_app) == {
        "/health",
        "/api/v1/sessions/ingest-internal",
        "/api/v1/nodes/register-internal",
        "/api/v1/nodes/heartbeat-internal",
    }
    # The full application is unchanged, and has everything else.
    full = _paths(full_app)
    assert _paths(ingest_app) < full
    assert {"/api/v1/auth/login", "/api/v1/sessions/", "/api/v1/export/", "/api/v1/audit-logs"} <= full

    with pytest.raises(RuntimeError):
        create_app("everything")


async def test_ingest_role_serves_engines_and_nothing_else(db_session):
    from app.main import create_app

    ingest_app = create_app("ingest")

    async def _override_get_db():
        yield db_session

    ingest_app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=ingest_app)
    async with AsyncClient(transport=transport, base_url="http://test") as engine:
        registered = await engine.post(
            "/api/v1/nodes/register-internal", headers=SHARED,
            json={"name": "edge", "protocol": "multi", "ip_address": "0.0.0.0", "port": 2222},
        )
        assert registered.status_code == 200, registered.text
        ingested = await engine.post(
            f"/api/v1/sessions/ingest-internal?node_id={registered.json()['id']}", headers=SHARED,
            json={"protocol": "ssh", "attacker_ip": "45.83.64.95", "commands": ["id"]},
        )
        assert ingested.status_code == 200, ingested.text

        for method, path in [
            ("POST", "/api/v1/auth/login"),
            ("GET", "/api/v1/auth/capabilities"),
            ("GET", "/api/v1/sessions/"),
            ("GET", f"/api/v1/sessions/{ingested.json()['session_id']}"),
            ("POST", "/api/v1/sessions/ingest"),
            ("GET", "/api/v1/nodes/"),
            ("POST", "/api/v1/export/"),
            ("GET", "/api/v1/dashboard/stats"),
            ("GET", "/api/v1/audit-logs"),
            ("GET", "/api/v1/iocs/feed"),
            ("GET", "/docs"),
        ]:
            response = await engine.request(method, path, json={} if method == "POST" else None)
            assert response.status_code in (404, 405), (method, path, response.status_code)


async def test_ingest_role_starts_no_background_workers(monkeypatch):
    from app import main
    from app.services import scheduler

    started = []

    async def start():
        started.append("scheduler")

    async def nothing(*args, **kwargs):
        return None

    monkeypatch.setattr(scheduler, "start", start)
    monkeypatch.setattr(scheduler, "stop", nothing)
    monkeypatch.setattr(main, "init_db", nothing)
    monkeypatch.setattr(main, "_auto_seed", nothing)
    # The test runner keeps its own process flags.
    monkeypatch.setattr(main.hardening, "make_non_dumpable", lambda: True)

    ingest_app = main.create_app("ingest")
    async with ingest_app.router.lifespan_context(ingest_app):
        pass
    assert started == []

    full_app = main.create_app("full")
    async with full_app.router.lifespan_context(full_app):
        pass
    assert started == ["scheduler"]


# --- dashboard summary cache -----------------------------------------------------------------

async def test_summary_is_computed_once_within_the_cache_window(client, auth_headers, monkeypatch):
    from app.api import dashboard

    monkeypatch.setattr(get_settings(), "DASHBOARD_CACHE_SECONDS", 30.0)
    calls = []
    real = dashboard.dashboard_service.get_stats

    async def counted(db):
        calls.append(1)
        return await real(db)

    monkeypatch.setattr(dashboard.dashboard_service, "get_stats", counted)
    headers = await auth_headers(UserRole.VIEWER)
    for _ in range(3):
        assert (await client.get("/api/v1/dashboard/stats", headers=headers)).status_code == 200
    assert len(calls) == 1

    # Expiry: the next request recomputes.
    dashboard.summary_cache._entries["stats"] = (0.0, dashboard.summary_cache._entries["stats"][1])
    await client.get("/api/v1/dashboard/stats", headers=headers)
    assert len(calls) == 2

    # And the cache is only reachable signed in.
    assert (await client.get("/api/v1/dashboard/stats")).status_code in (401, 403)


async def test_cache_can_be_switched_off(client, auth_headers, monkeypatch):
    from app.api import dashboard

    monkeypatch.setattr(get_settings(), "DASHBOARD_CACHE_SECONDS", 0)
    calls = []
    real = dashboard.dashboard_service.get_stats

    async def counted(db):
        calls.append(1)
        return await real(db)

    monkeypatch.setattr(dashboard.dashboard_service, "get_stats", counted)
    headers = await auth_headers(UserRole.VIEWER)
    for _ in range(2):
        await client.get("/api/v1/dashboard/stats", headers=headers)
    assert len(calls) == 2
