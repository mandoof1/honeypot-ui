"""The records an analyst filters must be the same records they export."""
import csv
import io
import json
from datetime import datetime, timezone
from uuid import UUID
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
from sqlalchemy import select
from app.models import HoneypotNode, HoneypotSession, SessionStatus, AttackCategory, UserRole


@pytest_asyncio.fixture
async def records(db_session):
    node = HoneypotNode(name="test", protocol="ssh", ip_address="127.0.0.1", port=2222)
    db_session.add(node)
    await db_session.flush()
    for index, (protocol, country, scanner) in enumerate([
        ("ssh", "AE", None), ("http", "US", None), ("ssh", "AE", "censys"),
    ]):
        db_session.add(HoneypotSession(
            node_id=node.id, session_uuid=f"session-{index}",
            attacker_ip=f"192.0.2.{index + 1}", protocol=protocol,
            geo_country=country, scanner_operator=scanner,
            status=SessionStatus.COMPLETED, attack_category=AttackCategory.RECONNAISSANCE,
            is_anomalous=index == 0, command_summary="echo 100%_literal" if index == 0 else "ls",
            started_at=datetime(2026, 1, index + 1, tzinfo=timezone.utc),
        ))
    await db_session.commit()


@pytest.mark.parametrize("filters,expected", [
    ({"protocol": "ssh", "exclude_scanners": "true"}, ["session-0"]),
    ({"country": "ae"}, ["session-2", "session-0"]),
    ({"is_anomalous": "false"}, ["session-2", "session-1"]),
    ({"search": "%_"}, ["session-0"]),
    ({"date_from": "2026-01-02T00:00:00Z", "date_to": "2026-01-03T00:00:00Z"}, ["session-2", "session-1"]),
    ({"protocol": "ftp"}, []),
])
async def test_list_export_parity(client, auth_headers, records, filters, expected):
    headers = await auth_headers()
    listing = await client.get("/api/v1/sessions/", params=filters, headers=headers)
    exported = await client.post("/api/v1/export/", params=filters, headers=headers)
    assert listing.status_code == exported.status_code == 200
    assert [row["session_uuid"] for row in listing.json()["sessions"]] == expected
    assert [row["session"]["uuid"] for row in exported.json()] == expected
    assert int(exported.headers["x-export-count"]) == len(expected)
    assert exported.headers["x-export-truncated"] == "false"


@pytest.mark.parametrize("filters,status", [
    ({"protocol": "smb"}, 400),
    ({"status": "invalid"}, 400),
    ({"date_from": "not-a-date"}, 422),
    ({"date_from": "2026-02-01", "date_to": "2026-01-01"}, 400),
])
async def test_both_endpoints_validate_filters(client, auth_headers, filters, status):
    headers = await auth_headers()
    assert (await client.get("/api/v1/sessions/", params=filters, headers=headers)).status_code == status
    assert (await client.post("/api/v1/export/", params=filters, headers=headers)).status_code == status


async def test_export_limit_is_disclosed(client, auth_headers, records, monkeypatch):
    monkeypatch.setattr("app.api.export.MAX_EXPORT_SESSIONS", 2)
    response = await client.post("/api/v1/export/", headers=await auth_headers())
    assert response.headers["x-export-truncated"] == "true"
    assert response.headers["x-export-count"] == "2"
    assert len(response.json()) == 2


async def test_csv_is_filtered_and_has_download_name(client, auth_headers, records):
    response = await client.post("/api/v1/export/", params={"format": "csv", "protocol": "http"}, headers=await auth_headers())
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 1 and rows[0]["Protocol"] == "http"
    assert '.csv"' in response.headers["content-disposition"]


@pytest.mark.parametrize("value", ["=WEBSERVICE(\"x\")", "+1", "-1", "@SUM(1)", "  =1", "\tcmd"])
def test_csv_neutralizes_formulas(value):
    from app.api.export import _csv_cell
    assert _csv_cell(value).startswith("'")


async def test_viewers_cannot_export_csv(client, auth_headers):
    response = await client.post("/api/v1/export/?format=csv", headers=await auth_headers(UserRole.VIEWER))
    assert response.status_code == 403


def test_stix_bundle_identifier_is_valid_and_unique():
    from app.api.export import _render
    first, second = [json.loads(_render("stix", []))["id"] for _ in range(2)]
    assert first != second
    assert UUID(first.removeprefix("bundle--")).version == 4


async def test_browser_can_read_export_metadata(client, auth_headers):
    from app.main import settings
    headers = await auth_headers()
    headers["Origin"] = settings.CORS_ORIGINS[0]
    response = await client.post("/api/v1/export/", headers=headers)
    exposed = response.headers["access-control-expose-headers"].lower()
    assert all(name in exposed for name in ["content-disposition", "x-export-count", "x-export-truncated"])


@pytest.mark.parametrize("summary", ['=WEBSERVICE("https://example.invalid")', '  +SUM(1,2)', '\tcmd', 'echo "hello, world"\nwhoami'])
async def test_csv_exports_attacker_command_summary_safely(client, auth_headers, records, db_session, summary):
    session = (await db_session.execute(select(HoneypotSession).where(HoneypotSession.protocol == "http"))).scalar_one()
    session.command_summary = summary
    await db_session.commit()
    response = await client.post("/api/v1/export/", params={"format": "csv", "protocol": "http"}, headers=await auth_headers())
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 1
    expected = summary if summary.startswith("echo") else "'" + summary
    assert rows[0]["Command summary"] == expected


async def test_seeded_protocols_are_filterable_and_exportable(client, auth_headers, db_session, monkeypatch):
    from app import seed

    @asynccontextmanager
    async def factory():
        yield db_session

    monkeypatch.setattr("app.core.database.async_session_factory", factory)
    monkeypatch.setenv("ADMIN_SEED_PASSWORD", "test-only-seed-password")
    monkeypatch.setattr(seed, "SESSION_COUNT", len(seed.ATTACK_TYPES))
    await seed.seed_database()
    headers = await auth_headers()
    listing = await client.get("/api/v1/sessions/", headers=headers)
    rows = listing.json()["sessions"]
    assert {row["protocol"] for row in rows} == {"ssh", "ftp", "http", "https"}
    for protocol in ("ssh", "ftp", "http", "https"):
        expected = [row["session_uuid"] for row in rows if row["protocol"] == protocol]
        filtered = await client.get("/api/v1/sessions/", params={"protocol": protocol}, headers=headers)
        exported = await client.post("/api/v1/export/", params={"protocol": protocol}, headers=headers)
        assert filtered.status_code == exported.status_code == 200
        assert [row["session_uuid"] for row in filtered.json()["sessions"]] == expected
        assert [row["session"]["uuid"] for row in exported.json()] == expected


def test_scanner_filter_is_documented_on_both_endpoints():
    from app.main import app
    schema = app.openapi()
    for path, method in [("/api/v1/sessions/", "get"), ("/api/v1/export/", "post")]:
        param = next(p for p in schema["paths"][path][method]["parameters"] if p["name"] == "exclude_scanners")
        assert "research scanners" in param["description"]
        assert param["schema"]["default"] is False
