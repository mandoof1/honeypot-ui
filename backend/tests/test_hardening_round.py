"""Regression tests for the hardening round: ingest, engine credentials,
nodes, client addresses, encryption at rest and what list queries load."""

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import DBAPIError

from app.core import encryption
from app.core.config import Settings, get_settings
from app.models import (
    Alert,
    AlertStatus,
    AuditLog,
    HoneypotNode,
    HoneypotSession,
    IndicatorOfCompromise,
    PayloadSample,
    User,
    UserRole,
)

SHARED = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}
INGEST = "/api/v1/sessions/ingest-internal"


async def _node(db_session, name="edge", **fields):
    node = HoneypotNode(name=name, protocol="ssh", ip_address="10.0.0.9", port=2222, **fields)
    db_session.add(node)
    await db_session.commit()
    return node


def _session(**fields):
    return {
        "protocol": "ssh", "attacker_ip": "45.83.64.20", "commands": ["id"],
        "started_at": "2026-02-02T02:02:00Z", **fields,
    }


# --- ingest: schema, caps, database errors ---------------------------------------

async def test_overlong_values_are_cut_to_fit_their_columns(client, db_session):
    """One URL over 500 characters made PostgreSQL reject the indicator insert,
    the session with it, and the engine resend the session for ever. SQLite
    does not enforce the width, so the assertion is on what was stored."""
    node = await _node(db_session)
    long_url = "http://45.83.64.21/" + "a" * 900
    response = await client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json=_session(
            commands=[f"wget {long_url}"],
            protocol="p" * 80,
            events=[{"event_type": "file_download", "url": long_url, "host": "h" * 900,
                     "filename": "f" * 900}],
        ),
    )
    assert response.status_code == 200, response.text

    rows = (await db_session.execute(select(IndicatorOfCompromise))).scalars().all()
    assert rows and all(len(r.value) <= 500 and len(r.ioc_type) <= 50 for r in rows)
    stored = (await db_session.execute(select(HoneypotSession))).scalar_one()
    assert len(stored.protocol) <= 20


@pytest.mark.parametrize(
    "body",
    [
        _session(attacker_ip="4" * 46),
        _session(attacker_ip={"nested": "object"}),
        _session(commands="id"),
        _session(uploads={"not": "a list"}),
        _session(transcript="text"),
        _session(fingerprints=["not", "an", "object"]),
        ["not", "an", "object"],
    ],
)
async def test_unrepairable_payloads_are_refused_with_422(client, db_session, body):
    node = await _node(db_session)
    response = await client.post(f"{INGEST}?node_id={node.id}", headers=SHARED, json=body)
    assert response.status_code == 422
    assert (await db_session.execute(select(HoneypotSession))).first() is None


async def test_repairable_values_are_coerced_not_refused(client, db_session):
    """A counter that is not a number used to raise inside the pipeline."""
    node = await _node(db_session)
    response = await client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json=_session(
            attacker_port="not-a-port", duration_seconds="soon", failed_logins="many",
            keystroke_count=None, connection_rate="fast", port_scan_count=-3,
            packets=[{"type": "x", "size": "big"}, "not an object"],
            credentials=[{"username": "u" * 5000, "password": 12345, "success": "yes"}],
        ),
    )
    assert response.status_code == 200, response.text
    stored = (await db_session.execute(select(HoneypotSession))).scalar_one()
    assert stored.attacker_port is None and stored.duration_seconds == 0


async def test_new_engine_keys_reach_the_pipeline_untouched(client, db_session, monkeypatch):
    from app.api import sessions as sessions_api

    node = await _node(db_session)
    seen = {}
    real = sessions_api.analysis_pipeline.process_session

    async def capture(db, session_data, node_id):
        seen.update(session_data)
        return await real(db, session_data, node_id)

    monkeypatch.setattr(sessions_api.analysis_pipeline, "process_session", capture)
    fingerprints = {"hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1", "ja3": "e7d705a3286e19ea42f587b344ee6865"}
    headers = {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
    events = [
        {"event_type": "ai_canary_triggered", "canary": "c-1", "at": 1.5},
        {"event_type": "honeytoken_used", "token": "t-9"},
        {"event_type": "connection_refused", "reason": "rate"},
        {"event_type": "direct_tcpip", "host": "45.83.64.30", "port": 25},
    ]
    response = await client.post(
        f"{INGEST}?node_id={node.id}", headers=SHARED,
        json=_session(
            protocol="http", fingerprints=fingerprints, events=events,
            transcript=[{"command": "GET / HTTP/1.1", "output": "", "exit_code": 0,
                         "timestamp": 1.0, "headers": headers}],
            a_key_added_later={"kept": True},
        ),
    )
    assert response.status_code == 200, response.text
    assert seen["fingerprints"] == fingerprints
    assert seen["events"] == events
    assert seen["transcript"][0]["headers"] == headers
    assert seen["a_key_added_later"] == {"kept": True}
    # Keys the engine did not send are not invented on its behalf.
    assert "payload" not in seen and "credentials" not in seen


class _FakeDriverError(Exception):
    def __init__(self, sqlstate):
        super().__init__("simulated driver error")
        self.sqlstate = sqlstate


@pytest.mark.parametrize("sqlstate, expected", [("22001", 422), ("22021", 422), ("22P05", 422)])
async def test_values_the_database_refuses_are_a_422(client, db_session, monkeypatch, sqlstate, expected):
    """A 500 is "try again later" to the engine, so an unstorable session was
    resent for ever. A 4xx is filed under failed/ and left."""
    from app.api import sessions as sessions_api

    node = await _node(db_session)

    async def reject(db, session_data, node_id):
        raise DBAPIError("INSERT", {}, _FakeDriverError(sqlstate))

    monkeypatch.setattr(sessions_api.analysis_pipeline, "process_session", reject)
    response = await client.post(f"{INGEST}?node_id={node.id}", headers=SHARED, json=_session())
    assert response.status_code == expected
    assert "could not be stored" in response.json()["detail"]


async def test_an_outage_is_still_an_error_the_engine_retries(client, db_session, monkeypatch):
    from app.api import sessions as sessions_api

    node = await _node(db_session)

    async def deadlock(db, session_data, node_id):
        raise DBAPIError("INSERT", {}, _FakeDriverError("40P01"))

    monkeypatch.setattr(sessions_api.analysis_pipeline, "process_session", deadlock)
    with pytest.raises(DBAPIError):
        await client.post(f"{INGEST}?node_id={node.id}", headers=SHARED, json=_session())


def test_is_data_error_reads_the_sqlstate_class():
    from sqlalchemy.exc import DataError, IntegrityError

    from app.core.dberrors import is_data_error

    assert is_data_error(DataError("x", {}, Exception("y")))
    assert is_data_error(DBAPIError("x", {}, _FakeDriverError("22001")))
    assert not is_data_error(DBAPIError("x", {}, _FakeDriverError("08006")))
    assert not is_data_error(IntegrityError("x", {}, _FakeDriverError("23505")))
    assert not is_data_error(ValueError("not a database error"))


# --- engine routes: token before body, own size limit -------------------------------

async def test_engine_route_checks_the_token_before_reading_the_body(client):
    """FastAPI parses a body before it runs a route's dependencies, so a
    request with no token and a malformed body used to be answered 422: the
    body had been read and parsed for someone who was never authenticated."""
    for headers in ({}, {"X-Honeypot-Token": "wrong"}):
        response = await client.post(
            f"{INGEST}?node_id=1", content=b"{ this is not json",
            headers={"Content-Type": "application/json", **headers},
        )
        assert response.status_code == 401, response.text


async def test_body_limit_middleware_on_engine_routes():
    from app.core.body_limit import BodySizeLimit

    reached = []

    async def inner(scope, receive, send):
        reached.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def call(path, body, authorised):
        received = {"count": 0}
        sent = []

        async def receive():
            received["count"] += 1
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        middleware = BodySizeLimit(
            inner, max_bytes=10, internal_max_bytes=100, internal_gate=lambda headers: authorised
        )
        await middleware({"type": "http", "path": path, "headers": []}, receive, send)
        return sent[0]["status"], received["count"]

    # No valid token: refused, and not one byte of the body was asked for.
    assert await call("/api/v1/sessions/ingest-internal", b"x" * 50, False) == (401, 0)
    # A valid token gets the engine limit, which is larger than the user one...
    assert (await call("/api/v1/sessions/ingest-internal", b"x" * 50, True))[0] == 200
    # ...but is a limit.
    assert (await call("/api/v1/sessions/ingest-internal", b"x" * 101, True))[0] == 413
    assert (await call("/api/v1/auth/login", b"x" * 50, True))[0] == 413
    assert reached == ["/api/v1/sessions/ingest-internal"]


# --- per-node engine tokens ----------------------------------------------------------

@pytest.fixture
def node_tokens(monkeypatch):
    tokens = {"alpha": "alpha-node-token-0001", "beta": "beta-node-token-0002"}
    monkeypatch.setattr(get_settings(), "HONEYPOT_NODE_TOKENS", json.dumps(tokens))
    return {name: {"X-Honeypot-Token": token} for name, token in tokens.items()}


def _registration(name):
    return {"name": name, "protocol": "multi", "ip_address": "0.0.0.0", "port": 2222}


async def test_node_token_is_bound_to_its_node(client, db_session, node_tokens):
    """One shared token let any engine register, report and ingest as any other."""
    register = "/api/v1/nodes/register-internal"
    heartbeat = "/api/v1/nodes/heartbeat-internal"

    alpha = await client.post(register, headers=node_tokens["alpha"], json=_registration("alpha"))
    assert alpha.status_code == 200, alpha.text
    alpha_id = alpha.json()["id"]

    # alpha's token for any other name, and anyone else's token for alpha.
    assert (await client.post(register, headers=node_tokens["alpha"], json=_registration("beta"))).status_code == 403
    assert (await client.post(register, headers=node_tokens["alpha"], json=_registration("gamma"))).status_code == 403
    assert (await client.post(register, headers=SHARED, json=_registration("alpha"))).status_code == 403
    assert (await client.post(register, headers=node_tokens["beta"], json=_registration("alpha"))).status_code == 403

    beat = {"node_id": alpha_id, "name": "alpha", "status": {}}
    assert (await client.post(heartbeat, headers=node_tokens["alpha"], json=beat)).status_code == 200
    assert (await client.post(heartbeat, headers=node_tokens["beta"], json=beat)).status_code == 403
    assert (await client.post(heartbeat, headers=SHARED, json=beat)).status_code == 403

    ingest = f"{INGEST}?node_id={alpha_id}"
    assert (await client.post(ingest, headers=node_tokens["beta"], json=_session())).status_code == 403
    assert (await client.post(ingest, headers=SHARED, json=_session())).status_code == 403
    assert (await client.post(ingest, headers=node_tokens["alpha"], json=_session())).status_code == 200
    assert len((await db_session.execute(select(HoneypotSession))).scalars().all()) == 1


async def test_nodes_without_their_own_token_keep_the_shared_one(client, db_session, node_tokens):
    register = "/api/v1/nodes/register-internal"
    gamma = await client.post(register, headers=SHARED, json=_registration("gamma"))
    assert gamma.status_code == 200
    ingest = f"{INGEST}?node_id={gamma.json()['id']}"
    assert (await client.post(ingest, headers=SHARED, json=_session())).status_code == 200
    # A token bound to another node is not a substitute for the shared one.
    assert (await client.post(ingest, headers=node_tokens["alpha"], json=_session())).status_code == 403
    assert (await client.post(ingest, headers={"X-Honeypot-Token": "unknown"}, json=_session())).status_code == 401


def test_an_empty_token_never_matches():
    from app.core.security import match_engine_token

    assert match_engine_token("") is None


@pytest.mark.parametrize(
    "raw",
    ['{"a": "same-token-value-000", "b": "same-token-value-000"}', "not json", '["a"]', '{"a": ""}'],
)
def test_malformed_node_tokens_stop_startup(raw):
    settings = Settings(
        ENVIRONMENT="test", SECRET_KEY="k" * 40, ENCRYPTION_KEY="e" * 40,
        HONEYPOT_INGEST_TOKEN="shared-token-000000000", HONEYPOT_NODE_TOKENS=raw,
    )
    with pytest.raises(RuntimeError):
        settings.validate_roles_and_tokens()


def test_node_token_equal_to_the_shared_token_is_refused():
    settings = Settings(
        ENVIRONMENT="test", SECRET_KEY="k" * 40, ENCRYPTION_KEY="e" * 40,
        HONEYPOT_INGEST_TOKEN="shared-token-000000000",
        HONEYPOT_NODE_TOKENS='{"a": "shared-token-000000000"}',
    )
    with pytest.raises(RuntimeError):
        settings.validate_roles_and_tokens()


async def test_control_calls_use_the_control_token_when_set(monkeypatch):
    import httpx

    from app.api import honeypot as engine_api

    sent = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url, json=None, headers=None):
            sent.append(headers["X-Honeypot-Token"])
            return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(engine_api.httpx, "AsyncClient", FakeClient)
    settings = get_settings()

    await engine_api._engine_request("GET", "/status")
    monkeypatch.setattr(settings, "HONEYPOT_CONTROL_TOKEN", "control-token-000000001")
    await engine_api._engine_request("GET", "/status")
    assert sent == [settings.HONEYPOT_INGEST_TOKEN, "control-token-000000001"]


# --- nodes: activation, liveness, isolation --------------------------------------------

async def test_heartbeat_and_reregistration_leave_a_deactivated_node_off(client, db_session):
    node = await _node(db_session, name="switched-off", is_active=False)
    beat = await client.post(
        "/api/v1/nodes/heartbeat-internal", headers=SHARED,
        json={"node_id": node.id, "name": node.name, "status": {"running": True}},
    )
    assert beat.status_code == 200 and beat.json()["is_active"] is False
    again = await client.post(
        "/api/v1/nodes/register-internal", headers=SHARED, json=_registration(node.name)
    )
    assert again.status_code == 200

    await db_session.refresh(node)
    assert node.is_active is False
    assert node.last_heartbeat is not None  # it is still seen to be reporting


async def test_one_engines_bad_report_does_not_stop_the_liveness_check(db_session):
    """A non-numeric disk figure raised inside the loop over nodes, on every
    tick, so no engine's outage was noticed while it stayed stored."""
    from app.services import scheduler

    long_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    await _node(db_session, name="a-garbage", last_heartbeat=datetime.now(timezone.utc),
                last_status={"disk": {"total_bytes": "lots", "free_bytes": {"x": 1}}, "spool_pending": "many"})
    await _node(db_session, name="b-zero", last_heartbeat=datetime.now(timezone.utc),
                last_status={"disk": {"total_bytes": "0", "free_bytes": 5}})
    silent = await _node(db_session, name="c-silent", last_heartbeat=long_ago)

    summary = await scheduler.liveness_tick(db_session)
    assert summary["nodes"] == 3 and summary["raised"] == 1
    await db_session.refresh(silent)
    assert silent.offline_alerted is True


async def test_engine_reporting_it_is_not_isolated_raises_a_system_alert(client, db_session):
    node = await _node(db_session, name="leaky")

    async def beat(isolation):
        return await client.post(
            "/api/v1/nodes/heartbeat-internal", headers=SHARED,
            json={"node_id": node.id, "name": node.name, "status": {"isolation": isolation}},
        )

    insecure = {
        "isolation_enabled": True, "total_checks": 1, "overall_secure": False,
        "last_check": {"egress_blocked": False, "read_only_rootfs": True, "overall_secure": False},
    }
    assert (await beat(insecure)).status_code == 200
    assert (await beat(insecure)).status_code == 200  # repeated every minute

    alerts = (await db_session.execute(select(Alert).where(Alert.kind == "system"))).scalars().all()
    assert len(alerts) == 1  # one alert, however often the engine repeats it
    alert = alerts[0]
    assert alert.node_id == node.id and alert.status == AlertStatus.NEW
    assert "not isolated" in alert.title and "egress_blocked" in alert.description
    assert "read_only_rootfs" not in alert.description

    secure = {"isolation_enabled": True, "total_checks": 2, "overall_secure": True, "last_check": {}}
    await beat(secure)
    await db_session.refresh(alert)
    assert alert.status == AlertStatus.RESOLVED


async def test_secure_engine_raises_nothing(client, db_session):
    node = await _node(db_session, name="tight")
    await client.post(
        "/api/v1/nodes/heartbeat-internal", headers=SHARED,
        json={"node_id": node.id, "name": node.name,
              "status": {"isolation": {"overall_secure": True, "last_check": {}}}},
    )
    assert (await db_session.execute(select(Alert))).first() is None


# --- client address --------------------------------------------------------------------

class _Request:
    def __init__(self, peer, forwarded=None):
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}
        self.client = type("Client", (), {"host": peer})()


def test_forwarded_header_is_ignored_unless_the_peer_is_a_trusted_proxy(monkeypatch):
    """The hops inside the header were checked; who sent the header was not."""
    from app.core.clientip import client_ip

    settings = get_settings()
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "127.0.0.0/8,172.16.0.0/12")

    # Direct from somewhere that is not our proxy: its header is its own claim.
    assert client_ip(_Request("45.83.64.40", "1.2.3.4")) == "45.83.64.40"
    assert client_ip(_Request("45.83.64.40", "127.0.0.1")) == "45.83.64.40"
    # Through our proxy: the address the proxy appended.
    assert client_ip(_Request("172.20.0.2", "45.83.64.41")) == "45.83.64.41"
    assert client_ip(_Request("::ffff:172.20.0.2", "45.83.64.41")) == "45.83.64.41"
    # Text that is not an address was typed by the client, never by a proxy.
    assert client_ip(_Request("172.20.0.2", "not-an-address, 127.0.0.1")) == "127.0.0.1"
    assert client_ip(_Request("172.20.0.2", "<script>")) == "172.20.0.2"
    assert client_ip(_Request("172.20.0.2")) == "172.20.0.2"


# --- accounts ----------------------------------------------------------------------------

async def test_token_for_a_deleted_user_is_refused(client, auth_headers, db_session):
    """A missing row was waved through with the role the token claimed."""
    from sqlalchemy import delete

    from app.core import security
    from app.models import RefreshToken

    headers = await auth_headers(UserRole.ADMIN, email="gone@example.com")
    assert (await client.get("/api/v1/auth/users", headers=headers)).status_code == 200

    await db_session.execute(delete(AuditLog))
    await db_session.execute(delete(RefreshToken))
    await db_session.execute(delete(User).where(User.email == "gone@example.com"))
    await db_session.commit()
    security._user_state_cache.clear()

    assert (await client.get("/api/v1/auth/users", headers=headers)).status_code == 401


# --- transcripts ---------------------------------------------------------------------------

async def test_transcript_needs_analyst_and_the_read_is_audited(client, auth_headers, db_session):
    node = await _node(db_session)
    result = (
        await client.post(
            f"{INGEST}?node_id={node.id}", headers=SHARED,
            json=_session(transcript=[{"command": "id", "output": "uid=0", "exit_code": 0, "timestamp": 1.0}]),
        )
    ).json()
    path = f"/api/v1/sessions/{result['session_id']}/transcript"

    viewer = await auth_headers(UserRole.VIEWER)
    assert (await client.get(path, headers=viewer)).status_code == 403

    analyst = await auth_headers(UserRole.ANALYST)
    response = await client.get(path, headers=analyst)
    assert response.status_code == 200
    assert response.json()["entries"][0]["command"] == "id"

    reads = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "transcript_viewed"))
    ).scalars().all()
    assert len(reads) == 1 and reads[0].resource_id == result["session_id"]
    assert reads[0].user_id is not None and reads[0].ip_address


# --- what list queries load ------------------------------------------------------------------

@pytest.fixture
def statements(db_session):
    """Every SQL statement the test's database session runs."""
    captured = []
    engine = db_session.bind.sync_engine

    def record(conn, cursor, statement, parameters, context, executemany):
        captured.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    yield captured
    event.remove(engine, "before_cursor_execute", record)


_BLOBS = ("raw_commands_encrypted", "raw_payloads_encrypted", "transcript_encrypted", "credentials_encrypted")


def _selects_a_blob(statement: str) -> bool:
    # "x_encrypted IS NOT NULL AS has_x" asks whether the blob exists
    # without fetching it; anything else that names a blob column loads it.
    select_list = statement.split(" FROM ")[0]
    for blob in _BLOBS:
        for fragment in select_list.split(","):
            if blob in fragment and "IS NOT NULL" not in fragment:
                return True
    return False


async def test_list_views_do_not_load_encrypted_blobs(client, auth_headers, db_session, statements):
    """A page of sessions fetched every session's transcript, payload and
    credentials, megabytes each, to draw a table that shows none of them."""
    node = await _node(db_session)
    content = b"#!/bin/sh\necho hi\n"
    upload = {
        "filename": "a.sh", "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
        "source": "ssh_shell", "content_b64": base64.b64encode(content).decode(),
    }
    ingested = (
        await client.post(
            f"{INGEST}?node_id={node.id}", headers=SHARED,
            json=_session(uploads=[upload], payload="x" * 100,
                          transcript=[{"command": "id", "output": "", "exit_code": 0, "timestamp": 1.0}],
                          credentials=[{"username": "root", "password": "pw", "success": False}]),
        )
    ).json()
    headers = await auth_headers(UserRole.ANALYST)
    session_id = ingested["session_id"]

    for method, path in [
        ("GET", "/api/v1/sessions/"),
        ("GET", f"/api/v1/sessions/{session_id}"),
        ("GET", "/api/v1/sessions/attacker/45.83.64.20"),
        ("GET", "/api/v1/dashboard/live-events"),
        ("POST", "/api/v1/export/?format=json"),
        ("POST", "/api/v1/export/?format=csv"),
        ("POST", f"/api/v1/sessions/{session_id}/export?format=stix"),
        ("GET", "/api/v1/payloads/"),
        ("GET", f"/api/v1/payloads/{upload['sha256']}"),
    ]:
        statements.clear()
        response = await client.request(method, path, headers=headers)
        assert response.status_code == 200, (path, response.text[:200])
        session_selects = [s for s in statements if "FROM honeypot_sessions" in s]
        if path == "/api/v1/sessions/attacker/45.83.64.20":
            # The summary reads credentials, alone, to count usernames.
            session_selects = [s for s in session_selects if "transcript_encrypted" in s or "raw_" in s]
        assert not any(_selects_a_blob(s) for s in session_selects), path
        sample_selects = [s for s in statements if "FROM payload_samples" in s]
        assert not any(
            "content_encrypted" in s.split(" FROM ")[0].replace("content_encrypted IS NOT NULL", "")
            for s in sample_selects
        ), path

    listed = (await client.get("/api/v1/sessions/", headers=headers)).json()["sessions"][0]
    assert listed["has_transcript"] is True and listed["has_credentials"] is True
    detail = (await client.get(f"/api/v1/payloads/{upload['sha256']}", headers=headers)).json()
    assert detail["content_available"] is True and detail["sessions"][0]["session_id"] == session_id


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/dashboard/live-events?limit=100000",
        "/api/v1/dashboard/live-events?limit=0",
        "/api/v1/sessions/?page_size=101",
        "/api/v1/payloads/?page_size=101",
        "/api/v1/iocs/?page_size=201",
    ],
)
async def test_limits_are_bounded(client, auth_headers, path):
    headers = await auth_headers(UserRole.VIEWER)
    assert (await client.get(path, headers=headers)).status_code == 422


async def test_bulk_export_is_a_whole_document_across_batches(client, auth_headers, db_session, monkeypatch):
    from app.api import export as export_api

    monkeypatch.setattr(export_api, "EXPORT_BATCH", 2)
    node = await _node(db_session)
    for index in range(5):
        await client.post(
            f"{INGEST}?node_id={node.id}", headers=SHARED,
            json=_session(attacker_ip=f"45.83.64.{50 + index}", commands=["uname -a"]),
        )
    headers = await auth_headers(UserRole.ANALYST)

    as_json = await client.post("/api/v1/export/?format=json", headers=headers)
    assert as_json.headers["x-export-count"] == "5"
    assert len(json.loads(as_json.text)) == 5

    as_csv = await client.post("/api/v1/export/?format=csv", headers=headers)
    lines = as_csv.text.strip().splitlines()
    assert len(lines) == 6 and lines[0].startswith("Session ID")

    as_cef = await client.post("/api/v1/export/?format=cef", headers=headers)
    assert len(as_cef.text.splitlines()) == 5

    import stix2

    as_stix = await client.post("/api/v1/export/?format=stix", headers=headers)
    bundle = stix2.parse(as_stix.text, allow_custom=False)
    addresses = [o.pattern for o in bundle.objects if o.type == "indicator" and "ipv4-addr" in o.pattern]
    assert len(set(addresses)) == 5


def test_stix_export_carries_the_stored_indicators():
    """The rows were loaded and then ignored: only the source address went out."""
    import stix2

    from app.services.report_generator import report_generator

    sha256 = "a" * 64
    iocs = [
        {"type": "domain", "value": "c2.example.net", "confidence": 0.9, "tags": ["c2_host"]},
        {"type": "url", "value": "http://c2.example.net/stage1", "confidence": 0.95, "tags": ["dropper"]},
        {"type": "file_hash", "value": sha256, "confidence": 0.9, "tags": ["uploaded_malware"]},
        {"type": "ip", "value": "45.83.64.60", "confidence": 0.9, "tags": ["c2_host"]},
        {"type": "referenced_ip", "value": "45.83.64.61", "confidence": 0.7, "tags": ["referenced_ip"]},
        {"type": "filename", "value": "x86'; DROP", "confidence": 0.7, "tags": []},
        # Not the shape their type claims: left out, not exported loosely.
        {"type": "ip", "value": "not-an-address", "tags": []},
        {"type": "domain", "value": "bad domain\n", "tags": []},
        {"type": "file_hash", "value": "zz", "tags": []},
        {"type": "wallet", "value": "BTC:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "tags": []},
        "not a row",
    ]
    text = report_generator.generate_stix_report(
        {"attacker_ip": "45.83.64.20", "session_uuid": "s-1"},
        {"category": "exploitation", "iocs": iocs, "detected_tools": [], "mitre": {}},
    )
    bundle = stix2.parse(text, allow_custom=False)  # raises if anything is invalid STIX
    patterns = {o.pattern: o for o in bundle.objects if o.type == "indicator"}

    assert "[domain-name:value = 'c2.example.net']" in patterns
    assert "[url:value = 'http://c2.example.net/stage1']" in patterns
    assert f"[file:hashes.'SHA-256' = '{sha256}']" in patterns
    assert "[ipv4-addr:value = '45.83.64.60']" in patterns
    assert "[file:name = 'x86\\'; DROP']" in patterns
    referenced = patterns["[ipv4-addr:value = '45.83.64.61']"]
    assert referenced.indicator_types == ["anomalous-activity"]
    assert patterns["[domain-name:value = 'c2.example.net']"].confidence == 90
    assert len(patterns) == 7  # the six above and the session's own address
    assert not any("not-an-address" in p or "wallet" in p for p in patterns)


# --- encryption at rest: key ids, previous keys, contexts, rotation ----------------------

def _legacy_v2(plaintext: bytes, secret: str) -> str:
    """A blob exactly as the previous build wrote it."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = hashlib.sha256(secret.encode()).digest()
    nonce = os.urandom(12)
    return "v2:" + base64.b64encode(nonce + AESGCM(key).encrypt(nonce, plaintext, None)).decode()


def test_ciphertext_names_its_key_and_old_formats_still_open():
    from cryptography.fernet import Fernet

    secret = get_settings().ENCRYPTION_KEY
    blob = encryption.encrypt_data("evidence")
    version, key_id, context, _ = blob.split(":", 3)
    assert (version, key_id, context) == ("v3", encryption.current_key_id(), "")
    assert encryption.decrypt_data(blob) == "evidence"

    assert encryption.decrypt_data(_legacy_v2(b"older row", secret)) == "older row"
    assert encryption.decrypt_bytes(_legacy_v2(b"\x00\x01", secret)) == b"\x00\x01"
    fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))
    assert encryption.decrypt_data(fernet.encrypt(b"oldest row").decode()) == "oldest row"


def test_previous_keys_decrypt_and_only_the_current_key_encrypts(monkeypatch):
    settings = get_settings()
    old_secret = settings.ENCRYPTION_KEY
    under_old = encryption.encrypt_data("written before the rotation")
    old_v2 = _legacy_v2(b"written long before", old_secret)
    old_key_id = encryption.current_key_id()

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", "a-new-key-after-rotation")
    with pytest.raises(ValueError, match="ENCRYPTION_KEY_PREVIOUS"):
        encryption.decrypt_data(under_old)
    with pytest.raises(ValueError):
        encryption.decrypt_data(old_v2)

    monkeypatch.setattr(settings, "ENCRYPTION_KEY_PREVIOUS", f"some-other-old-key, {old_secret}")
    assert encryption.decrypt_data(under_old) == "written before the rotation"
    assert encryption.decrypt_data(old_v2) == "written long before"
    assert encryption.current_key_id() != old_key_id
    assert encryption.encrypt_data("new").split(":")[1] == encryption.current_key_id()
    assert encryption.needs_rotation(under_old) and encryption.needs_rotation(old_v2)


def test_a_blob_is_bound_to_the_row_it_was_sealed_for():
    """Nothing tied a ciphertext to its place: with write access to the
    database, a session's admin-only credentials blob could be copied into
    its transcript column and read back by an analyst."""
    credentials = encryption.session_context(7, "credentials_encrypted")
    transcript = encryption.session_context(7, "transcript_encrypted")
    blob = encryption.encrypt_data('[{"password": "x"}]', credentials)

    assert encryption.decrypt_data(blob, credentials) == '[{"password": "x"}]'
    with pytest.raises(encryption.ContextMismatch):
        encryption.decrypt_data(blob, transcript)
    with pytest.raises(encryption.ContextMismatch):
        encryption.decrypt_data(blob, encryption.session_context(8, "credentials_encrypted"))

    # The label is authenticated: rewriting it does not make the blob open.
    version, key_id, _, payload = blob.split(":", 3)
    forged_label = base64.urlsafe_b64encode(transcript.encode()).decode().rstrip("=")
    with pytest.raises(ValueError):
        encryption.decrypt_data(f"{version}:{key_id}:{forged_label}:{payload}", transcript)
    with pytest.raises(ValueError):
        encryption.decrypt_data(f"{version}:{key_id}::{payload}")


async def test_rotate_key_reencrypts_and_binds_every_blob(db_session, monkeypatch):
    from app.core import rotate_key

    settings = get_settings()
    old_secret = settings.ENCRYPTION_KEY
    node = await _node(db_session)
    session = HoneypotSession(
        node_id=node.id, protocol="ssh", attacker_ip="45.83.64.70",
        raw_commands_encrypted=_legacy_v2(b"id\nuname -a", old_secret),
        credentials_encrypted=encryption.encrypt_data('[{"username": "root"}]'),
    )
    content = b"#!/bin/sh\n"
    sha256 = hashlib.sha256(content).hexdigest()
    sample = PayloadSample(
        sha256=sha256, sha1="", md5="", size=len(content),
        content_encrypted=_legacy_v2(content, old_secret),
    )
    user = User(
        email="rotate@example.com", hashed_password="x", role=UserRole.ADMIN,
        totp_secret_encrypted=encryption.encrypt_data("JBSWY3DPEHPK3PXP"),
    )
    lost = HoneypotSession(
        node_id=node.id, protocol="ssh", attacker_ip="45.83.64.71",
        raw_commands_encrypted=_legacy_v2(b"gone", "a key nobody has any more"),
    )
    db_session.add_all([session, sample, user, lost])
    await db_session.commit()
    lost_before = lost.raw_commands_encrypted

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", "the-new-key-0123456789")
    monkeypatch.setattr(settings, "ENCRYPTION_KEY_PREVIOUS", old_secret)

    dry = await rotate_key.rotate(db_session, dry_run=True)
    assert dry == {"examined": 5, "rotated": 4, "current": 0, "failed": 1}
    await db_session.refresh(session)
    assert session.raw_commands_encrypted.startswith("v2:")  # a dry run writes nothing

    done = await rotate_key.rotate(db_session, batch_size=1)
    assert done == {"examined": 5, "rotated": 4, "current": 0, "failed": 1}
    for row in (session, sample, user, lost):
        await db_session.refresh(row)

    # Everything now opens with the new key alone...
    monkeypatch.setattr(settings, "ENCRYPTION_KEY_PREVIOUS", "")
    commands = encryption.session_context(session.id, "raw_commands_encrypted")
    assert encryption.decrypt_data(session.raw_commands_encrypted, commands) == "id\nuname -a"
    assert encryption.decrypt_bytes(sample.content_encrypted, encryption.payload_context(sha256)) == content
    assert encryption.decrypt_data(user.totp_secret_encrypted, encryption.totp_context(user.id)) == "JBSWY3DPEHPK3PXP"
    # ...and is bound to its own row and column.
    with pytest.raises(encryption.ContextMismatch):
        encryption.decrypt_data(
            session.credentials_encrypted, encryption.session_context(session.id, "transcript_encrypted")
        )
    # What could not be opened is left exactly as it was.
    assert lost.raw_commands_encrypted == lost_before

    again = await rotate_key.rotate(db_session)
    assert again == {"examined": 5, "rotated": 0, "current": 4, "failed": 1}
