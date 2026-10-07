"""Sessions survive a backend outage, and the engine says it is alive.

Delivery used to be one attempt: anything but an immediate 200 dropped the
capture. These tests drive the spool through a mock backend that fails and
then recovers, and the heartbeat through the responses the backend gives.
"""

import asyncio
import json
import os
import time

import httpx
import pytest

from honeypot.core.config import config
from honeypot.core.session import SessionManager, session_manager
from honeypot.core.spool import Spool


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "backend_api_url", "http://backend.test/api/v1")
    manager = SessionManager()
    yield manager


def _backend(manager, handler):
    """Point the manager's HTTP client at an in-process fake backend."""
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"X-Honeypot-Token": config.ingest_token},
    )
    manager._client = client
    return client


async def _finished_session(manager, protocol="ssh"):
    session_id = await manager.create_session(protocol, "198.51.100.9", 40000)
    await manager.record_command(session_id, "uname -a", "Linux", 0)
    return session_id


# -- payload ---------------------------------------------------------------

async def test_payload_carries_engine_session_id_and_truncation(manager):
    session_id = await _finished_session(manager)
    session = await manager.get_session(session_id)
    for _ in range(session.MAX_COMMANDS + 5):
        await manager.record_command(session_id, "echo x", "x", 0)
    payload = session.to_backend_payload(7)
    assert payload["session_id"] == session_id
    assert len(session.commands) == session.MAX_COMMANDS
    assert payload["truncated"] == {"commands": 6}


async def test_event_and_credential_caps_count_drops(manager):
    session_id = await _finished_session(manager)
    session = await manager.get_session(session_id)
    for _ in range(session.MAX_NETWORK_EVENTS + 3):
        await manager.record_network_event(session_id, "http_request", {"path": "/"})
    for _ in range(session.MAX_AUTH_ATTEMPTS + 2):
        await manager.record_auth_attempt(session_id, "root", "x", False)
    assert len(session.network_events) == session.MAX_NETWORK_EVENTS
    assert len(session.authentication_attempts) == session.MAX_AUTH_ATTEMPTS
    assert session.truncated == {"events": 3, "credentials": 2}


# -- spool -----------------------------------------------------------------

async def test_backend_down_spools_then_replay_delivers(manager):
    state = {"up": False, "received": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if not state["up"]:
            raise httpx.ConnectError("refused", request=request)
        state["received"].append(json.loads(request.content))
        return httpx.Response(200, json={"session_id": 1, "ai_classification": {"category": "benign"}})

    _backend(manager, handler)
    session_id = await _finished_session(manager)
    await manager.end_session(session_id)
    await manager.drain()

    assert manager.spool.pending == 1
    assert manager.ingest_stats["spooled"] == 1
    queued = manager.spool.oldest(10)
    assert Spool.session_id_of(queued[0]) == session_id
    # The local copy was written too, independently of delivery.
    assert os.path.exists(os.path.join(config.session_capture_dir, f"{session_id}.json"))

    state["up"] = True
    delivered = await manager.replay_spool()
    assert delivered == 1
    assert manager.spool.pending == 0
    assert state["received"][0]["session_id"] == session_id
    assert manager.ingest_stats["replayed"] == 1


async def test_server_error_and_timeout_spool_but_rejection_does_not(manager):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503)
        if calls["n"] == 2:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(422, json={"detail": "bad"})

    _backend(manager, handler)
    for _ in range(3):
        session_id = await _finished_session(manager)
        await manager.end_session(session_id)
    await manager.drain()

    assert manager.spool.pending == 2
    assert manager.ingest_stats["rejected"] == 1
    failed_dir = os.path.join(config.session_capture_dir, "failed")
    assert len([n for n in os.listdir(failed_dir) if n.endswith(".json")]) == 1


async def test_replay_stops_at_first_outage_and_treats_duplicate_as_success(manager):
    outcomes = iter([
        httpx.Response(200, json={"duplicate": True}),
        None,  # connection error
    ])

    def handler(request: httpx.Request) -> httpx.Response:
        outcome = next(outcomes)
        if outcome is None:
            raise httpx.ConnectError("gone", request=request)
        return outcome

    _backend(manager, handler)
    for i in range(3):
        manager.spool.put(f"s{i}", {"session_id": f"s{i}", "protocol": "ssh"})
    delivered = await manager.replay_spool()
    assert delivered == 1
    assert manager.spool.pending == 2


def test_spool_evicts_oldest_when_full(tmp_path):
    spool = Spool(str(tmp_path), max_files=3, max_bytes=10_000)
    for i in range(5):
        spool.put(f"s{i}", {"session_id": f"s{i}"})
        time.sleep(0.001)
    assert spool.pending == 3
    assert [Spool.session_id_of(p) for p in spool.oldest(10)] == ["s2", "s3", "s4"]
    assert spool.bytes == sum(os.path.getsize(p) for p in spool.oldest(10))


def test_spool_byte_bound(tmp_path):
    spool = Spool(str(tmp_path), max_files=100, max_bytes=120)
    for i in range(4):
        spool.put(f"s{i}", {"session_id": f"s{i}", "pad": "x" * 20})
    assert spool.bytes <= 120
    assert spool.pending < 4


def test_spool_survives_restart_by_rescanning(tmp_path):
    first = Spool(str(tmp_path), 100, 10_000)
    first.put("a", {"session_id": "a"})
    second = Spool(str(tmp_path), 100, 10_000)
    assert second.pending == 1
    assert second.bytes > 0


async def test_persist_failure_does_not_block_delivery(manager, monkeypatch):
    received = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(200, json={"ai_classification": {"category": "benign"}})

    _backend(manager, handler)

    def boom(session):
        raise OSError("disk full")

    monkeypatch.setattr(manager, "_persist_session", boom)
    session_id = await _finished_session(manager)
    await manager.end_session(session_id)
    await manager.drain()
    assert len(received) == 1
    assert manager.ingest_stats["sent"] == 1


# -- heartbeat ---------------------------------------------------------------

async def test_heartbeat_payload_and_mode_adoption(manager, monkeypatch):
    from honeypot.core.config import OperationalMode
    from honeypot.core.modes import mode_handler

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/nodes/register-internal"):
            return httpx.Response(200, json={"id": 42, "mode": "active"})
        if path.endswith("/nodes/heartbeat-internal"):
            seen["body"] = json.loads(request.content)
            seen["token"] = request.headers.get("X-Honeypot-Token")
            return httpx.Response(200, json={"id": 42, "mode": "passive"})
        return httpx.Response(404)

    _backend(manager, handler)
    monkeypatch.setattr(mode_handler, "mode", OperationalMode.ACTIVE_EMULATION)

    status = {"running": True, "active_sessions": 0, "uptime_seconds": 5}
    assert await manager.heartbeat(status) is True
    assert manager.node_id == 42
    assert manager.registered
    assert seen["token"] == config.ingest_token
    assert seen["body"]["node_id"] == 42
    assert seen["body"]["name"] == config.node_name
    assert seen["body"]["status"] == status
    assert mode_handler.mode is OperationalMode.PASSIVE_MONITORING


async def test_heartbeat_404_reregisters(manager):
    calls = {"register": 0, "heartbeat": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/nodes/register-internal"):
            calls["register"] += 1
            return httpx.Response(200, json={"id": 5 + calls["register"], "mode": "active"})
        calls["heartbeat"] += 1
        if calls["heartbeat"] == 1:
            return httpx.Response(404, json={"detail": "Honeypot node not found"})
        return httpx.Response(200, json={"id": manager.node_id, "mode": "active"})

    _backend(manager, handler)
    assert await manager.heartbeat({}) is False
    # Registered once up front (unregistered manager), once after the 404.
    assert calls["register"] == 2
    assert manager.node_id == 7
    assert await manager.heartbeat({}) is True


async def test_heartbeat_outage_is_quiet_and_recovers(manager, caplog):
    state = {"up": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/nodes/register-internal"):
            return httpx.Response(200, json={"id": 3, "mode": "active"})
        if not state["up"]:
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, json={"id": 3, "mode": "active"})

    _backend(manager, handler)
    with caplog.at_level("WARNING", logger="honeypot.core.session"):
        for _ in range(3):
            assert await manager.heartbeat({}) is False
    assert sum("Heartbeat failed" in r.message for r in caplog.records) == 1
    state["up"] = True
    assert await manager.heartbeat({}) is True


# -- retention ---------------------------------------------------------------

def test_retention_prunes_old_files_but_not_spool_or_host_keys(tmp_path):
    from honeypot.core.retention import prune_captures

    sessions = tmp_path / "sessions"
    uploads = tmp_path / "uploads"
    (sessions / "spool").mkdir(parents=True)
    uploads.mkdir()
    old = time.time() - 10 * 86400
    for name in ("old.json", "ssh_host_ed25519_key", "spool/queued.json", "new.json"):
        path = sessions / name
        path.write_text("{}")
    (uploads / "abc").write_bytes(b"x")
    (uploads / "fresh").write_bytes(b"y")
    for path in (sessions / "old.json", sessions / "ssh_host_ed25519_key", sessions / "spool/queued.json", uploads / "abc"):
        os.utime(path, (old, old))

    result = prune_captures(str(sessions), str(uploads), 7, 7)
    assert result == {"sessions": 1, "uploads": 1}
    assert not (sessions / "old.json").exists()
    assert (sessions / "new.json").exists()
    assert (sessions / "ssh_host_ed25519_key").exists()
    assert (sessions / "spool" / "queued.json").exists()
    assert (uploads / "fresh").exists()
