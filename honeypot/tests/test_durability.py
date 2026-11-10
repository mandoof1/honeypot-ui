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

OLD_CAPTURE = "0a1b2c3d-1111-4222-8333-444455556666.json"
NEW_CAPTURE = "0a1b2c3d-1111-4222-8333-444455557777.json"


def test_retention_prunes_old_files_but_not_spool_or_host_keys(tmp_path):
    from honeypot.core.retention import prune_captures

    sessions = tmp_path / "sessions"
    uploads = tmp_path / "uploads"
    (sessions / "spool").mkdir(parents=True)
    uploads.mkdir()
    old = time.time() - 10 * 86400
    for name in (OLD_CAPTURE, "ssh_host_ed25519_key", "spool/queued.json", NEW_CAPTURE):
        path = sessions / name
        path.write_text("{}")
    (uploads / "abc").write_bytes(b"x")
    (uploads / "fresh").write_bytes(b"y")
    for path in (sessions / OLD_CAPTURE, sessions / "ssh_host_ed25519_key", sessions / "spool/queued.json", uploads / "abc"):
        os.utime(path, (old, old))

    result = prune_captures(str(sessions), str(uploads), 7, 7)
    assert result == {"sessions": 1, "uploads": 1}
    assert not (sessions / OLD_CAPTURE).exists()
    assert (sessions / NEW_CAPTURE).exists()
    assert (sessions / "ssh_host_ed25519_key").exists()
    assert (sessions / "spool" / "queued.json").exists()
    assert (uploads / "fresh").exists()


def test_retention_keeps_the_host_identity_and_other_engine_state(tmp_path):
    """The session pass deleted every old ``*.json``, the identity included:
    a week after first start the decoy became a different machine."""
    from honeypot.core.retention import prune_captures

    sessions = tmp_path / "sessions"
    sessions.mkdir()
    old = time.time() - 30 * 86400
    kept = ("host-identity.json", "accepted-logins.json", "tls-cert.pem", "notes.json")
    for name in kept + (OLD_CAPTURE,):
        (sessions / name).write_text("{}")
        os.utime(sessions / name, (old, old))

    result = prune_captures(str(sessions), str(tmp_path / "uploads"), 7, 7)
    assert result["sessions"] == 1
    assert not (sessions / OLD_CAPTURE).exists()
    for name in kept:
        assert (sessions / name).exists(), name


def test_identity_survives_a_retention_pass_after_a_week(tmp_path, monkeypatch):
    from honeypot.core.identity import IDENTITY_FILE, get_identity, reset_identity
    from honeypot.core.retention import prune_captures

    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    reset_identity()
    try:
        before = get_identity()
        path = tmp_path / "sessions" / IDENTITY_FILE
        aged = time.time() - 8 * 86400
        os.utime(path, (aged, aged))
        prune_captures(str(tmp_path / "sessions"), str(tmp_path / "uploads"), 7, 30)
        reset_identity()
        after = get_identity()
        assert (after.seed, after.hostname, after.boot_time) == (
            before.seed, before.hostname, before.boot_time
        )
    finally:
        reset_identity()


# -- write-ahead and poison payloads -----------------------------------------

async def test_session_is_on_disk_before_the_first_post_and_gone_after(manager):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        # What the spool held at the moment the backend was first asked.
        seen["queued"] = [Spool.session_id_of(p) for p in manager.spool.oldest(10)]
        return httpx.Response(200, json={"ai_classification": {"category": "benign"}})

    _backend(manager, handler)
    session_id = await _finished_session(manager)
    await manager.end_session(session_id)
    await manager.drain()

    assert seen["queued"] == [session_id]
    assert manager.spool.pending == 0
    assert manager.ingest_stats["sent"] == 1


async def test_shutdown_mid_post_keeps_the_session_for_the_next_start(manager, tmp_path):
    release = asyncio.Event()

    async def hang(request: httpx.Request) -> httpx.Response:
        await release.wait()
        return httpx.Response(200, json={})

    _backend(manager, hang)
    session_id = await _finished_session(manager)
    await manager.end_session(session_id)
    # The drain gives up long before the POST's own timeout would.
    await manager.drain(timeout=0.2)
    assert not manager._background
    assert manager.spool.pending == 1

    # A new process: nothing in memory, only the directory.
    received = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(json.loads(request.content)["session_id"])
        return httpx.Response(200, json={})

    restarted = SessionManager()
    _backend(restarted, handler)
    assert await restarted.replay_spool() == 1
    assert received == [session_id]
    assert restarted.spool.pending == 0
    release.set()


async def test_one_payload_the_backend_cannot_take_does_not_block_the_rest(manager):
    def handler(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content)["session_id"] == "poison":
            return httpx.Response(500)
        return httpx.Response(200, json={})

    _backend(manager, handler)
    manager.spool.put("poison", {"session_id": "poison"})
    for i in range(3):
        time.sleep(0.001)
        manager.spool.put(f"good{i}", {"session_id": f"good{i}"})

    assert await manager.replay_spool() == 3
    remaining = manager.spool.oldest(10)
    assert [Spool.session_id_of(p) for p in remaining] == ["poison"]
    # The backend answered others after failing it, so the failure counts.
    assert Spool.attempts_of(remaining[0]) == 1


async def test_a_poison_payload_is_dead_lettered_after_bounded_attempts(manager, monkeypatch):
    monkeypatch.setattr(SessionManager, "SPOOL_MAX_ATTEMPTS", 3)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/nodes/heartbeat-internal"):
            return httpx.Response(200, json={"id": 1, "mode": "active"})
        if request.url.path.endswith("/nodes/register-internal"):
            return httpx.Response(200, json={"id": 1, "mode": "active"})
        return httpx.Response(502)

    _backend(manager, handler)
    manager.spool.put("poison", {"session_id": "poison"})
    for _ in range(3):
        assert await manager.replay_spool() == 0
        # Alone in the queue, so only the heartbeat can vouch for the backend.
        assert await manager.heartbeat({}) is True

    assert manager.spool.pending == 0
    assert manager.ingest_stats["dead_lettered"] == 1
    failed_dir = os.path.join(config.session_capture_dir, "failed")
    kept = [n for n in os.listdir(failed_dir) if n.endswith(".json")]
    assert len(kept) == 1
    with open(os.path.join(failed_dir, kept[0])) as handle:
        record = json.load(handle)
    assert record["payload"] == {"session_id": "poison"}
    assert "3 times" in record["reason"]


async def test_an_outage_never_counts_against_the_queued_sessions(manager, monkeypatch):
    monkeypatch.setattr(SessionManager, "SPOOL_MAX_ATTEMPTS", 2)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    _backend(manager, handler)
    for i in range(2):
        manager.spool.put(f"s{i}", {"session_id": f"s{i}"})
        time.sleep(0.001)
    # Nothing ever succeeds, so no failure can be pinned on a payload.
    for _ in range(6):
        await manager.replay_spool()
    assert manager.spool.pending == 2
    assert all(Spool.attempts_of(p) == 0 for p in manager.spool.oldest(10))


async def test_attempt_count_survives_a_restart(tmp_path):
    spool = Spool(str(tmp_path), 100, 10_000)
    path = spool.put("abc", {"session_id": "abc"})
    path = spool.note_attempt(path)
    path = spool.note_attempt(path)
    reopened = Spool(str(tmp_path), 100, 10_000)
    queued = reopened.oldest(10)
    assert queued == [path]
    assert Spool.attempts_of(queued[0]) == 2
    assert Spool.session_id_of(queued[0]) == "abc"
    assert reopened.pending == 1


async def test_a_rejection_during_replay_goes_to_failed_and_the_pass_continues(manager):
    def handler(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content)["session_id"] == "bad":
            return httpx.Response(422, json={"detail": "no"})
        return httpx.Response(200, json={})

    _backend(manager, handler)
    manager.spool.put("bad", {"session_id": "bad"})
    time.sleep(0.001)
    manager.spool.put("fine", {"session_id": "fine"})
    assert await manager.replay_spool() == 1
    assert manager.spool.pending == 0
    assert manager.ingest_stats["rejected"] == 1


# -- memory bounds -------------------------------------------------------------

async def test_output_is_capped_when_recorded_not_when_sent(manager):
    session_id = await manager.create_session("ssh", "198.51.100.9", 40000)
    session = await manager.get_session(session_id)
    await manager.record_command(session_id, "cat big", "x" * 1_000_000, 0)
    assert len(session.commands[0]["output"]) == session.MAX_OUTPUT_CHARS
    assert session.truncated == {"outputs": 1}


async def test_many_huge_commands_stay_inside_the_session_budget(manager):
    session_id = await manager.create_session("ssh", "198.51.100.9", 40000)
    session = await manager.get_session(session_id)
    huge = "echo " + "A" * (256 * 1024)
    for _ in range(session.MAX_COMMANDS):
        await manager.record_command(session_id, huge, "", 0)
    held = sum(len(c["command"]) + len(c["output"]) for c in session.commands)
    ceiling = session.MAX_TRANSCRIPT_CHARS + session.MAX_COMMANDS * session.MIN_COMMAND_CHARS
    assert held <= ceiling
    assert session.truncated["transcript"] > 0
    # A command past the budget is still identifiable.
    assert session.commands[-1]["command"].startswith("echo AAAA")
    payload = session.to_backend_payload(1)
    assert payload["truncated"]["transcript"] == session.truncated["transcript"]


async def test_a_command_recorded_first_gets_its_output_later(manager):
    session_id = await manager.create_session("ssh", "198.51.100.9", 40000)
    session = await manager.get_session(session_id)
    entry = await manager.record_command(session_id, "uname -a")
    assert session.commands[0]["output"] == ""
    await manager.set_command_result(session_id, entry, "Linux\n", 0)
    assert session.commands[0]["output"] == "Linux\n"
    # Replacing an output does not charge the budget twice.
    await manager.set_command_result(session_id, entry, "Linux\n", 3)
    assert session.transcript_chars == len("uname -a") + len("Linux\n")
    assert session.commands[0]["exit_code"] == 3


async def test_refused_uploads_are_counted_and_keep_their_digest(manager, monkeypatch):
    import hashlib

    monkeypatch.setattr(SessionManager, "MAX_UPLOAD_BYTES", 64)
    monkeypatch.setattr(SessionManager, "MAX_UPLOADS_PER_SESSION", 1)
    session_id = await manager.create_session("ssh", "198.51.100.9", 40000)
    session = await manager.get_session(session_id)

    big = b"B" * 200
    assert await manager.record_file_upload(session_id, "big.bin", big, "/tmp/big.bin", "sftp") is None
    assert await manager.record_file_upload(session_id, "one", b"1", "/tmp/one", "sftp")
    assert await manager.record_file_upload(session_id, "two", b"2", "/tmp/two", "sftp") is None

    assert session.truncated == {"uploads_oversize": 1, "uploads_over_count": 1}
    uploads = {u["filename"]: u for u in session.to_backend_payload(1)["uploads"]}
    assert uploads["big.bin"]["sha256"] == hashlib.sha256(big).hexdigest()
    assert uploads["big.bin"]["size"] == 200
    assert uploads["big.bin"]["dropped"] == "oversize"
    assert "content_b64" not in uploads["big.bin"]
    assert uploads["two"]["dropped"] == "over_count"
    assert "content_b64" in uploads["one"]


async def test_credentials_are_bounded_where_they_enter(manager):
    session_id = await manager.create_session("ssh", "198.51.100.9", 40000)
    session = await manager.get_session(session_id)
    await manager.record_auth_attempt(session_id, "root", "p" * 200_000, False)
    assert len(session.authentication_attempts[0]["password"]) == session.MAX_CREDENTIAL_CHARS


# -- payload contract ----------------------------------------------------------

async def test_new_event_types_and_fingerprints_reach_the_payload(manager):
    session_id = await manager.create_session("ssh", "198.51.100.9", 40000)
    session = await manager.get_session(session_id)
    assert "fingerprints" not in session.to_backend_payload(1)

    await manager.record_network_event(
        session_id, "ai_canary_triggered", {"canary": "t", "channel": "shell", "detail": "d"})
    await manager.record_network_event(
        session_id, "honeytoken_used", {"token_id": "db", "kind": "credential", "detail": "d"})
    await manager.record_network_event(session_id, "connection_refused", {"reason": "rate"})
    await manager.record_network_event(
        session_id, "direct_tcpip", {"dest_host": "192.0.2.1", "dest_port": 25})
    await manager.record_network_event(session_id, "ssh_client_banner", {"banner": "x"})
    session.fingerprints.update({
        "ssh_client_version": "SSH-2.0-Go", "hassh": "a" * 32, "ja3": "", "unlisted": "x",
    })

    payload = session.to_backend_payload(1)
    assert [e["event_type"] for e in payload["events"]] == [
        "ai_canary_triggered", "honeytoken_used", "connection_refused", "direct_tcpip",
    ]
    assert payload["events"][3]["dest_port"] == 25
    assert all("at" in e for e in payload["events"])
    # Empty values and keys outside the contract are left out.
    assert payload["fingerprints"] == {"ssh_client_version": "SSH-2.0-Go", "hassh": "a" * 32}
