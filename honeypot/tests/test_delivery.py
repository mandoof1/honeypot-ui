import asyncio
import json
import stat
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from honeypot.core import outbox as delivery
from honeypot.core.config import config
from honeypot.core.outbox import DeliveryOutbox
from honeypot.core.session import SessionManager


@pytest.fixture
def queue(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: clock[0]))
    return DeliveryOutbox(tmp_path / "delivery.sqlite3", "http://test/api/v1", "private-token"), clock


def payload():
    return {"capture_id": str(uuid4()), "attacker_ip": "192.0.2.1", "commands": ["uname -a"]}


def transport(send):
    async def handle(request):
        if request.url.path.endswith("ingest-capabilities"):
            return httpx.Response(200, json={"idempotent_capture": True})
        response = send(request)
        return await response if asyncio.iscoroutine(response) else response
    return httpx.MockTransport(handle)


async def test_timeout_survives_restart_and_pins_node(queue):
    outbox, clock = queue
    capture = payload()
    await outbox.enqueue(capture)
    requests = []

    def send(request):
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ReadTimeout("receipt lost")
        return httpx.Response(200, json={"session_uuid": capture["capture_id"]})

    register = AsyncMock(return_value=42)
    async with httpx.AsyncClient(transport=transport(send)) as client:
        await outbox.deliver_one(client, register)
        assert (await outbox.stats())["retrying"] == 1
        assert not await outbox.deliver_one(client, register)  # Backoff is real.
        clock[0] += 400
        restarted = DeliveryOutbox(outbox.path, outbox.api_url, outbox.token)
        await restarted.deliver_one(client, AsyncMock(return_value=99))
        assert (await restarted.stats())["pending"] == 0
    assert len(requests) == 2
    assert all(request.url.params["node_id"] == "42" for request in requests)
    assert requests[0].content == requests[1].content
    assert stat.S_IMODE(outbox.path.stat().st_mode) == 0o600


@pytest.mark.parametrize("status", [401, 404, 409, 422, 429, 503])
async def test_rejection_retains_evidence_without_leaking_body(queue, status):
    outbox, clock = queue
    await outbox.enqueue(payload(), 7)
    async with httpx.AsyncClient(transport=transport(lambda request: httpx.Response(
        status, text="secret-password", headers={"Retry-After": "600"},
    ))) as client:
        assert await outbox.deliver_one(client, AsyncMock())
        clock[0] += 599
        assert not await outbox.deliver_one(client, AsyncMock())
    stats = await outbox.stats()
    assert stats["pending"] == stats["retrying"] == 1
    assert stats["last_error"] == f"Ingest HTTP {status}"
    assert "secret-password" not in outbox.path.read_bytes().decode(errors="ignore")


async def test_wrong_receipt_does_not_discard_capture(queue):
    outbox, _ = queue
    await outbox.enqueue(payload(), 7)
    async with httpx.AsyncClient(transport=transport(lambda request: httpx.Response(
        200, json={"session_uuid": str(uuid4())},
    ))) as client:
        await outbox.deliver_one(client, AsyncMock())
    assert (await outbox.stats())["pending"] == 1


async def test_registration_failure_never_falls_back_to_node_one(queue):
    outbox, _ = queue
    await outbox.enqueue(payload())
    send = AsyncMock()
    get = AsyncMock(return_value=httpx.Response(200, json={"idempotent_capture": True}))
    await outbox.deliver_one(SimpleNamespace(post=send, get=get), AsyncMock(return_value=None))
    send.assert_not_called()
    assert (await outbox.stats())["pending"] == 1


async def test_one_poison_capture_does_not_block_others(queue):
    outbox, _ = queue
    first, second = payload(), payload()
    await outbox.enqueue(first, 7)
    await outbox.enqueue(second, 7)

    def send(request):
        capture = json.loads(request.content)["capture_id"]
        return httpx.Response(422) if capture == first["capture_id"] else httpx.Response(200, json={"session_uuid": capture})

    async with httpx.AsyncClient(transport=transport(send)) as client:
        await outbox.deliver_one(client, AsyncMock())
        await outbox.deliver_one(client, AsyncMock())
    assert (await outbox.stats())["pending"] == 1
    assert (await outbox.stats())["retrying"] == 1


async def test_shutdown_during_send_preserves_capture(queue, monkeypatch):
    outbox, _ = queue
    await outbox.enqueue(payload(), 7)
    started = asyncio.Event()

    async def blocked(request):
        started.set()
        await asyncio.Event().wait()

    original = httpx.AsyncClient
    monkeypatch.setattr(delivery.httpx, "AsyncClient", lambda: original(transport=transport(blocked)))
    await outbox.start(AsyncMock())
    await asyncio.wait_for(started.wait(), 2)
    await asyncio.wait_for(outbox.stop(), 2)
    assert (await outbox.stats())["pending"] == 1


async def test_legacy_api_is_never_sent_a_capture(queue):
    outbox, _ = queue
    await outbox.enqueue(payload(), 7)
    send = AsyncMock()
    get = AsyncMock(return_value=httpx.Response(404))
    await outbox.deliver_one(SimpleNamespace(post=send, get=get), AsyncMock())
    send.assert_not_called()
    assert (await outbox.stats())["pending"] == 1


async def test_outage_pauses_the_sender_instead_of_hammering_api(queue):
    outbox, _ = queue
    for _ in range(10):
        await outbox.enqueue(payload(), 7)
    send = AsyncMock(return_value=httpx.Response(503))
    async with httpx.AsyncClient(transport=transport(send)) as client:
        assert await outbox.deliver_one(client, AsyncMock())
        assert not await outbox.deliver_one(client, AsyncMock())
    assert send.call_count == 1
    assert (await outbox.stats())["pending"] == 10


@pytest.fixture
def manager(tmp_path, monkeypatch):
    for setting, directory in (("session_capture_dir", "sessions"), ("file_capture_dir", "uploads"), ("log_dir", "logs")):
        monkeypatch.setattr(config, setting, str(tmp_path / directory))
    return SessionManager()


async def test_capture_limits_apply_while_recording_and_survive_delivery(manager):
    sid = await manager.create_session("ssh", "192.0.2.4", 22222)
    for _ in range(510):
        await manager.record_command(sid, "x" * 5000, "y" * 5000)
    for _ in range(210):
        await manager.record_auth_attempt(sid, "u" * 200, "p" * 200, False)
        await manager.record_network_event(sid, "file_download", {"url": "x" * 5000})
    for _ in range(1030):
        await manager.record_keystroke(sid, "x")
    capture = await manager.end_session(sid)
    assert len(capture.commands) == 500
    assert len(capture.commands[0]["command"]) == len(capture.commands[0]["output"]) == 4096
    assert len(capture.authentication_attempts) == 200
    assert len(capture.authentication_attempts[0]["password"]) == 128
    assert len(capture.network_events) == 200
    assert len(capture.keystrokes) == 1024
    assert capture.capture_dropped["commands"] == 10
    assert capture.capture_dropped["credentials"] == capture.capture_dropped["events"] == 10
    assert capture.to_backend_payload()["keystroke_count"] == 1030
    assert (await manager.outbox.stats())["pending"] == 1
    # An ended session is immutable, even if an emulator writes late.
    await manager.record_command(sid, "late")
    await manager.end_session(sid)
    assert (await manager.outbox.stats())["pending"] == 1
    archive = manager.outbox.path.parent / f"{sid}.json"
    assert json.loads(archive.read_text())["capture_dropped"]["commands"] == 10
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert await manager.get_session(sid) is None
    assert await manager.get_session_count() == 1


async def test_upload_budget_is_per_session_not_per_file(manager, monkeypatch):
    monkeypatch.setattr(manager, "MAX_UPLOAD_BYTES", 10)
    sid = await manager.create_session("ftp", "192.0.2.4", 22222)
    await manager.record_file_upload(sid, "../../escape", b"123456")
    await manager.record_file_upload(sid, "second", b"abcdef")
    capture = await manager.get_session(sid)
    assert len(capture.files_uploaded) == 1
    assert capture.capture_dropped["uploads"] == 1
    assert len(list(manager.outbox.path.parent.parent.joinpath("uploads").iterdir())) == 1


async def test_archive_failure_does_not_lose_queued_capture(manager, monkeypatch):
    monkeypatch.setattr(manager, "_persist_session", AsyncMock(side_effect=OSError("disk unavailable")))
    sid = await manager.create_session("ssh", "192.0.2.4", 22222)
    await manager.end_session(sid)
    assert (await manager.outbox.stats())["pending"] == 1
    assert manager.capture_errors == 1


async def test_cancelled_handler_still_finishes_capture_before_shutdown(manager, monkeypatch):
    sid = await manager.create_session("ssh", "192.0.2.4", 22222)
    started, release = asyncio.Event(), asyncio.Event()
    enqueue = manager.outbox.enqueue

    async def slow_enqueue(*args):
        started.set()
        await release.wait()
        await enqueue(*args)

    monkeypatch.setattr(manager.outbox, "enqueue", slow_enqueue)
    caller = asyncio.create_task(manager.end_session(sid))
    await started.wait()
    caller.cancel()
    await asyncio.gather(caller, return_exceptions=True)
    release.set()
    await manager.drain()
    assert (await manager.outbox.stats())["pending"] == 1
    assert await manager.get_session(sid) is None


async def test_http_headers_remain_captured_with_bounded_values(manager):
    sid = await manager.create_session("http", "192.0.2.4", 22222)
    await manager.record_network_event(sid, "http_request", {
        "headers": {"user-agent": "test-client", "x-large": "x" * 20_000},
        "timestamp": "forged", "event_type": "forged",
    })
    capture = await manager.get_session(sid)
    event = capture.network_events[0]
    assert event["headers"]["user-agent"] == "test-client"
    assert len(event["headers"]["x-large"]) == 4096
    assert event["event_type"] == "http_request"
    assert isinstance(event["timestamp"], float)
    assert capture.capture_dropped["event_characters"] == 15904


async def test_storage_failure_reports_unknown_backlog(queue, monkeypatch):
    outbox, _ = queue
    monkeypatch.setattr(outbox, "_db", AsyncMock(side_effect=sqlite3.OperationalError("disk full")))
    stats = await outbox.stats()
    assert stats["available"] is False
    assert stats["pending"] is None
    assert "storage unavailable" in stats["last_error"]
