"""Bounds that keep one client from taking the engine down.

Each of these guards something that was configured but unenforced, or not
bounded at all: concurrent connections per address, requests per keep-alive
connection, the heredoc buffer, a passive-mode request that the reader
refuses, and the unauthenticated health probe.
"""

import asyncio
import json
import time

import pytest

from honeypot.capture.shell_writes import HeredocBuffer, needs_continuation, open_heredoc_delimiters
from honeypot.core.config import OperationalMode, config
from honeypot.core.control_api import ControlAPI
from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.emulators.http import HTTPHoneypot
from honeypot.security.rate_limiter import RateLimiter, rate_limiter


@pytest.fixture
async def http_server(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "http_upstream", "")
    monkeypatch.setattr(config, "http_decoy_upstream", "")

    async def swallow(session):
        return None

    monkeypatch.setattr(session_manager, "_send_to_backend", swallow)
    honeypot = HTTPHoneypot(use_tls=False)
    honeypot.port = 0
    await honeypot.start()
    port = honeypot._server.sockets[0].getsockname()[1]
    try:
        yield honeypot, port
    finally:
        await honeypot.stop()


# -- heredoc -----------------------------------------------------------------

def test_open_delimiters_are_reported_in_order():
    assert open_heredoc_delimiters("cat > a <<EOF; cat > b <<-'END'") == [("EOF", False), ("END", True)]
    assert open_heredoc_delimiters("echo hi") == []


def test_heredoc_buffer_closes_on_delimiter_and_keeps_content():
    buffer = HeredocBuffer("cat > /tmp/x <<EOF", 1 << 20)
    assert buffer.open
    buffer.feed("line one")
    buffer.feed("  EOF ")  # not the delimiter: surrounding whitespace
    assert buffer.open
    buffer.feed("EOF")
    assert not buffer.open
    assert buffer.text() == "cat > /tmp/x <<EOF\nline one\n  EOF \nEOF"
    assert not needs_continuation(buffer.text())


def test_heredoc_buffer_handles_two_heredocs_and_tab_stripping():
    buffer = HeredocBuffer("cat <<A; cat <<-B", 1 << 20)
    buffer.feed("a body")
    buffer.feed("A")
    assert buffer.open
    buffer.feed("\t\tB")
    assert not buffer.open


def test_twenty_thousand_line_heredoc_is_linear():
    buffer = HeredocBuffer("cat > /tmp/payload <<EOF", 4 << 20)
    started = time.perf_counter()
    for _ in range(20_000):
        buffer.feed("")
        if not buffer.open:
            break
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"took {elapsed:.2f}s"
    # Force-closed by the line cap rather than left open for ever.
    assert not buffer.open
    assert buffer.exhausted


def test_heredoc_buffer_byte_cap():
    buffer = HeredocBuffer("cat <<EOF", 100)
    for _ in range(20):
        buffer.feed("x" * 10)
    assert not buffer.open and buffer.exhausted


# -- rate limiter admission ----------------------------------------------------

def test_admit_enforces_per_ip_and_global_caps(monkeypatch):
    limiter = RateLimiter()
    limiter._max_per_ip = 2
    limiter._max_total = 3
    limiter._max_requests = 1000
    assert limiter.admit("10.0.0.1")
    assert limiter.admit("10.0.0.1")
    assert not limiter.admit("10.0.0.1")
    assert limiter.refused["per_ip"] == 1
    assert limiter.admit("10.0.0.2")
    assert not limiter.admit("10.0.0.3")
    assert limiter.refused["total"] == 1
    limiter.release("10.0.0.1")
    assert limiter.admit("10.0.0.3")
    assert limiter.active_connections() == 3
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        limiter.release(ip)
    assert limiter.active_connections() == 0
    # Releasing more than was admitted never goes negative.
    limiter.release("10.0.0.9")
    assert limiter.active_connections() == 0


def test_admit_respects_blocks_without_counting():
    limiter = RateLimiter()
    limiter._blocked["10.0.0.5"] = time.time() + 60
    assert not limiter.admit("10.0.0.5")
    assert limiter.refused["blocked"] == 1
    assert limiter.active_connections() == 0


# -- live connection caps -------------------------------------------------------

async def _open(port):
    return await asyncio.open_connection("127.0.0.1", port)


async def test_per_ip_concurrent_connections_are_capped(http_server, monkeypatch):
    _, port = http_server
    monkeypatch.setattr(rate_limiter, "_max_per_ip", 2)
    connections = []
    try:
        for _ in range(2):
            connections.append(await _open(port))
        reader, writer = await _open(port)
        connections.append((reader, writer))
        # The third is closed at accept, before any protocol work.
        assert await asyncio.wait_for(reader.read(1), timeout=5) == b""
        assert rate_limiter.refused["per_ip"] >= 1
    finally:
        for _, w in connections:
            w.close()
    # Wait for the handlers to release their slots.
    for _ in range(50):
        if rate_limiter.active_connections() == 0:
            break
        await asyncio.sleep(0.05)
    assert rate_limiter.active_connections() == 0


async def test_keep_alive_request_cap(http_server, monkeypatch):
    honeypot, port = http_server
    monkeypatch.setattr(HTTPHoneypot, "MAX_REQUESTS_PER_CONNECTION", 3)
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    reader, writer = await _open(port)
    served = 0
    try:
        for _ in range(5):
            writer.write(b"GET /robots.txt HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            try:
                status = await asyncio.wait_for(reader.readline(), timeout=5)
            except asyncio.TimeoutError:
                break
            if not status:
                break
            served += 1
            # Skip the rest of this response.
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if line in (b"\r\n", b""):
                    break
                k, _, v = line.decode().partition(":")
                headers[k.strip().lower()] = v.strip()
            length = int(headers.get("content-length", 0))
            if length:
                await asyncio.wait_for(reader.readexactly(length), timeout=5)
    finally:
        writer.close()
    assert served == 3


async def test_passive_mode_refused_line_still_ends_session(http_server, monkeypatch):
    _, port = http_server
    monkeypatch.setattr(mode_handler, "mode", OperationalMode.PASSIVE_MONITORING)
    before = {s.session_id for s in await session_manager.get_active_sessions()}
    reader, writer = await _open(port)
    try:
        # No newline within the reader's 64 KiB limit: readline() raises.
        writer.write(b"GET /" + b"A" * 70_000)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(1), timeout=5) == b""
    finally:
        writer.close()
    for _ in range(50):
        active = {s.session_id for s in await session_manager.get_active_sessions()} - before
        if not active:
            break
        await asyncio.sleep(0.05)
    assert not active, "passive-mode session leaked"


# -- health probe -----------------------------------------------------------------

async def _http_get(port, path, token=None):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    headers = f"GET {path} HTTP/1.1\r\nHost: x\r\n"
    if token:
        headers += f"X-Honeypot-Token: {token}\r\n"
    writer.write((headers + "\r\n").encode())
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(65536), timeout=5)
    writer.close()
    head, _, body = raw.decode().partition("\r\n\r\n")
    return int(head.split()[1]), (json.loads(body) if body else None)


async def test_healthz_needs_no_token_but_status_does():
    api = ControlAPI("127.0.0.1", 0, "secret-token")

    @api.route("GET", "/healthz")
    async def healthz(_body):
        return {"ok": True, "active_sessions": 0, "spool_pending": 0}

    @api.route("GET", "/status")
    async def status(_body):
        return {"running": True}

    await api.start()
    port = api._server.sockets[0].getsockname()[1]
    try:
        assert await _http_get(port, "/healthz") == (200, {"ok": True, "active_sessions": 0, "spool_pending": 0})
        assert (await _http_get(port, "/status"))[0] == 401
        assert (await _http_get(port, "/status", "secret-token"))[0] == 200
        assert (await _http_get(port, "/nope", "secret-token"))[0] == 404
    finally:
        await api.stop()
