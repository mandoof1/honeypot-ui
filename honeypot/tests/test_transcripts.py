"""What the HTTP and FTP decoys hand the backend, and passive mode.

Requests and FTP commands used to be recorded only as engine-side network
events, which the ingest never forwards, so these sessions reached the
dashboard as empty rows. These tests read the ingest payload itself.
"""

import asyncio
import base64
import ftplib

import pytest

from honeypot.core.config import OperationalMode, config
from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.emulators.ftp import FTPHoneypot
from honeypot.emulators.http import HTTPHoneypot


@pytest.fixture
def ingested(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    queue: asyncio.Queue = asyncio.Queue()

    async def capture(session):
        await queue.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture)
    previous = mode_handler.mode
    yield queue
    mode_handler.mode = previous


async def _http(port: int, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    return response


@pytest.fixture
async def http_port():
    honeypot = HTTPHoneypot()
    honeypot.port = 24340
    await honeypot.start()
    yield honeypot.port
    await honeypot.stop()


async def test_http_request_reaches_the_transcript_with_agent_and_body(ingested, http_port):
    body = b"id=1' UNION SELECT username,password FROM users--"
    await _http(http_port, (
        b"POST /search HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.8.2\r\n"
        b"Content-Type: text/plain\r\nContent-Length: " + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n" + body
    ))
    payload = await asyncio.wait_for(ingested.get(), timeout=10)

    [entry] = payload["transcript"]
    assert entry["command"].startswith("POST /search  [ua: sqlmap/1.8.2]")
    assert "UNION SELECT" in entry["command"]
    assert entry["output"].startswith("HTTP/1.1 200")
    assert payload["commands"] == [entry["command"]]


async def test_login_form_credentials_are_captured(ingested, http_port):
    body = b"log=admin&pwd=hunter2&wp-submit=Log+In"
    await _http(http_port, (
        b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
    ))
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    [cred] = payload["credentials"]
    assert (cred["username"], cred["password"]) == ("admin", "hunter2")


async def test_basic_auth_credentials_are_captured(ingested, http_port):
    token = base64.b64encode(b"tomcat:s3cret").decode()
    await _http(http_port, (
        f"GET /manager/html HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {token}\r\n"
        "Connection: close\r\n\r\n"
    ).encode())
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    [cred] = payload["credentials"]
    assert (cred["username"], cred["password"]) == ("tomcat", "s3cret")


async def test_passive_http_records_the_request_and_answers_nothing(ingested, http_port):
    mode_handler.mode = OperationalMode.PASSIVE_MONITORING
    response = await _http(http_port, b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n")
    payload = await asyncio.wait_for(ingested.get(), timeout=10)

    assert response == b""
    [entry] = payload["transcript"]
    assert entry["command"] == "GET /.env"
    assert "passive" in entry["output"]


async def test_ftp_commands_reach_the_transcript_with_the_password_masked(ingested):
    honeypot = FTPHoneypot()
    honeypot.port = 24341
    await honeypot.start()
    try:
        def session():
            client = ftplib.FTP()
            client.connect("127.0.0.1", honeypot.port, timeout=10)
            client.login("anonymous", "guest@example.com")
            client.cwd("/")
            client.quit()

        await asyncio.to_thread(session)
        payload = await asyncio.wait_for(ingested.get(), timeout=10)
    finally:
        await honeypot.stop()

    commands = [e["command"] for e in payload["transcript"]]
    assert "USER anonymous" in commands
    assert "PASS ********" in commands
    assert not any("guest@example.com" in c for c in commands)
    assert any(c.startswith("CWD") for c in commands)


def test_engine_adopts_the_mode_stored_for_its_node():
    previous = mode_handler.mode
    try:
        mode_handler.mode = OperationalMode.ACTIVE_EMULATION
        session_manager._adopt_stored_mode("passive")
        assert mode_handler.mode == OperationalMode.PASSIVE_MONITORING
        session_manager._adopt_stored_mode("nonsense")
        assert mode_handler.mode == OperationalMode.PASSIVE_MONITORING
    finally:
        mode_handler.mode = previous
