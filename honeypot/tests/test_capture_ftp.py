"""FTP uploads are received over a real passive data channel and captured.

Driven with the standard library's ftplib, so the emulator is held to what an
ordinary client expects rather than to what its own code assumes.
"""

import asyncio
import base64
import ftplib
import hashlib
import io
import socket

import pytest

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.emulators import ftp as ftp_module
from honeypot.emulators.ftp import FTPHoneypot

PORT = 24510
PASV_RANGE = "24520-24529"
PAYLOAD = b"\x7fELF\x01\x02\x01" + bytes(range(256)) * 64


@pytest.fixture
async def ftp_honeypot(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "ftp_pasv_ports", PASV_RANGE)
    monkeypatch.setattr(config, "ftp_pasv_address", "127.0.0.1")
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)
    honeypot = FTPHoneypot()
    honeypot.port = PORT
    await honeypot.start()
    try:
        yield ingested
    finally:
        await honeypot.stop()


def _client():
    client = ftplib.FTP()
    client.connect("127.0.0.1", PORT, timeout=10)
    client.login("anonymous", "probe@example.com")
    return client


async def test_stor_captures_the_exact_bytes(ftp_honeypot):
    ingested = ftp_honeypot

    def session():
        client = _client()
        client.cwd("/incoming")
        client.storbinary("STOR bot.arm7", io.BytesIO(PAYLOAD))
        listing = []
        client.retrlines("LIST", listing.append)
        echoed = io.BytesIO()
        client.retrbinary("RETR bot.arm7", echoed.write)
        client.quit()
        return listing, echoed.getvalue()

    listing, echoed = await asyncio.to_thread(session)

    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    upload = payload["uploads"][0]
    assert upload["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert upload["remote_path"] == "/incoming/bot.arm7"
    assert upload["source"] == "ftp_stor"
    assert base64.b64decode(upload["content_b64"]) == PAYLOAD
    # The session stays self-consistent: the upload is listed and retrievable.
    assert any(line.endswith(" bot.arm7") and str(len(PAYLOAD)) in line for line in listing)
    assert echoed == PAYLOAD


async def test_active_mode_is_refused(ftp_honeypot):
    def session():
        client = _client()
        try:
            client.sendcmd("PORT 127,0,0,1,95,150")
        except ftplib.error_perm as exc:
            return str(exc)
        finally:
            client.close()

    assert (await asyncio.to_thread(session)).startswith("500")


async def test_transfer_without_pasv_is_refused(ftp_honeypot):
    def session():
        client = _client()
        client.sock.sendall(b"STOR x\r\n")
        reply = client.getline()
        client.close()
        return reply

    assert (await asyncio.to_thread(session)).startswith("425")


async def test_data_connection_from_another_address_is_rejected(ftp_honeypot, monkeypatch):
    monkeypatch.setattr(ftp_module, "DATA_CONNECT_TIMEOUT", 1)

    def session():
        client = _client()
        reply = client.sendcmd("EPSV")
        port = int(reply.split("|||")[1].split("|")[0])
        # Linux routes all of 127/8 to loopback, so a second source address
        # is available without any network setup.
        thief = socket.socket()
        thief.bind(("127.0.0.2", 0))
        thief.connect(("127.0.0.1", port))
        thief.settimeout(2)
        stolen = thief.recv(1)  # b"" once the server closes it
        thief.close()
        client.sock.sendall(b"STOR stolen\r\n")
        first = client.getline()
        second = client.getline()
        client.close()
        return stolen, first, second

    stolen, first, second = await asyncio.to_thread(session)
    assert stolen == b""
    assert first.startswith("150")
    assert second.startswith("425")
