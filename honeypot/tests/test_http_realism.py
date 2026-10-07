"""The HTTP decoy looks like the web server it claims to be.

GET / used to 404, X-Powered-By went out on every response including errors,
and the 404 footer leaked the container's internal port 8080. These drive the
decoy over a socket and read the raw response.
"""

import asyncio

import pytest

from honeypot.core.config import config
from honeypot.core.identity import reset_identity
from honeypot.emulators.http import HTTPHoneypot

PORT = 24810


@pytest.fixture(autouse=True)
def _capture_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "cap"))
    monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
    reset_identity()
    yield
    reset_identity()


@pytest.fixture
async def http_port():
    honeypot = HTTPHoneypot()
    honeypot.port = PORT
    await honeypot.start()
    try:
        yield PORT
    finally:
        await honeypot.stop()


async def _get(port, path):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    return raw.decode("utf-8", errors="replace")


async def test_root_is_a_real_landing_page_not_a_404(http_port):
    resp = await _get(http_port, "/")
    assert resp.startswith("HTTP/1.1 200")
    assert ("It works" in resp) or ("Welcome to nginx" in resp)


async def test_404_carries_no_x_powered_by(http_port):
    resp = await _get(http_port, "/this/does/not/exist")
    assert resp.startswith("HTTP/1.1 404")
    head = resp.split("\r\n\r\n", 1)[0].lower()
    assert "x-powered-by" not in head


async def test_404_does_not_leak_the_internal_port(http_port):
    resp = await _get(http_port, "/nope")
    # The container listens on 8080/8443; the page must show 80/443 or nothing.
    assert "Port 8080" not in resp
    assert "Port 8443" not in resp


async def test_trailing_slash_resolves_like_the_bare_path(http_port):
    bare = await _get(http_port, "/admin")
    slashed = await _get(http_port, "/admin/")
    assert bare.startswith("HTTP/1.1 200")
    assert slashed.startswith("HTTP/1.1 200")


async def test_server_header_is_stable_across_requests(http_port):
    def server(resp):
        for line in resp.split("\r\n"):
            if line.lower().startswith("server:"):
                return line
        return ""
    first = server(await _get(http_port, "/"))
    second = server(await _get(http_port, "/nope"))
    assert first and first == second
