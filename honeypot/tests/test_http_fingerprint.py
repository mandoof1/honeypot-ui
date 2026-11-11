"""The HTTP decoy answers the way Apache 2.4.41 and nginx 1.18.0 answered.

Every expected status line, header list and body here is copied from the
reference side of docs/evaluation/fingerprint/1-baseline/http-apache-focal.json
and http-nginx-focal.json, the first probe-by-probe comparison of the decoy
with the real servers; each test sends the request the named probe sent
(tools/fingerprint_audit/http_probes.py). The check id is in each test's
docstring. The identity seeds are the ones that comparison used: 8 claims
Apache/2.4.41 (Ubuntu), 75 nginx/1.18.0 (Ubuntu).
"""

import asyncio

import pytest

from honeypot.core.config import config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.session import session_manager
from honeypot.emulators.http import HTTPHoneypot

APACHE, NGINX = 8, 75

#: The headers every probe request carries (http_probes.py).
PROBE_HEADERS = b"Host: localhost\r\nUser-Agent: fingerprint-audit\r\nAccept: */*\r\n"


@pytest.fixture
async def decoy(tmp_path, monkeypatch):
    """``await decoy(seed)`` starts the decoy with that identity; its port."""
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "http_upstream", "")
    monkeypatch.setattr(config, "http_decoy_upstream", "")

    async def discard(session):
        return None

    monkeypatch.setattr(session_manager, "_send_to_backend", discard)
    running = []

    async def start(seed):
        monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / f"sessions-{seed}"))
        monkeypatch.setenv("HONEYPOT_IDENTITY_SEED", str(seed))
        reset_identity()
        honeypot = HTTPHoneypot(use_tls=False)
        honeypot.port = 0
        await honeypot.start()
        running.append(honeypot)
        return honeypot._server.sockets[0].getsockname()[1]

    yield start
    for honeypot in running:
        await honeypot.stop()
    reset_identity()


async def _until_close(port: int, data: bytes) -> bytes:
    """Send bytes and read everything until the server closes."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    try:
        return await asyncio.wait_for(reader.read(), timeout=5)
    finally:
        writer.close()


async def _one_response(port: int, data: bytes) -> tuple[str, list[str], dict[str, str], bytes]:
    """Send a request on a connection the server keeps open and read one
    response: (status line, header names in order, values by lower-case
    name, body)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        lines = head.decode("latin-1").rstrip("\r\n").split("\r\n")
        pairs = [line.partition(":") for line in lines[1:]]
        values = {name.lower(): value.strip() for name, _, value in pairs}
        body = await asyncio.wait_for(
            reader.readexactly(int(values.get("content-length", "0"))), timeout=5
        )
        return lines[0], [name for name, _, _ in pairs], values, body
    finally:
        writer.close()


async def _page(port: int) -> bytes:
    """The body of an ordinary GET /."""
    _status, _names, _values, body = await _one_response(port, b"GET / HTTP/1.1\r\n" + PROBE_HEADERS + b"\r\n")
    return body


class TestPostToTheRootPage:
    async def test_apache_serves_the_page(self, decoy):
        """http.post_root.status_line, .header_names and .header_values —
        reference: "HTTP/1.1 200 OK" and the headers of a GET. The decoy
        answered "405 Method Not Allowed" with an Allow header."""
        port = await decoy(APACHE)
        assert get_identity().http_family == "apache"
        request = b"POST / HTTP/1.1\r\n" + PROBE_HEADERS + b"Content-Length: 0\r\n\r\n"
        status, names, values, body = await _one_response(port, request)
        assert status == "HTTP/1.1 200 OK"
        assert names == [
            "Date", "Server", "Last-Modified", "ETag", "Accept-Ranges",
            "Content-Length", "Vary", "Content-Type",
        ]
        assert values["server"] == "Apache/2.4.41 (Ubuntu)"
        assert values["accept-ranges"] == "bytes"
        assert values["vary"] == "Accept-Encoding"
        assert values["content-type"] == "text/html"
        assert "allow" not in values
        # The same document a GET gets (in the reference, both are 10918 bytes).
        assert body == await _page(port)

    async def test_nginx_still_refuses_it(self, decoy):
        """http.post_root.* for nginx matched before and must go on
        matching: nginx does not serve a static page for POST."""
        port = await decoy(NGINX)
        assert get_identity().http_family == "nginx"
        request = b"POST / HTTP/1.1\r\n" + PROBE_HEADERS + b"Content-Length: 0\r\n\r\n"
        status, _names, values, _body = await _one_response(port, request)
        assert status == "HTTP/1.1 405 Not Allowed"
        assert values["server"] == "nginx/1.18.0 (Ubuntu)"


class TestUnknownMethod:
    async def test_apache_s_501_page_is_apache_s_to_the_byte(self, decoy):
        """http.unknown_method.body and the Content-Length in
        .header_values — reference: 282 bytes, with two spaces after the
        method. The decoy's had one, and 281."""
        port = await decoy(APACHE)
        response = await _until_close(port, b"FPAUDIT / HTTP/1.1\r\n" + PROBE_HEADERS + b"\r\n")
        head, _, body = response.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 501 Not Implemented\r\n")
        assert b"\r\nContent-Length: 282\r\n" in head
        assert body == (
            b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
            b"<html><head>\n"
            b"<title>501 Not Implemented</title>\n"
            b"</head><body>\n"
            b"<h1>Not Implemented</h1>\n"
            b"<p>FPAUDIT  not supported for current URL.<br />\n"
            b"</p>\n"
            b"<hr>\n"
            b"<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>\n"
            b"</body></html>\n"
        )


class TestHttp09:
    @pytest.mark.parametrize("seed", [APACHE, NGINX])
    async def test_a_request_with_no_version_gets_the_document_alone(self, decoy, seed):
        """http.http09_request.status_line, .header_names, .server and
        .header_values, for both servers — reference: no status line
        (null), no headers ([]), the response beginning with the page
        itself, then closed. The decoy sent a full "HTTP/1.1 200 OK"
        response."""
        port = await decoy(seed)
        page = await _page(port)
        response = await _until_close(port, b"GET /\r\n\r\n")
        assert response == page
        assert not response.startswith(b"HTTP/")

    async def test_nginx_s_document_is_its_welcome_page(self, decoy):
        """http.http09_request.body for nginx — the reference's response
        begins "<!DOCTYPE html>\\n<html>\\n<head>\\n<title>Welcome to
        nginx!</title>"; 612 bytes, as its GET."""
        port = await decoy(NGINX)
        response = await _until_close(port, b"GET /\r\n\r\n")
        assert response.startswith(b"<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>")
        assert len(response) == 612

    async def test_the_request_line_alone_is_the_request(self, decoy):
        """HTTP/0.9 has no headers, so a client that sends only the line
        must be answered without being made to wait for a blank one."""
        port = await decoy(APACHE)
        page = await _page(port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"GET /\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=3)
        finally:
            writer.close()
        assert response == page
