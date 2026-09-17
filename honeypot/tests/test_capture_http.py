"""HTTP bodies are captured as bytes, not as mangled text.

Payload bytes are synthetic; the shapes — a webshell on an upload form, a
JSP PUT onto a servlet container, PHP smuggled in a form field — are the ones
web exploitation actually uses.
"""

import asyncio
import base64
import hashlib

import httpx
import pytest

from honeypot.capture.http_uploads import (
    extract_files,
    looks_like_payload,
    parse_multipart,
    safe_filename,
)
from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.emulators.http import HTTPHoneypot

BINARY = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 4  # not valid UTF-8


def _multipart(boundary, parts):
    body = b""
    for headers, data in parts:
        body += b"--" + boundary + b"\r\n" + headers + b"\r\n\r\n" + data + b"\r\n"
    return body + b"--" + boundary + b"--\r\n"


class TestMultipart:
    def test_file_part_is_extracted_byte_for_byte(self):
        body = _multipart(b"XyZ", [
            (b'Content-Disposition: form-data; name="note"', b"hello"),
            (b'Content-Disposition: form-data; name="file"; filename="x86"\r\n'
             b"Content-Type: application/octet-stream", BINARY),
        ])
        files = extract_files("POST", "/upload", {"content-type": 'multipart/form-data; boundary="XyZ"'}, body)
        assert len(files) == 1
        assert files[0].content == BINARY
        assert files[0].filename == "x86"
        assert files[0].source == "http_multipart"

    def test_rfc5987_filename(self):
        body = _multipart(b"b", [
            (b"Content-Disposition: form-data; name=f; filename*=UTF-8''shell%20one.php", b"<?php ?>"),
        ])
        files = extract_files("POST", "/", {"content-type": "multipart/form-data; boundary=b"}, body)
        assert files[0].filename == "shell one.php"

    def test_traversal_in_filename_is_only_a_label(self):
        assert safe_filename("../../../etc/cron.d/x", "f") == "x"
        assert safe_filename("..\\..\\windows\\evil.aspx", "f") == "evil.aspx"
        assert safe_filename("a\x00b\x1f.php", "f") == "ab.php"
        assert safe_filename("", "fallback") == "fallback"

    def test_payload_in_a_plain_field_is_captured(self):
        body = _multipart(b"B", [(b'Content-Disposition: form-data; name="code"', b"<?php system($_GET[1]); ?>")])
        files = extract_files("POST", "/", {"content-type": "multipart/form-data; boundary=B"}, body)
        assert files[0].source == "http_form_field"
        assert files[0].field == "code"

    def test_part_count_is_bounded(self):
        parts = [(b'Content-Disposition: form-data; name="f"; filename="a"', b"x")] * 500
        body = _multipart(b"B", parts)
        assert len(parse_multipart("multipart/form-data; boundary=B", body)) <= 32

    def test_missing_boundary_yields_nothing(self):
        assert parse_multipart("multipart/form-data", b"--x\r\n\r\ndata") == []


class TestOtherShapes:
    def test_put_body(self):
        files = extract_files("PUT", "/manager/cmd.jsp", {"content-type": "text/plain"}, b"<% Runtime.getRuntime(); %>")
        assert files[0].filename == "cmd.jsp"
        assert files[0].source == "http_put"

    def test_urlencoded_field_with_php(self):
        body = b"user=admin&payload=%3C%3Fphp+eval%28%24_POST%5Bx%5D%29%3B"
        files = extract_files("POST", "/index.php", {"content-type": "application/x-www-form-urlencoded"}, body)
        assert files[0].content.startswith(b"<?php")
        assert files[0].field == "payload"

    def test_ordinary_login_form_is_not_a_file(self):
        body = b"log=admin&pwd=password123"
        assert extract_files("POST", "/wp-login.php", {"content-type": "application/x-www-form-urlencoded"}, body) == []

    def test_json_api_body_is_not_a_file(self):
        assert extract_files("POST", "/api", {"content-type": "application/json"}, b'{"a": 1}') == []

    def test_octet_stream_post(self):
        files = extract_files("POST", "/cgi-bin/up", {"content-type": "application/octet-stream"}, BINARY)
        assert files[0].content == BINARY

    def test_base64_elf_is_recognised(self):
        assert looks_like_payload(base64.b64encode(b"\x7fELF\x01"))


PORT = 24410


@pytest.fixture
async def http_honeypot(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)
    honeypot = HTTPHoneypot(use_tls=False)
    honeypot.port = PORT
    await honeypot.start()
    try:
        yield f"http://127.0.0.1:{PORT}", ingested
    finally:
        await honeypot.stop()


async def test_binary_upload_arrives_intact_over_the_wire(http_honeypot):
    base_url, ingested = http_honeypot
    async with httpx.AsyncClient(base_url=base_url) as client:
        response = await client.post("/upload", files={"file": ("bot.x86", BINARY, "application/octet-stream")})
    assert response.status_code == 200

    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    upload = payload["uploads"][0]
    assert upload["sha256"] == hashlib.sha256(BINARY).hexdigest()
    assert upload["filename"] == "bot.x86"
    assert upload["source"] == "http_multipart"
    assert upload["remote_path"] == "/upload"
    assert base64.b64decode(upload["content_b64"]) == BINARY


async def test_put_is_captured_over_the_wire(http_honeypot):
    base_url, ingested = http_honeypot
    jsp = b'<%@ page import="java.io.*" %><% out.println("x"); %>'
    async with httpx.AsyncClient(base_url=base_url) as client:
        await client.put("/manager/shell.jsp", content=jsp)
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert base64.b64decode(payload["uploads"][0]["content_b64"]) == jsp
    assert payload["uploads"][0]["source"] == "http_put"
