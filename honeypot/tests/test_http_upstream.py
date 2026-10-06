"""A real application behind the HTTP decoy (HONEYPOT_HTTP_UPSTREAM).

The upstream here is a small stand-in for a web shop: it echoes what it was
sent, sets a cookie, and can answer chunked. The card numbers are the public
test numbers payment processors publish.
"""

import asyncio
import json

import httpx
import pytest

from honeypot.capture.redact import redact_card_data
from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.emulators.http import HTTPHoneypot

DECOY_PORT = 24420
UPSTREAM_PORT = 24421
TEST_CARD = "4242 4242 4242 4242"


class TestRedaction:
    def test_card_number_keeps_last_four(self):
        assert redact_card_data(f"pay {TEST_CARD} now") == "pay [card ****4242] now"
        assert redact_card_data("4000-0000-0000-0002") == "[card ****0002]"
        assert redact_card_data('{"number":"4242424242424242"}') == '{"number":"[card ****4242]"}'

    def test_digits_that_fail_luhn_are_kept(self):
        assert redact_card_data("order 4242424242424241") == "order 4242424242424241"
        assert redact_card_data("phone 5550123456") == "phone 5550123456"

    def test_security_code_is_masked_in_json_and_forms(self):
        assert redact_card_data('{"cvc": "123", "exp": "12/29"}') == '{"cvc": "[redacted]", "exp": "12/29"}'
        assert redact_card_data("cvv=1234&name=x") == "cvv=[redacted]&name=x"
        assert redact_card_data("cvcount=3") == "cvcount=3"

    def test_empty(self):
        assert redact_card_data("") == ""


async def _upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Answer one request, the way an Express app behind a proxy would."""
    request_line = (await reader.readline()).decode()
    headers = {}
    while (line := await reader.readline()) not in (b"\r\n", b""):
        name, _, value = line.decode().partition(":")
        headers[name.strip().lower()] = value.strip()
    body = await reader.readexactly(int(headers.get("content-length", 0)))
    method, target, _ = request_line.split()

    if target == "/chunked":
        writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    else:
        echo = json.dumps({
            "method": method,
            "target": target,
            "body": body.decode(),
            "forwarded_for": headers.get("x-forwarded-for"),
            "connection": headers.get("connection"),
        }).encode()
        writer.write(
            b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
            b"Set-Cookie: sid=abc; HttpOnly\r\nConnection: close\r\n"
            + f"Content-Length: {len(echo)}\r\n\r\n".encode() + echo
        )
    await writer.drain()
    writer.close()


@pytest.fixture
async def shop(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "http_upstream", f"http://127.0.0.1:{UPSTREAM_PORT}")
    monkeypatch.setattr(config, "http_upstream_owns", "/login,/admin")
    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)
    upstream = await asyncio.start_server(_upstream, "127.0.0.1", UPSTREAM_PORT)
    honeypot = HTTPHoneypot(use_tls=False)
    honeypot.port = DECOY_PORT
    await honeypot.start()
    try:
        yield f"http://127.0.0.1:{DECOY_PORT}", ingested, upstream, tmp_path
    finally:
        await honeypot.stop()
        upstream.close()
        await upstream.wait_closed()


async def test_application_answers_and_cookies_pass_through(shop):
    base_url, _, _, _ = shop
    async with httpx.AsyncClient(base_url=base_url) as client:
        response = await client.patch("/api/cart/7?x=1", json={"quantity": 2})
    assert response.status_code == 201
    echo = response.json()
    assert echo["method"] == "PATCH"
    assert echo["target"] == "/api/cart/7?x=1"
    assert echo["body"] == '{"quantity":2}'
    assert echo["forwarded_for"] == "127.0.0.1"
    assert echo["connection"] == "close"
    assert response.headers["set-cookie"] == "sid=abc; HttpOnly"
    assert "server" in response.headers


async def test_one_session_records_every_request_on_a_kept_alive_connection(shop):
    base_url, ingested, _, _ = shop
    async with httpx.AsyncClient(base_url=base_url) as client:
        first = await client.get("/")
        second = await client.get("/api/products")
    assert first.headers["connection"] == "keep-alive"
    assert second.status_code == 201

    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert [c.split("  [ua:")[0] for c in payload["commands"]] == ["GET /", "GET /api/products"]
    assert ingested.empty()


async def test_card_data_reaches_the_shop_but_not_the_records(shop):
    base_url, ingested, _, tmp_path = shop
    order = {"card": {"number": TEST_CARD, "exp": "12/29", "cvc": "123"}}
    async with httpx.AsyncClient(base_url=base_url) as client:
        response = await client.post("/api/orders", json=order)
    assert TEST_CARD in response.json()["body"]

    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    recorded = json.dumps(payload)
    assert "4242424242424242" not in recorded.replace(" ", "")
    assert "****4242" in recorded
    assert '\\"cvc\\": \\"123\\"' not in recorded
    # The engine's own capture on disk holds every event, not just the ones
    # sent to the backend.
    captured = " ".join(f.read_text() for f in (tmp_path / "sessions").rglob("*") if f.is_file())
    assert captured, "expected the session to be written to disk"
    assert "4242424242424242" not in captured.replace(" ", "").replace("-", "")


async def test_json_login_is_recorded_as_credentials(shop):
    base_url, ingested, _, _ = shop
    async with httpx.AsyncClient(base_url=base_url) as client:
        await client.post("/api/auth/login", json={"email": "admin@example.test", "password": "hunter22"})
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    creds = payload["credentials"][0]
    assert creds["username"] == "admin@example.test"
    assert creds["password"] == "hunter22"


async def test_bait_paths_stay_with_the_decoy_unless_the_shop_owns_them(shop):
    base_url, _, _, _ = shop
    async with httpx.AsyncClient(base_url=base_url) as client:
        env = await client.get("/.env")
        wordpress = await client.get("/wp-login.php")
        login = await client.get("/login")
    assert "DB_PASS=" in env.text
    assert wordpress.status_code == 200 and "target" not in wordpress.text
    assert login.json()["target"] == "/login"


async def test_chunked_upstream_response_is_relayed_whole(shop):
    base_url, _, _, _ = shop
    async with httpx.AsyncClient(base_url=base_url) as client:
        response = await client.get("/chunked")
    assert response.text == "hello world"
    assert response.headers["content-length"] == "11"
    assert "transfer-encoding" not in response.headers


async def test_probe_in_a_forwarded_query_is_flagged(shop):
    base_url, ingested, _, _ = shop
    async with httpx.AsyncClient(base_url=base_url) as client:
        await client.get("/api/products", params={"q": "1' union select password from users--"})
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert "attack_detected" in [p["type"] for p in payload["packets"]]


async def test_upstream_down_gives_a_bad_gateway(shop):
    base_url, _, upstream, _ = shop
    upstream.close()
    await upstream.wait_closed()
    async with httpx.AsyncClient(base_url=base_url) as client:
        response = await client.get("/")
    assert response.status_code == 502
