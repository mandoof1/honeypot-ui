"""JA3 and JA4 from a ClientHello, and the HTTPS decoy recording them.

The ClientHello bytes are built here, field by field, from the worked
examples the two specifications publish, so the expected fingerprints are
the published ones and not this implementation's own output.
"""

import asyncio
import os
import re
import socket
import ssl
import struct

import pytest

from honeypot.capture import tls_fingerprint
from honeypot.core.config import config
from honeypot.core.identity import reset_identity
from honeypot.core.session import session_manager
from honeypot.emulators.http import HTTPHoneypot
from honeypot.security.refusals import refusal_log


def _u16_list(values) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">H", len(body)) + body


def _extension(kind: int, data: bytes = b"") -> bytes:
    return struct.pack(">HH", kind, len(data)) + data


def _client_hello(version: int, ciphers, extensions) -> bytes:
    """A TLS record holding a ClientHello; ``extensions`` None leaves the
    extensions block out altogether, as SSL 3 clients did."""
    body = struct.pack(">H", version) + bytes(32) + b"\x00" + _u16_list(ciphers) + b"\x01\x00"
    if extensions is not None:
        block = b"".join(extensions)
        body += struct.pack(">H", len(block)) + block
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


SERVER_NAME = _extension(0x0000, b"\x00\x0e\x00\x00\x0bexample.com")


def _ja4_example() -> bytes:
    """The ClientHello of the worked example in the FoxIO JA4 specification
    (technical details, "JA4: TLS client fingerprint"), with GREASE values
    added in every list the way the browser it was taken from sends them."""
    ciphers = [
        0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
    ]
    contents = {
        0x0000: SERVER_NAME[4:],
        0x0010: struct.pack(">H", 12) + b"\x02h2\x08http/1.1",
        0x000D: _u16_list([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
        0x002B: b"\x06" + struct.pack(">HHH", 0x7A7A, 0x0304, 0x0303),
        0x000A: _u16_list([0x2A2A, 29, 23, 24]),
        0x000B: b"\x01\x00",
    }
    order = [
        0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D,
        0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015,
    ]
    extensions = (
        [_extension(0x1A1A)]
        + [_extension(kind, contents.get(kind, b"")) for kind in order]
        + [_extension(0x3A3A, b"\x00")]
    )
    return _client_hello(0x0303, ciphers, extensions)


def test_ja3_matches_the_published_examples():
    # Both strings and their MD5s are the examples in the JA3 README
    # (salesforce/ja3). The digests were also recomputed with md5sum over
    # the strings, independently of this code.
    with_extensions = _client_hello(
        769, [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
        [SERVER_NAME, _extension(10, _u16_list([23, 24, 25])), _extension(11, b"\x01\x00")],
    )
    prints = tls_fingerprint.fingerprint(with_extensions)
    assert prints["ja3_string"] == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    assert prints["ja3"] == "ada70206e40642a3e4461f35503241d5"

    bare = _client_hello(769, [4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99], None)
    prints = tls_fingerprint.fingerprint(bare)
    assert prints["ja3_string"] == "769,4-5-10-9-100-98-3-6-19-18-99,,,"
    assert prints["ja3"] == "de350869b8c85de67a350c8d186f11e6"


def test_ja4_matches_the_specifications_worked_example():
    # Expected value from the specification's example: 15 ciphers and 16
    # extensions once GREASE is dropped, TLS 1.3 from supported_versions, SNI
    # present, first ALPN "h2". Its two hashes were recomputed with sha256sum
    # over the sorted lists the specification prints:
    #   002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
    #       -> 8daaf6152771
    #   0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01
    #   _0403,0804,0401,0503,0805,0501,0806,0601
    #       -> e5627efa2ab1
    prints = tls_fingerprint.fingerprint(_ja4_example())
    assert prints["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    # GREASE is gone from JA3 as well.
    assert prints["ja3_string"].startswith("771,4865-4866-4867-")
    assert ",27-0-51-16-17513-23-45-13-5-35-18-43-65281-11-10-21,29-23-24,0" in prints["ja3_string"]


def test_ja4_without_extensions_alpn_or_sni():
    prints = tls_fingerprint.fingerprint(_client_hello(0x0301, [0x002F, 0x0035], None))
    assert prints["ja4"].startswith("t10i020000_")
    assert prints["ja4"].endswith("_000000000000")

    odd_alpn = _client_hello(0x0303, [0x1301], [_extension(0x0010, b"\x00\x03\x02\xab\xcd")])
    assert tls_fingerprint.fingerprint(odd_alpn)["ja4"].startswith("t12i0101ad_")


def test_a_hello_split_across_records_is_stitched():
    record = _ja4_example()
    handshake = record[5:]
    split = (
        b"\x16\x03\x01" + struct.pack(">H", 100) + handshake[:100]
        + b"\x16\x03\x01" + struct.pack(">H", len(handshake) - 100) + handshake[100:]
    )
    assert tls_fingerprint.fingerprint(split)["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    # Only the first record there yet: no fingerprint, and no exception.
    assert tls_fingerprint.fingerprint(split[:105]) == {}


def test_malformed_input_is_no_fingerprint_never_an_error():
    hello = _ja4_example()
    assert tls_fingerprint.fingerprint(b"") == {}
    assert tls_fingerprint.fingerprint(b"GET / HTTP/1.1\r\n\r\n") == {}
    assert tls_fingerprint.record_length(b"GET /") is None
    assert tls_fingerprint.record_length(hello[:5]) == len(hello)
    for cut in range(len(hello)):
        assert tls_fingerprint.fingerprint(hello[:cut]) == {}
    for n in range(2000):
        garbage = bytearray(hello)
        garbage[5 + n % (len(hello) - 5)] ^= 0xFF
        tls_fingerprint.fingerprint(bytes(garbage))
        tls_fingerprint.fingerprint(os.urandom(n % 200))


# -- over the wire --------------------------------------------------------------

@pytest.fixture
async def https(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "http_upstream", "")
    monkeypatch.setattr(config, "http_decoy_upstream", "")
    monkeypatch.setenv("HONEYPOT_IDENTITY_SEED", "4")
    reset_identity()
    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)
    honeypot = HTTPHoneypot(use_tls=True)
    honeypot.port = 0
    await honeypot.start()
    try:
        yield honeypot._server.sockets[0].getsockname()[1], ingested
    finally:
        await honeypot.stop()
        reset_identity()


def _client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def test_the_https_decoy_records_the_clients_fingerprints(https):
    port, ingested = https
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=_client_context(), server_hostname="shop.example"
    )
    writer.write(b"GET /robots.txt HTTP/1.1\r\nHost: shop.example\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    # The handshake and the request are untouched by the look at the hello.
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")

    prints = (await asyncio.wait_for(ingested.get(), timeout=10))["fingerprints"]
    assert re.fullmatch(r"[0-9a-f]{32}", prints["ja3"])
    assert prints["ja3_string"].startswith("771,")
    # This client: TCP, TLS 1.3, a server name, no ALPN.
    assert re.fullmatch(r"t13d\d{4}00_[0-9a-f]{12}_[0-9a-f]{12}", prints["ja4"])
    assert prints["http_header_order"] == "host,accept,connection"


async def test_a_hello_arriving_in_pieces_is_still_fingerprinted_and_served(https):
    port, ingested = https
    # Capture what a client would send, then deliver it a few bytes at a
    # time through a plain socket, as a slow or deliberate client might.
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = _client_context().wrap_bio(incoming, outgoing, server_hostname="shop.example")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    async def pump():
        data = outgoing.read()
        for start in range(0, len(data), 50):
            writer.write(data[start:start + 50])
            await writer.drain()
            await asyncio.sleep(0.005)

    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            await pump()
            incoming.write(await asyncio.wait_for(reader.read(65536), timeout=10))
    await pump()
    tls.write(b"GET / HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n\r\n")
    await pump()
    answer = b""
    while b"\r\n\r\n" not in answer:
        incoming.write(await asyncio.wait_for(reader.read(65536), timeout=10))
        try:
            answer += tls.read(65536)
        except ssl.SSLWantReadError:
            pass
    writer.close()
    assert answer.startswith(b"HTTP/1.1 200 OK\r\n")
    prints = (await asyncio.wait_for(ingested.get(), timeout=10))["fingerprints"]
    assert prints["ja4"].startswith("t13d")


async def test_plain_http_on_the_https_port_gets_the_servers_own_answer(https):
    port, _ = https
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET / HTTP/1.1\r\nHost: shop.example\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert b"You're speaking plain HTTP to an SSL-enabled server port." in response
    assert ("127.0.0.1", "https", "plain_http_on_tls_port") in refusal_log._pending


async def test_a_handshake_that_fails_is_counted_and_breaks_nothing(https):
    port, ingested = https
    sock = socket.create_connection(("127.0.0.1", port))
    # A handshake record that is not a ClientHello.
    sock.sendall(b"\x16\x03\x01\x00\x05hello")
    sock.settimeout(5)
    try:
        while sock.recv(4096):
            pass
    except OSError:
        pass
    sock.close()
    for _ in range(50):
        if ("127.0.0.1", "https", "tls_handshake_failed") in refusal_log._pending:
            break
        await asyncio.sleep(0.05)
    assert ("127.0.0.1", "https", "tls_handshake_failed") in refusal_log._pending

    # The listener is still serving.
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=_client_context())
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    await writer.drain()
    assert (await asyncio.wait_for(reader.read(), timeout=10)).startswith(b"HTTP/1.1 200 OK")
    writer.close()
