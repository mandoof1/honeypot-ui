"""TLS client fingerprints: JA3 and JA4, from the ClientHello.

A TLS client announces itself before any HTTP is spoken: the cipher suites,
extensions and curves it offers, and the order it offers them in, are fixed
by the library it was built on. curl, a Go scanner, Python and a browser all
differ, and none of them can change it by setting a User-Agent header. The
HTTPS decoy saw none of this, because the handshake was finished by the time
a request reached it.

Two fingerprints are computed from the same ClientHello:

* JA3 — the MD5 of ``version,ciphers,extensions,curves,point_formats``, each
  a dash-joined list of decimal values in the order sent, with GREASE values
  removed. Old, lossy, and what every threat feed still indexes by.
* JA4 — the TLS client fingerprint of the FoxIO JA4 specification (only JA4
  itself, none of the other JA4+ variants): a readable prefix (protocol, TLS
  version, SNI, counts, ALPN) and two truncated SHA-256 hashes over the
  *sorted* ciphers and extensions, so a client that shuffles its extension
  order, as current browsers do, still gets one fingerprint.

Everything parsed here was sent by an unauthenticated client. The parser
reads through a bounds-checked cursor, never trusts a length field beyond the
bytes it was given, and ``fingerprint`` turns any malformed input into "no
fingerprint" rather than an exception: a fingerprint is never worth a
connection.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

#: A TLS record starts with type (1), version (2) and length (2).
RECORD_HEADER_BYTES = 5
#: Largest plaintext record TLS allows (RFC 8446, 5.1).
MAX_RECORD_PAYLOAD = 16384

_HANDSHAKE_RECORD = 22
_CLIENT_HELLO = 1

_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_VERSIONS = 0x002B

#: JA4's two-character names for a protocol version.
_JA4_VERSIONS = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}


@dataclass
class ClientHello:
    #: The legacy version field, which TLS 1.3 clients leave at 1.2.
    version: int
    ciphers: list[int] = field(default_factory=list)
    #: Extension types in the order sent, GREASE included.
    extensions: list[int] = field(default_factory=list)
    curves: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    alpn: list[bytes] = field(default_factory=list)


class _Cursor:
    """Read fixed-size fields from a buffer, refusing to run off its end."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._at

    def take(self, count: int) -> bytes:
        if count < 0 or count > self.remaining:
            raise ValueError("truncated ClientHello")
        chunk = self._data[self._at:self._at + count]
        self._at += count
        return chunk

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, length_size: int) -> "_Cursor":
        """A length-prefixed field, as its own cursor."""
        return _Cursor(self.take(self.uint(length_size)))


def is_grease(value: int) -> bool:
    """GREASE values (RFC 8701): 0x0a0a, 0x1a1a ... 0xfafa.

    Clients insert them at random to keep servers tolerant of unknown values,
    so they say nothing about the client and both fingerprints drop them.
    """
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def record_length(prefix: bytes) -> Optional[int]:
    """Bytes the first record occupies, if these bytes begin a TLS handshake.

    Takes at least the five header bytes. None means this is not TLS at all
    (plain HTTP sent to the HTTPS port, a port scanner's probe), so there is
    nothing to wait for.
    """
    if len(prefix) < RECORD_HEADER_BYTES:
        return None
    if prefix[0] != _HANDSHAKE_RECORD or prefix[1] != 3:
        return None
    length = int.from_bytes(prefix[3:5], "big")
    if length == 0 or length > MAX_RECORD_PAYLOAD:
        return None
    return RECORD_HEADER_BYTES + length


def _handshake_bytes(data: bytes) -> bytes:
    """The handshake stream carried by the leading handshake records.

    A ClientHello may be split across records; whatever follows in the same
    bytes is stitched on. Records that are not there yet simply leave the
    message short, which the parser then refuses.
    """
    stream = bytearray()
    cursor = _Cursor(data)
    while cursor.remaining >= RECORD_HEADER_BYTES:
        record_type = cursor.uint(1)
        cursor.take(2)
        length = cursor.uint(2)
        if record_type != _HANDSHAKE_RECORD or length > MAX_RECORD_PAYLOAD:
            break
        stream += cursor.take(min(length, cursor.remaining))
    return bytes(stream)


def _uint16_list(cursor: _Cursor) -> list[int]:
    values = []
    while cursor.remaining >= 2:
        values.append(cursor.uint(2))
    return values


def parse_client_hello(data: bytes) -> Optional[ClientHello]:
    """Parse the ClientHello at the start of ``data`` (record header first).

    Returns None for anything that is not a complete, well-formed ClientHello.
    """
    try:
        return _parse(data)
    except (ValueError, IndexError):
        return None


def _parse(data: bytes) -> Optional[ClientHello]:
    if record_length(data) is None:
        return None
    handshake = _Cursor(_handshake_bytes(data))
    if handshake.uint(1) != _CLIENT_HELLO:
        return None
    body = handshake.vector(3)

    hello = ClientHello(version=body.uint(2))
    body.take(32)        # random
    body.vector(1)       # legacy session id
    hello.ciphers = _uint16_list(body.vector(2))
    body.vector(1)       # compression methods
    if body.remaining == 0:
        # SSL 3 and bare TLS 1.0 hellos end here, with no extensions.
        return hello

    extensions = body.vector(2)
    while extensions.remaining >= 4:
        ext_type = extensions.uint(2)
        ext = extensions.vector(2)
        hello.extensions.append(ext_type)
        if ext_type == _EXT_SUPPORTED_GROUPS:
            hello.curves = _uint16_list(ext.vector(2))
        elif ext_type == _EXT_EC_POINT_FORMATS:
            formats = ext.vector(1)
            hello.point_formats = list(formats.take(formats.remaining))
        elif ext_type == _EXT_SIGNATURE_ALGORITHMS:
            hello.signature_algorithms = _uint16_list(ext.vector(2))
        elif ext_type == _EXT_SUPPORTED_VERSIONS:
            hello.supported_versions = _uint16_list(ext.vector(1))
        elif ext_type == _EXT_ALPN:
            protocols = ext.vector(2)
            while protocols.remaining:
                name = protocols.vector(1)
                hello.alpn.append(name.take(name.remaining))
    return hello


def ja3_string(hello: ClientHello) -> str:
    """``version,ciphers,extensions,curves,point_formats`` with GREASE removed."""

    def joined(values: list[int]) -> str:
        return "-".join(str(v) for v in values if not is_grease(v))

    return ",".join([
        str(hello.version),
        joined(hello.ciphers),
        joined(hello.extensions),
        joined(hello.curves),
        "-".join(str(v) for v in hello.point_formats),
    ])


def ja3(hello: ClientHello) -> str:
    return hashlib.md5(ja3_string(hello).encode("ascii")).hexdigest()


def _hex_list(values: list[int]) -> str:
    return ",".join(f"{v:04x}" for v in values)


def _truncated_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def _is_ascii_alnum(byte: int) -> bool:
    return 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


def _ja4_alpn(hello: ClientHello) -> str:
    """First and last character of the first ALPN protocol; "00" for none."""
    if not hello.alpn or not hello.alpn[0]:
        return "00"
    first = hello.alpn[0]
    if _is_ascii_alnum(first[0]) and _is_ascii_alnum(first[-1]):
        return chr(first[0]) + chr(first[-1])
    # Not printable: the specification falls back to the hex of the value.
    as_hex = first.hex()
    return as_hex[0] + as_hex[-1]


def ja4(hello: ClientHello, transport: str = "t") -> str:
    """The JA4 TLS client fingerprint, ``a_b_c``.

    ``a`` is readable: transport (t for TCP), TLS version, whether a server
    name was sent (d) or not (i), the cipher and extension counts, and the
    ALPN marker. ``b`` hashes the sorted cipher list. ``c`` hashes the sorted
    extension list without SNI and ALPN, followed by the signature algorithms
    in the order sent.
    """
    ciphers = [c for c in hello.ciphers if not is_grease(c)]
    extensions = [e for e in hello.extensions if not is_grease(e)]
    versions = [v for v in hello.supported_versions if not is_grease(v)]
    signature_algorithms = [s for s in hello.signature_algorithms if not is_grease(s)]

    # supported_versions is where a TLS 1.3 client says so; without it the
    # legacy field is the version.
    version = max(versions) if versions else hello.version
    part_a = "".join([
        transport,
        _JA4_VERSIONS.get(version, "00"),
        "d" if _EXT_SERVER_NAME in extensions else "i",
        f"{min(len(ciphers), 99):02d}",
        f"{min(len(extensions), 99):02d}",
        _ja4_alpn(hello),
    ])

    part_b = _truncated_sha256(_hex_list(sorted(ciphers))) if ciphers else "0" * 12

    hashed_extensions = sorted(
        e for e in extensions if e not in (_EXT_SERVER_NAME, _EXT_ALPN)
    )
    if not hashed_extensions:
        part_c = "0" * 12
    else:
        text = _hex_list(hashed_extensions)
        if signature_algorithms:
            text += "_" + _hex_list(signature_algorithms)
        part_c = _truncated_sha256(text)

    return f"{part_a}_{part_b}_{part_c}"


def fingerprint(data: bytes) -> dict[str, str]:
    """``{"ja3", "ja3_string", "ja4"}`` for the ClientHello in ``data``.

    An empty dict when there is no complete ClientHello to read. Never raises.
    """
    try:
        hello = parse_client_hello(data)
        if hello is None:
            return {}
        return {
            "ja3": ja3(hello),
            "ja3_string": ja3_string(hello),
            "ja4": ja4(hello),
        }
    except Exception:
        return {}
