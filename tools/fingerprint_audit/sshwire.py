"""The unencrypted part of an SSH connection, parsed by hand.

Everything a server sends before NEWKEYS is in the clear: its identification
line and its KEXINIT. That is where "Bitter Harvest" tells a library's
transport from OpenSSH's, so it is read here straight off the wire, with no
SSH library in between to tidy it up (RFC 4253, sections 4.2, 6 and 7.1).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_DEBUG = 4
MSG_SERVICE_REQUEST = 5
MSG_SERVICE_ACCEPT = 6
MSG_EXT_INFO = 7
MSG_KEXINIT = 20
MSG_NEWKEYS = 21

MSG_NAMES = {
    MSG_DISCONNECT: "SSH_MSG_DISCONNECT",
    MSG_IGNORE: "SSH_MSG_IGNORE",
    MSG_UNIMPLEMENTED: "SSH_MSG_UNIMPLEMENTED",
    MSG_DEBUG: "SSH_MSG_DEBUG",
    MSG_SERVICE_REQUEST: "SSH_MSG_SERVICE_REQUEST",
    MSG_SERVICE_ACCEPT: "SSH_MSG_SERVICE_ACCEPT",
    MSG_EXT_INFO: "SSH_MSG_EXT_INFO",
    MSG_KEXINIT: "SSH_MSG_KEXINIT",
    MSG_NEWKEYS: "SSH_MSG_NEWKEYS",
}

#: Largest packet a compliant implementation must accept (RFC 4253, 6.1).
#: Anything claiming to be longer is treated as text, not as a packet.
MAX_PACKET_LENGTH = 35000

#: Cipher block size before any cipher is negotiated.
CLEAR_BLOCK_SIZE = 8

#: The ten name-lists of a KEXINIT, in wire order.
KEXINIT_LISTS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


class WireError(ValueError):
    """The bytes are not what the protocol says should be there."""


def message_name(number: int) -> str:
    return MSG_NAMES.get(number, f"message {number}")


# ------------------------------------------------------------ identification

def parse_identification(line: bytes) -> dict:
    """Split ``SSH-protoversion-softwareversion SP comments`` (RFC 4253, 4.2).

    ``line`` is the identification without its line ending.
    """
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WireError("identification is not ASCII") from exc
    if not text.startswith("SSH-"):
        raise WireError("identification does not start with SSH-")
    parts = text.split("-", 2)
    if len(parts) != 3 or not parts[1] or not parts[2]:
        raise WireError("identification lacks a protocol or software version")
    software, _, comments = parts[2].partition(" ")
    return {
        "protocol_version": parts[1],
        "software_version": software,
        "comments": comments or None,
    }


# ------------------------------------------------------------------- packets

@dataclass
class Packet:
    """One binary packet as it appears before encryption starts."""

    packet_length: int
    padding_length: int
    payload: bytes
    padding: bytes

    @property
    def message(self) -> int:
        return self.payload[0] if self.payload else -1

    @property
    def name(self) -> str:
        return message_name(self.message)

    @property
    def wire_length(self) -> int:
        return 4 + self.packet_length


def read_packet(data: bytes) -> Optional[tuple[Packet, bytes]]:
    """Take one packet off the front of ``data``.

    Returns the packet and the bytes after it, or None when ``data`` does
    not yet hold a whole packet. Raises WireError when the first bytes cannot
    be a packet header at all.
    """
    if len(data) < 5:
        return None
    packet_length, padding_length = struct.unpack(">IB", data[:5])
    if not 2 <= packet_length <= MAX_PACKET_LENGTH:
        raise WireError(f"implausible packet length {packet_length}")
    if padding_length + 1 > packet_length:
        raise WireError("padding longer than the packet")
    if len(data) < 4 + packet_length:
        return None
    payload_length = packet_length - padding_length - 1
    payload = data[5:5 + payload_length]
    padding = data[5 + payload_length:4 + packet_length]
    return Packet(packet_length, padding_length, payload, padding), data[4 + packet_length:]


def build_packet(payload: bytes) -> bytes:
    """Frame a payload the way an unencrypted sender must: padded with at
    least four bytes to a multiple of eight. Zero padding, so the probes are
    the same bytes on every run."""
    padding_length = minimum_padding(len(payload))
    packet_length = len(payload) + padding_length + 1
    return struct.pack(">IB", packet_length, padding_length) + payload + bytes(padding_length)


def minimum_padding(payload_length: int, block_size: int = CLEAR_BLOCK_SIZE) -> int:
    """The least padding RFC 4253 section 6 allows for this payload."""
    padding = block_size - ((payload_length + 5) % block_size)
    if padding < 4:
        padding += block_size
    return padding


def padding_behaviour(packet: Packet) -> dict:
    """How a sender padded a clear-text packet.

    Three things differ between implementations and none depends on what the
    packet says: whether the whole packet is a multiple of the block size,
    whether the padding is the minimum allowed, and whether the padding bytes
    are zeros or random.
    """
    return {
        "packet_is_multiple_of_8": packet.wire_length % CLEAR_BLOCK_SIZE == 0,
        "padding_is_minimum": packet.padding_length == minimum_padding(len(packet.payload)),
        "padding_bytes": "all-zero" if not any(packet.padding) else "non-zero",
    }


# ----------------------------------------------------------------- payloads

class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def take(self, count: int) -> bytes:
        if self._at + count > len(self._data):
            raise WireError("payload ends early")
        chunk = self._data[self._at:self._at + count]
        self._at += count
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def uint32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.uint32())

    def name_list(self) -> list[str]:
        raw = self.string()
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise WireError("name-list is not ASCII") from exc
        return text.split(",") if text else []

    def at_end(self) -> bool:
        return self._at == len(self._data)


@dataclass
class KexInit:
    cookie: bytes
    lists: dict[str, list[str]]
    first_kex_packet_follows: bool
    reserved: int


def parse_kexinit(payload: bytes) -> KexInit:
    """Decode an SSH_MSG_KEXINIT payload (RFC 4253, 7.1)."""
    reader = _Reader(payload)
    if reader.byte() != MSG_KEXINIT:
        raise WireError("not a KEXINIT payload")
    cookie = reader.take(16)
    lists = {name: reader.name_list() for name in KEXINIT_LISTS}
    follows = reader.byte() != 0
    reserved = reader.uint32()
    if not reader.at_end():
        raise WireError("bytes left over after KEXINIT")
    return KexInit(cookie, lists, follows, reserved)


def hassh_server(kexinit: KexInit) -> tuple[str, str]:
    """The hasshServer fingerprint and the string it is the MD5 of.

    Salesforce's HASSH joins the server-to-client halves of the proposal:
    key exchange, encryption, MAC and compression name-lists, each as sent,
    separated by semicolons.
    """
    lists = kexinit.lists
    source = ";".join(
        ",".join(lists[name])
        for name in (
            "kex_algorithms",
            "encryption_server_to_client",
            "mac_server_to_client",
            "compression_server_to_client",
        )
    )
    return hashlib.md5(source.encode("ascii")).hexdigest(), source


def parse_disconnect(payload: bytes) -> dict:
    """Reason code and text of an SSH_MSG_DISCONNECT (RFC 4253, 11.1)."""
    reader = _Reader(payload)
    if reader.byte() != MSG_DISCONNECT:
        raise WireError("not a DISCONNECT payload")
    code = reader.uint32()
    description = reader.string().decode("utf-8", "replace")
    return {"reason_code": code, "description": description}


# ------------------------------------------------- a server's clear-text stream

def describe_stream(data: bytes) -> list[dict]:
    """What a server sent, as a list of text lines and packets.

    A server answering a bad identification may reply in plain text
    (OpenSSH writes a one-line error) or with a binary packet, and which it
    does is the fingerprint. Bytes that can be read as a whole packet are;
    anything else is taken as text up to the end of its line.
    """
    items: list[dict] = []
    rest = data
    while rest:
        packet = None
        try:
            parsed = read_packet(rest)
        except WireError:
            parsed = None
        if parsed is not None:
            packet, rest = parsed
            items.append(_describe_packet(packet))
            continue
        end = rest.find(b"\n")
        line, rest = (rest, b"") if end < 0 else (rest[:end + 1], rest[end + 1:])
        items.append({"text": line.decode("latin-1")})
    return items


def _describe_packet(packet: Packet) -> dict:
    item: dict = {"packet": packet.name}
    try:
        if packet.message == MSG_DISCONNECT:
            item.update(parse_disconnect(packet.payload))
        elif packet.message == MSG_UNIMPLEMENTED:
            item["rejected_sequence_number"] = _Reader(packet.payload[1:]).uint32()
    except WireError:
        item["malformed"] = True
    return item


def blank_volatile(data: bytes) -> bytes:
    """The stream with what legitimately differs per connection zeroed.

    A KEXINIT carries a 16-byte random cookie, and padding may be random;
    left in, two captures of the same server would never score 1.0.
    """
    out = bytearray()
    rest = data
    while rest:
        try:
            parsed = read_packet(rest)
        except WireError:
            parsed = None
        if parsed is None:
            out += rest
            break
        packet, rest = parsed
        payload = packet.payload
        if packet.message == MSG_KEXINIT and len(payload) >= 17:
            payload = payload[:1] + bytes(16) + payload[17:]
        out += struct.pack(">IB", packet.packet_length, packet.padding_length)
        out += payload + bytes(len(packet.padding))
    return bytes(out)
