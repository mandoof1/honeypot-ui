"""What the SSH transport does before encryption, matched to OpenSSH 8.2p1.

``ssh_profile.py`` makes the KEXINIT proposal the one the banner's release
sends. The proposal is not the only thing a scanner reads before it has
authenticated. The first probe-by-probe comparison with a real sshd
(docs/evaluation/fingerprint/1-baseline/ssh-sshd-focal.json) found five more
places where asyncssh answered as asyncssh:

* packets sent before encryption starts were padded with random bytes, where
  sshd pads them with zeros;
* a malformed client identification closed the connection silently, where
  sshd says what was wrong in plain text first, and an identification longer
  than RFC 4253's 255 bytes was refused, where sshd accepts it;
* a packet length no packet can have left the connection open, waiting for
  four gigabytes that would never come, where sshd drops it at once;
* an unassigned message number was refused with asyncssh's wording and an
  ``en-US`` language tag, where sshd has its own wording and no tag.

Each is one probe and one reply, which is how honeypots are found at internet
scale. None has a public option in asyncssh, so each is a wrapper around one
private method of its server connection. The wrappers are applied to
``SSHServerConnection`` only, so asyncssh used as a client in the same process
is untouched, and every one is guarded: when a later asyncssh release has
renamed what a wrapper needs, that wrapper is left out with a warning and the
decoy starts without it.

The expected bytes quoted below are the reference's, from that file.
"""

from __future__ import annotations

import logging
import re
from typing import NamedTuple, Optional

logger = logging.getLogger(__name__)

#: Longest client identification sshd reads, in bytes without the line
#: ending (SSH_MAX_BANNER_LEN in OpenSSH's kex.c). The reference accepted an
#: identification of 300 bytes and answered with its KEXINIT, and refused
#: one of 9010.
MAX_IDENT_LINE = 8192

#: What sshd writes, in plain text, before closing on an identification it
#: cannot use.
INVALID_IDENT = b"Invalid SSH identification string."
MAJOR_VERSIONS_DIFFER = b"Protocol major versions differ."

#: The smallest and largest packet length sshd accepts (packet.c: one byte of
#: padding length and four of padding at least, PACKET_MAX_SIZE at most).
MIN_PACKET_LENGTH = 5
MAX_PACKET_LENGTH = 256 * 1024

#: Message numbers from here up are reserved for local extensions; sshd
#: disconnects on them, and on zero, rather than answering UNIMPLEMENTED.
FIRST_LOCAL_MESSAGE = 192

#: Marks a wrapper, so applying the hooks twice does not wrap twice.
_WRAPPED = "_honeypot_wrapped"
_MISSING = object()

_IDENT = re.compile(rb"SSH-(\d+)\.(\d+)-(.+)", re.DOTALL)


class IdentVerdict(NamedTuple):
    """What sshd makes of the first line a client sends."""

    #: Text to send before closing, or None when the line is acceptable.
    refusal: Optional[bytes]
    #: How much of the input sshd had read when it decided.
    consumed: int


def judge_client_identification(buffer: bytes) -> Optional[IdentVerdict]:
    """The verdict on a client identification; None while it is incomplete.

    The rules are the ones the five reference probes show, which are also
    the ones in ``kex_exchange_identification``: the line must read
    ``SSH-<major>.<minor>-<software>``, the major version must be 2 (1.99
    counts as 2), and the line may be up to 8192 bytes long.
    """
    # A line of the longest permitted length, its CR, and the LF itself.
    window = MAX_IDENT_LINE + 2
    newline = buffer.find(b"\n", 0, window)
    if newline < 0:
        if len(buffer) < window:
            return None
        # sshd reads a byte at a time and stops at the first one too many.
        return IdentVerdict(INVALID_IDENT, MAX_IDENT_LINE + 1)

    line = buffer[:newline]
    if line.endswith(b"\r"):
        line = line[:-1]
    if len(line) > MAX_IDENT_LINE:
        return IdentVerdict(INVALID_IDENT, MAX_IDENT_LINE + 1)

    consumed = newline + 1
    found = _IDENT.fullmatch(line)
    if found is None:
        return IdentVerdict(INVALID_IDENT, consumed)
    major, minor = int(found.group(1)), int(found.group(2))
    if major == 2 or (major, minor) == (1, 99):
        return IdentVerdict(None, consumed)
    return IdentVerdict(MAJOR_VERSIONS_DIFFER, consumed)


def zero_cleartext_padding(data: bytes) -> bytes:
    """One unencrypted binary packet with its padding bytes set to zero.

    Anything that is not exactly one well-formed packet — the identification
    line, for one — is returned as it came.
    """
    if len(data) < MIN_PACKET_LENGTH + 4:
        return data
    if int.from_bytes(data[:4], "big") != len(data) - 4:
        return data
    padding = data[4]
    if padding < 4 or padding > len(data) - 5:
        return data
    return data[:-padding] + bytes(padding)


def _in_cleartext(conn, attribute: str) -> bool:
    """True only when asyncssh says that direction is not encrypted yet.

    A missing attribute counts as "unknown", never as "not encrypted":
    rewriting the padding of an encrypted packet would break its MAC.
    """
    return getattr(conn, attribute, _MISSING) is None


def _cleartext_message_type(conn) -> Optional[int]:
    """The message number of the unencrypted packet asyncssh is about to
    process, once all of it has arrived; None when that cannot be told."""
    if not _in_cleartext(conn, "_recv_encryption"):
        return None
    header = getattr(conn, "_packet", None)
    length = getattr(conn, "_pktlen", None)
    pending = getattr(conn, "_inpbuf", None)
    if not isinstance(header, bytes) or not isinstance(length, int) or pending is None:
        return None
    # The first block is already in the header; there is no MAC yet.
    remaining = 4 + length - len(header)
    if remaining < 0 or len(pending) < remaining:
        return None
    packet = header + bytes(pending[:remaining])
    padding = packet[4]
    payload = packet[5:len(packet) - padding]
    return payload[0] if payload else None


def _wrap(cls, name: str, build) -> bool:
    """Replace ``cls.name`` with ``build(original)``, once."""
    original = getattr(cls, name, None)
    if original is None:
        return False
    if getattr(original, _WRAPPED, False):
        return True
    wrapper = build(original)
    setattr(wrapper, _WRAPPED, True)
    setattr(cls, name, wrapper)
    return True


def _zero_padding_before_encryption(server_connection) -> bool:
    """sshd fills the padding with zeros until a cipher is in use (packet.c
    clears it when the send context is plaintext). Reference KEXINIT:
    ``"padding": "00000000000000000000"``; asyncssh sent ``os.urandom``."""

    def build(original):
        def _send(self, data):
            if _in_cleartext(self, "_send_encryption"):
                data = zero_cleartext_padding(bytes(data))
            original(self, data)

        return _send

    return _wrap(server_connection, "_send", build)


def _answer_identification_like_sshd(server_connection, connection_module) -> bool:
    """Refuse a bad client identification in sshd's words, and accept a long
    one.

    Reference replies: ``SSH-2.0`` alone and an HTTP request both get
    ``Invalid SSH identification string.``; ``SSH-1.5-...`` gets
    ``Protocol major versions differ.``; then the connection closes. sshd
    sends the text and its CR LF as two writes. When it closes with client
    input still unread — the rest of a 9010-byte line, the headers of the
    HTTP request — the connection is reset before the second write leaves,
    and the reference's reply ends without the line ending. When it had read
    everything, the CR LF arrives. Both forms are in the evidence, so both
    are reproduced.
    """
    import asyncssh

    needed = ("_recv_version", "_send", "_force_close")
    if not all(hasattr(server_connection, name) for name in needed):
        return False

    # asyncssh refuses an identification over 255 bytes; the reference took
    # one of 300 and carried on. Its own limits are module constants.
    limits = (("_MAX_VERSION_LINE_LEN", MAX_IDENT_LINE), ("_MAX_BANNER_LINE_LEN", MAX_IDENT_LINE + 2))
    for constant, value in limits:
        current = getattr(connection_module, constant, None)
        if not isinstance(current, int):
            logger.warning(
                "asyncssh no longer defines %s; a client identification over "
                "255 bytes will be refused, which sshd does not do", constant,
            )
        elif current < value:
            setattr(connection_module, constant, value)

    def build(original):
        def _recv_version(self):
            pending = getattr(self, "_inpbuf", None)
            if pending is None:
                return original(self)
            verdict = judge_client_identification(bytes(pending))
            if verdict is None:
                return False
            if verdict.refusal is None:
                # Accepting is asyncssh's own business.
                return original(self)
            everything_read = len(pending) <= verdict.consumed
            text = verdict.refusal + (b"\r\n" if everything_read else b"")
            self._send(text)
            self._force_close(asyncssh.ProtocolNotSupported(verdict.refusal.decode("ascii")))
            return False

        return _recv_version

    return _wrap(server_connection, "_recv_version", build)


def _drop_impossible_packet_lengths(server_connection) -> bool:
    """Close on a packet length no packet can have, as sshd does.

    Reference, for 64 bytes of 0xff in place of the first packet (a length
    of 4294967295): nothing sent, connection closed. asyncssh kept the
    connection open and went on buffering until that many bytes arrived.
    """
    import asyncssh

    if not hasattr(server_connection, "_force_close"):
        return False

    def build(original):
        def _recv_pkthdr(self):
            proceed = original(self)
            if not proceed or not _in_cleartext(self, "_recv_encryption"):
                return proceed
            length = getattr(self, "_pktlen", None)
            if not isinstance(length, int) or MIN_PACKET_LENGTH <= length <= MAX_PACKET_LENGTH:
                return proceed
            self._force_close(asyncssh.ProtocolError(f"Bad packet length {length}."))
            return False

        return _recv_pkthdr

    return _wrap(server_connection, "_recv_pkthdr", build)


def _disconnect_on_invalid_message_numbers(server_connection) -> bool:
    """Refuse a message number outside the protocol's range in sshd's words.

    Reference, for message 192 before any KEXINIT: SSH_MSG_DISCONNECT, reason
    2, ``Invalid ssh2 packet type: 192``. asyncssh sent reason 2 with
    ``Invalid request before key exchange was complete``. Only packets that
    arrive unencrypted are looked at, which is all the evidence covers.
    """
    import asyncssh

    def build(original):
        def _recv_packet(self):
            message = _cleartext_message_type(self)
            if message is not None and (message == 0 or message >= FIRST_LOCAL_MESSAGE):
                raise asyncssh.DisconnectError(
                    asyncssh.DISC_PROTOCOL_ERROR, f"Invalid ssh2 packet type: {message}", ""
                )
            return original(self)

        return _recv_packet

    return _wrap(server_connection, "_recv_packet", build)


def _disconnect_without_language_tag(server_connection) -> bool:
    """sshd's disconnect messages carry an empty language tag; asyncssh's say
    ``en-US``. Reference disconnect, after the description: ``00 00 00 00``."""

    def build(original):
        def _send_disconnect(self, code, reason, lang):
            original(self, code, reason, "")

        return _send_disconnect

    return _wrap(server_connection, "_send_disconnect", build)


def apply_transport_behaviour() -> dict[str, bool]:
    """Make asyncssh's server side answer pre-encryption probes as sshd does.

    Returns which of the hooks are in place, by name. One that could not be
    applied is logged and skipped; the others, and the decoy, carry on.
    """
    from asyncssh import connection as connection_module
    from asyncssh.connection import SSHServerConnection

    hooks = {
        "zero_padding": lambda: _zero_padding_before_encryption(SSHServerConnection),
        "identification": lambda: _answer_identification_like_sshd(SSHServerConnection, connection_module),
        "packet_length": lambda: _drop_impossible_packet_lengths(SSHServerConnection),
        "message_number": lambda: _disconnect_on_invalid_message_numbers(SSHServerConnection),
        "disconnect_language": lambda: _disconnect_without_language_tag(SSHServerConnection),
    }
    applied: dict[str, bool] = {}
    for name, apply in hooks.items():
        try:
            applied[name] = bool(apply())
        except Exception as exc:  # pragma: no cover - a release we have not seen
            logger.warning("SSH transport hook %s failed to apply: %s", name, exc)
            applied[name] = False
        if not applied[name]:
            logger.warning(
                "asyncssh no longer has what the SSH transport hook %r wraps; "
                "the decoy will answer that probe as asyncssh, not as sshd", name,
            )
    return applied
