"""The SSH decoy answers pre-authentication probes the way OpenSSH 8.2p1 did.

Every expected value here is copied from the reference side of
docs/evaluation/fingerprint/1-baseline/ssh-sshd-focal.json — the first
probe-by-probe comparison of the decoy with a real sshd (openssh-server
1:8.2p1-4ubuntu0.9) — and each test sends what the named probe sent
(tools/fingerprint_audit/ssh_probes.py and ssh_auth.py). The check id is in
each test's docstring.

They read the socket, not the configuration: what matters is what a scanner
receives.
"""

import asyncio
import dataclasses
import logging
import struct
import time

import asyncssh
import pytest

from honeypot.adaptive import ssh_transport
from honeypot.adaptive.ssh_profile import OPENSSH_8_2, server_sig_algs
from honeypot.core import login_delay as login_delay_module
from honeypot.core.config import HoneypotConfig, config
from honeypot.core.login_delay import MAX_DELAY_SECONDS, LoginDelay, login_delay
from honeypot.core.login_policy import login_policy
from honeypot.core.session import session_manager
from honeypot.emulators.ssh import SSHHoneypot

PORT = 24720

#: The identification every well-formed probe sends (ssh_probes.CLIENT_IDENT).
CLIENT_IDENT = b"SSH-2.0-OpenSSH_8.9p1\r\n"


@pytest.fixture
async def sshd(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    # One fast key: RSA-3072 per test adds seconds and tests nothing here.
    monkeypatch.setattr(
        SSHHoneypot, "_host_keys", lambda self: [asyncssh.generate_private_key("ssh-ed25519")]
    )

    async def discard(session):
        return None

    monkeypatch.setattr(session_manager, "_send_to_backend", discard)
    login_policy.reset()

    honeypot = SSHHoneypot()
    honeypot.port = PORT
    await honeypot.start()
    try:
        yield honeypot
    finally:
        await honeypot.stop()
        login_policy.reset()


async def _open():
    """A bare socket with the server's identification line already read."""
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    banner = await asyncio.wait_for(reader.readline(), timeout=5)
    assert banner == b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n"
    return reader, writer


async def _read_packet(reader) -> tuple[bytes, bytes]:
    """One unencrypted binary packet: (payload, padding)."""
    (length,) = struct.unpack(">I", await asyncio.wait_for(reader.readexactly(4), timeout=5))
    body = await asyncio.wait_for(reader.readexactly(length), timeout=5)
    padding_length = body[0]
    return body[1:length - padding_length], body[length - padding_length:]


async def _everything_until_close(reader) -> bytes:
    """All the server sends before it closes; fails if it stays open."""
    return await asyncio.wait_for(reader.read(-1), timeout=5)


async def _reply_to_identification(sent: bytes) -> bytes:
    reader, writer = await _open()
    try:
        writer.write(sent)
        await writer.drain()
        return await _everything_until_close(reader)
    finally:
        writer.close()


class TestKexinitPadding:
    async def test_packets_before_encryption_are_padded_with_zeros(self, sshd):
        """ssh.kexinit.padding — reference: "padding_bytes": "all-zero",
        "padding": "00000000000000000000". asyncssh sent random bytes."""
        reader, writer = await _open()
        try:
            writer.write(CLIENT_IDENT)
            await writer.drain()
            payload, padding = await _read_packet(reader)
        finally:
            writer.close()
        assert payload[0] == 20, "expected SSH_MSG_KEXINIT"
        # Ten bytes in the reference; fewer names here, with one host key, so
        # the length differs. What is compared is that every byte is zero.
        assert len(padding) >= 4
        assert padding == bytes(len(padding))

    def test_only_a_whole_cleartext_packet_is_rewritten(self):
        """The identification line, and anything else that is not one framed
        packet, must pass through untouched."""
        ident = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n"
        assert ssh_transport.zero_cleartext_padding(ident) == ident

        packet = struct.pack(">IB", 12, 6) + b"\x15payl" + b"\xaa" * 6
        assert ssh_transport.zero_cleartext_padding(packet) == packet[:-6] + bytes(6)

        # A length field that does not describe the data: an encrypted packet
        # with its MAC, say. Not ours to touch.
        assert ssh_transport.zero_cleartext_padding(packet + b"\x00" * 16) == packet + b"\x00" * 16


class TestClientIdentification:
    async def test_no_software_version(self, sshd):
        """ssh.ident_reply.no_software_version.response — sent "SSH-2.0\\r\\n"."""
        reply = await _reply_to_identification(b"SSH-2.0\r\n")
        assert reply == b"Invalid SSH identification string.\r\n"

    async def test_protocol_1(self, sshd):
        """ssh.ident_reply.protocol_1.response."""
        reply = await _reply_to_identification(b"SSH-1.5-FingerprintAudit\r\n")
        assert reply == b"Protocol major versions differ.\r\n"

    async def test_over_255_bytes_is_accepted(self, sshd):
        """ssh.ident_reply.over_255_bytes.response and .closes — the
        reference answered a 300-byte identification with its KEXINIT
        ("parsed": [{"packet": "SSH_MSG_KEXINIT"}]) and stayed open
        ("closed": null). The decoy closed without a word."""
        reader, writer = await _open()
        try:
            writer.write(b"SSH-2.0-" + b"A" * 290 + b"\r\n")
            await writer.drain()
            payload, _padding = await _read_packet(reader)
            assert payload[0] == 20, "expected SSH_MSG_KEXINIT"
            # Still open: nothing more arrives, and no end of stream either.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(reader.read(1), timeout=0.5)
        finally:
            writer.close()

    async def test_over_8192_bytes(self, sshd):
        """ssh.ident_reply.over_8192_bytes.response — the reference's text
        has no line ending here: it closed with the rest of the line unread."""
        reply = await _reply_to_identification(b"SSH-2.0-" + b"A" * 9000 + b"\r\n")
        assert reply == b"Invalid SSH identification string."

    async def test_http_request(self, sshd):
        """ssh.ident_reply.http_request.response — no line ending either:
        the request's headers were still unread."""
        reply = await _reply_to_identification(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert reply == b"Invalid SSH identification string."

    async def test_a_normal_client_still_connects(self, sshd):
        async with asyncio.timeout(15):
            async with asyncssh.connect(
                "127.0.0.1", PORT, username="root", password="root",
                known_hosts=None, client_keys=None, agent_path=None,
            ) as conn:
                result = await conn.run("echo ok")
        assert result.stdout.strip() == "ok"

    def test_the_verdict_waits_for_a_whole_line(self):
        judge = ssh_transport.judge_client_identification
        assert judge(b"SSH-2.0-OpenSSH") is None
        assert judge(b"SSH-2.0-OpenSSH_8.9p1\r\n").refusal is None
        assert judge(b"SSH-1.99-old\n").refusal is None
        # 8192 bytes are a line sshd still reads; one more is not.
        longest = b"SSH-2.0-" + b"A" * (ssh_transport.MAX_IDENT_LINE - 8)
        assert judge(longest + b"\r\n").refusal is None
        assert judge(longest + b"A\r\n").refusal == ssh_transport.INVALID_IDENT


class TestBadPackets:
    async def _after_key_exchange_init(self):
        reader, writer = await _open()
        writer.write(CLIENT_IDENT)
        await writer.drain()
        payload, _padding = await _read_packet(reader)
        assert payload[0] == 20
        return reader, writer

    async def test_an_impossible_packet_length_closes_the_connection(self, sshd):
        """ssh.packet_reply.bad_length.response and .closes — 64 bytes of
        0xff: the reference sent nothing ("length": 0) and closed
        ("closed": "eof"). The decoy stayed open."""
        reader, writer = await self._after_key_exchange_init()
        try:
            writer.write(b"\xff" * 64)
            await writer.drain()
            assert await _everything_until_close(reader) == b""
        finally:
            writer.close()

    async def test_an_unassigned_message_number_is_refused_in_sshd_s_words(self, sshd):
        """ssh.packet_reply.unknown_message.response — the 56 bytes the
        reference sent back for message 192 (padding is zero on the wire;
        the audit blanks it either way)."""
        reader, writer = await self._after_key_exchange_init()
        # sshwire.build_packet(bytes([192]) + b"fingerprint-audit")
        probe = b"\x00\x00\x00\x1c\t\xc0fingerprint-audit" + bytes(9)
        try:
            writer.write(probe)
            await writer.drain()
            reply = await _everything_until_close(reader)
        finally:
            writer.close()
        assert reply == (
            b"\x00\x00\x004\t\x01\x00\x00\x00\x02\x00\x00\x00\x1d"
            b"Invalid ssh2 packet type: 192\x00\x00\x00\x00" + bytes(9)
        )


class _ExtInfoLog(logging.Handler):
    """Collects what asyncssh's client logs about the EXT_INFO it received —
    the only place the library shows the order the names arrived in, and the
    way the audit reads it too.

    The decoy runs in the same process and logs what it sends in the same
    format, so only the lines after the client's "Received extension info"
    are taken.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.server_sig_algs = None
        self._receiving = False

    def emit(self, record: logging.LogRecord) -> None:
        message = str(record.msg)
        if message.endswith("Received extension info"):
            self._receiving = True
        elif message.endswith("Sending extension info"):
            self._receiving = False
        elif self._receiving and message.endswith("  %s: %s"):
            name, value = record.args
            if name == "server-sig-algs":
                self.server_sig_algs = str(value).split(",")


class TestExtInfo:
    async def test_server_sig_algs_are_openssh_s_in_its_order(self, sshd):
        """ssh.ext_info.server_sig_algs — the reference's ten names. The
        decoy sent asyncssh's whole catalogue twice, 33 names."""
        logger = logging.getLogger("asyncssh")
        saved_level, saved_propagate = logger.level, logger.propagate
        capture = _ExtInfoLog()
        logger.addHandler(capture)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        asyncssh.set_debug_level(2)
        try:
            async with asyncio.timeout(15):
                async with asyncssh.connect(
                    "127.0.0.1", PORT, username="root", password="root",
                    known_hosts=None, client_keys=None, agent_path=None,
                ):
                    pass
        finally:
            asyncssh.set_debug_level(1)
            logger.removeHandler(capture)
            logger.setLevel(saved_level)
            logger.propagate = saved_propagate

        assert capture.server_sig_algs == [
            "ssh-ed25519",
            "sk-ssh-ed25519@openssh.com",
            "ssh-rsa",
            "rsa-sha2-256",
            "rsa-sha2-512",
            "ssh-dss",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        ]

    def test_a_name_asyncssh_lacks_is_left_out_not_fatal(self):
        """asyncssh.listen raises ValueError for an algorithm it does not
        implement; the decoy must start regardless."""
        profile = dataclasses.replace(
            OPENSSH_8_2, server_sig_algs=("ssh-ed25519", "no-such-algorithm", "ssh-rsa")
        )
        assert server_sig_algs(profile) == ("ssh-ed25519", "ssh-rsa")


class TestFailedPasswordDelay:
    def test_the_default_is_the_measured_delay(self):
        """ssh.auth.failed_password_delay — reference value 2.175 s."""
        defaults = {field.name: field.default for field in dataclasses.fields(HoneypotConfig)}
        assert defaults["ssh_fail_delay"] == 2.175

    async def test_a_wrong_password_is_refused_only_after_the_delay(self, sshd, monkeypatch):
        """The reference took seconds to refuse ("rejection_seconds":
        [4.348, 2.175, 2.174]); the decoy took a millisecond. A shorter
        configured value keeps the test quick; the mechanism is the same."""
        monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
        monkeypatch.setattr(config, "ssh_fail_delay", 0.6)
        started = time.monotonic()
        with pytest.raises(asyncssh.PermissionDenied):
            async with asyncio.timeout(15):
                await asyncssh.connect(
                    "127.0.0.1", PORT, username="fpaudit-nouser", password="fpaudit-wrong-1",
                    known_hosts=None, client_keys=None, agent_path=None, preferred_auth="password",
                )
        assert time.monotonic() - started >= 0.6

    async def test_an_accepted_password_does_not_wait(self, sshd, monkeypatch):
        monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
        monkeypatch.setattr(config, "ssh_fail_delay", 5.0)
        started = time.monotonic()
        async with asyncio.timeout(15):
            async with asyncssh.connect(
                "127.0.0.1", PORT, username="root", password="root",
                known_hosts=None, client_keys=None, agent_path=None,
            ):
                pass
        assert time.monotonic() - started < 4.0

    async def test_pending_delays_are_capped(self, monkeypatch):
        """Many connections must not be able to pile up timers: past the
        cap a refusal goes out without the pause."""
        monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
        monkeypatch.setattr(config, "fail_delay_max_pending", 2)
        delay = LoginDelay()
        waiting = [asyncio.create_task(delay.pause(30.0)) for _ in range(2)]
        await asyncio.sleep(0)
        assert delay.pending == 2

        started = time.monotonic()
        assert await delay.pause(30.0) is False
        assert time.monotonic() - started < 0.5

        # A cancelled connection gives its place back.
        for task in waiting:
            task.cancel()
        await asyncio.gather(*waiting, return_exceptions=True)
        assert delay.pending == 0

    def test_a_setting_cannot_ask_for_an_unbounded_delay(self, monkeypatch):
        monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
        assert LoginDelay.seconds(3600.0) == MAX_DELAY_SECONDS
        assert LoginDelay.seconds(-1.0) == 0.0
        assert LoginDelay.seconds(float("nan")) == 0.0
        monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
        assert LoginDelay.seconds(2.175) == 0.0

    def test_the_emulators_share_one_counter(self):
        assert login_delay_module.login_delay is login_delay


class TestHooksFailSafe:
    """A later asyncssh may rename what the hooks wrap. The decoy must
    still start, without that one disguise."""

    def test_a_connection_class_without_the_internals_is_left_alone(self):
        class Bare:
            pass

        module = type("module", (), {})()
        assert ssh_transport._zero_padding_before_encryption(Bare) is False
        assert ssh_transport._answer_identification_like_sshd(Bare, module) is False
        assert ssh_transport._drop_impossible_packet_lengths(Bare) is False
        assert ssh_transport._disconnect_on_invalid_message_numbers(Bare) is False
        assert ssh_transport._disconnect_without_language_tag(Bare) is False
        assert vars(Bare).keys() == vars(type("Other", (), {})).keys()

    def test_unknown_encryption_state_is_never_treated_as_cleartext(self):
        """Zeroing the padding of an encrypted packet would break its MAC,
        so a missing attribute must not read as "not encrypted"."""

        class Connection:
            pass

        conn = Connection()
        assert ssh_transport._in_cleartext(conn, "_send_encryption") is False
        conn._send_encryption = None
        assert ssh_transport._in_cleartext(conn, "_send_encryption") is True
        conn._send_encryption = object()
        assert ssh_transport._in_cleartext(conn, "_send_encryption") is False

    def test_applying_twice_wraps_once(self):
        from asyncssh.connection import SSHServerConnection

        first = ssh_transport.apply_transport_behaviour()
        wrapped = SSHServerConnection._send
        second = ssh_transport.apply_transport_behaviour()
        assert first == second
        assert all(first.values())
        assert SSHServerConnection._send is wrapped
