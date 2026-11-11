"""The Telnet decoy negotiates and logs in the way Ubuntu 20.04's telnetd did.

Every expected sequence and text here is copied from the reference side of
docs/evaluation/fingerprint/baseline/telnet-telnetd-focal.json, the first
probe-by-probe comparison of the decoy with the real daemon; each test plays
the client the named probe played (tools/fingerprint_audit/telnet_probes.py).
The check id is in each test's docstring.
"""

import asyncio
import dataclasses
import time

import pytest

from honeypot.core.config import HoneypotConfig, config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.login_policy import login_policy
from honeypot.core.session import session_manager
from honeypot.emulators.telnet import DO, DONT, IAC, WILL, WONT, TelnetHoneypot

PORT = 24324

#: Option numbers, by the names the audit prints.
NAMES = {
    1: "ECHO",
    3: "SUPPRESS-GO-AHEAD",
    5: "STATUS",
    24: "TERMINAL-TYPE",
    31: "NAWS",
    32: "TERMINAL-SPEED",
    33: "REMOTE-FLOW-CONTROL",
    35: "X-DISPLAY-LOCATION",
    39: "NEW-ENVIRON",
}
VERBS = {DO: "DO", DONT: "DONT", WILL: "WILL", WONT: "WONT"}

#: An account neither a stock install nor the decoy's credential list has.
UNKNOWN_USER = "fpaudit-nouser"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))

    async def discard(session):
        return None

    monkeypatch.setattr(session_manager, "_send_to_backend", discard)
    login_policy.reset()
    reset_identity()
    yield
    login_policy.reset()
    reset_identity()


@pytest.fixture
async def telnet():
    honeypot = TelnetHoneypot(port=PORT)
    await honeypot.start()
    yield honeypot
    await honeypot.stop()


class _Client:
    """A telnet client that keeps the server's commands apart from its text
    and, unless told otherwise, refuses every option — the audit's client."""

    def __init__(self, reader, writer, refuse: bool = True) -> None:
        self.reader, self.writer = reader, writer
        self._refuse = refuse
        self._partial = b""
        self.commands: list[str] = []
        self.closed = False

    @classmethod
    async def connect(cls, refuse: bool = True) -> "_Client":
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        return cls(reader, writer, refuse)

    def _take(self, data: bytes) -> bytes:
        """Split off the commands in ``data``, answer them, return the text."""
        data = self._partial + data
        self._partial = b""
        text = bytearray()
        index = 0
        while index < len(data):
            if data[index] != IAC:
                text.append(data[index])
                index += 1
                continue
            if index + 3 > len(data):
                self._partial = data[index:]
                break
            verb, option = data[index + 1], data[index + 2]
            self.commands.append(f"{VERBS[verb]} {NAMES.get(option, f'OPTION-{option}')}")
            if self._refuse and verb in (DO, WILL):
                self.writer.write(bytes([IAC, WONT if verb == DO else DONT, option]))
            index += 3
        return bytes(text)

    async def read(self, until: bytes = b"", quiet: float = 0.5, timeout: float = 5.0) -> bytes:
        """The text received until it ends with ``until``, the server has
        been silent for ``quiet`` seconds, or it closes."""
        text = b""
        deadline = time.monotonic() + timeout
        while not (until and text.endswith(until)):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                data = await asyncio.wait_for(self.reader.read(4096), timeout=min(quiet, remaining))
            except asyncio.TimeoutError:
                if until:
                    continue
                break
            if not data:
                self.closed = True
                break
            text += self._take(data)
        return text

    def send(self, data: bytes) -> None:
        self.writer.write(data)

    def close(self) -> None:
        self.writer.close()


def _prompt() -> bytes:
    return f"{get_identity().hostname} login: ".encode()


class TestOpeningNegotiation:
    async def test_a_silent_client_gets_four_requests_and_nothing_else(self, telnet):
        """telnet.silent.negotiation and telnet.silent.text — the decoy sent
        WILL ECHO, WILL SGA, DO SGA and a banner without waiting."""
        client = await _Client.connect(refuse=False)
        try:
            text = await client.read(quiet=1.0)
        finally:
            client.close()
        assert client.commands == [
            "DO TERMINAL-TYPE",
            "DO TERMINAL-SPEED",
            "DO X-DISPLAY-LOCATION",
            "DO NEW-ENVIRON",
        ]
        assert text == b""
        assert not client.closed

    async def test_a_refusing_client_sees_telnetd_s_whole_sequence(self, telnet):
        """telnet.refusing.negotiation — the server's requests and its
        reaction to the refusals, in the reference's order."""
        client = await _Client.connect()
        try:
            await client.read(until=b"login: ")
            # A server may still be reacting to the last refusal.
            await client.read(quiet=0.5)
        finally:
            client.close()
        assert client.commands == [
            "DO TERMINAL-TYPE",
            "DO TERMINAL-SPEED",
            "DO X-DISPLAY-LOCATION",
            "DO NEW-ENVIRON",
            "WILL SUPPRESS-GO-AHEAD",
            "DO ECHO",
            "DO NAWS",
            "WILL STATUS",
            "DO REMOTE-FLOW-CONTROL",
            "WILL SUPPRESS-GO-AHEAD",
            "WILL ECHO",
        ]

    async def test_the_banner_starts_without_a_blank_line(self, telnet):
        """telnet.refusing.login_banner — reference:
        "Ubuntu 20.04.6 LTS\\r\\n<hostname> login: ". The decoy's began with
        "\\r\\n"."""
        client = await _Client.connect()
        try:
            text = await client.read(until=b"login: ")
        finally:
            client.close()
        identity = get_identity()
        assert text == f"Ubuntu {identity.os_version} LTS\r\n{identity.hostname} login: ".encode()

    async def test_unassigned_options_are_still_refused(self, telnet):
        """telnet.option.client_will_unknown and client_do_unknown — these
        matched before the negotiation changed and must go on matching:
        "DONT OPTION-99" and "WONT OPTION-99", no text."""
        client = await _Client.connect()
        try:
            await client.read(until=b"login: ")
            await client.read(quiet=0.3)
            before = len(client.commands)
            client.send(bytes([IAC, WILL, 99]))
            text = await client.read(quiet=0.3)
            assert (client.commands[before:], text) == (["DONT OPTION-99"], b"")
            before = len(client.commands)
            client.send(bytes([IAC, DO, 99]))
            text = await client.read(quiet=0.3)
            assert (client.commands[before:], text) == (["WONT OPTION-99"], b"")
        finally:
            client.close()


class TestLogin:
    async def test_the_username_is_echoed_before_the_password_prompt(self, telnet):
        """telnet.login.after_username — reference: "root\\r\\nPassword: ",
        to a client that had refused ECHO. The decoy sent "Password: "."""
        client = await _Client.connect()
        try:
            await client.read(until=b"login: ")
            client.send(b"root\r\n")
            text = await client.read(until=b"Password: ")
        finally:
            client.close()
        assert text == b"root\r\nPassword: "

    async def test_a_wrong_password_is_refused_as_before(self, telnet):
        """telnet.login.after_wrong_password — matched already; unchanged."""
        client = await _Client.connect()
        try:
            await client.read(until=b"login: ")
            client.send(UNKNOWN_USER.encode() + b"\r\n")
            await client.read(until=b"Password: ")
            client.send(b"fpaudit-wrong-1\r\n")
            text = await client.read(until=b"login: ")
        finally:
            client.close()
        assert text == b"\r\n\r\nLogin incorrect\r\n" + _prompt()

    async def test_the_fifth_wrong_password_ends_the_connection(self, telnet):
        """telnet.login.wrong_passwords.unknown_user — reference:
        "wrong_passwords_sent": 5, "ended": "closed-by-server", final text
        "\\r\\n\\r\\nLogin incorrect\\r\\nMaximum number of tries exceeded (5)\\r\\n".
        The decoy allowed six and printed another login prompt first."""
        client = await _Client.connect()
        sent = 0
        try:
            await client.read(until=b"login: ")
            while True:
                client.send(UNKNOWN_USER.encode() + b"\r\n")
                await client.read(until=b"Password: ")
                sent += 1
                client.send(f"fpaudit-wrong-{sent}\r\n".encode())
                final = await client.read(until=b"login: ")
                if client.closed or sent >= 8:
                    break
        finally:
            client.close()
        assert sent == 5
        assert client.closed
        assert final == b"\r\n\r\nLogin incorrect\r\nMaximum number of tries exceeded (5)\r\n"


class TestFailedLoginDelay:
    def test_the_default_is_the_measured_delay(self):
        """telnet.login.failed_login_delay — reference value 2.885 s."""
        defaults = {field.name: field.default for field in dataclasses.fields(HoneypotConfig)}
        assert defaults["telnet_fail_delay"] == 2.885

    async def test_the_next_prompt_comes_only_after_the_delay(self, telnet, monkeypatch):
        """The decoy's pause was a fixed second; a shorter configured value
        keeps the test quick, the mechanism is the same."""
        monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
        monkeypatch.setattr(config, "telnet_fail_delay", 0.6)
        client = await _Client.connect()
        try:
            await client.read(until=b"login: ")
            client.send(UNKNOWN_USER.encode() + b"\r\n")
            await client.read(until=b"Password: ")
            client.send(b"fpaudit-wrong-1\r\n")
            started = time.monotonic()
            await client.read(until=b"login: ")
            elapsed = time.monotonic() - started
        finally:
            client.close()
        assert 0.6 <= elapsed < 0.95
