"""The shell transports as a client sees them, and what they record.

Over a real SSH connection: a terminal gets CRLF, a banner and a prompt; a
pipe gets none of them; the exit status is the command's; arrow keys and
Ctrl-C behave. Then what each connection leaves in its session record — the
client's fingerprints, forwarding requests, a login that is honoured when
the source comes back — and the failure paths that used to lose sessions.
"""

import asyncio
import re

import asyncssh
import pytest

from honeypot.capture import shell_capture
from honeypot.core import shell_dispatch
from honeypot.core.config import config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.login_policy import LoginPolicy, login_policy
from honeypot.core.session import session_manager
from honeypot.core.shell_state import shell_states
from honeypot.emulators import ssh as ssh_module
from honeypot.emulators.ssh import SSHHoneypot, hassh, kexinit_name_lists
from honeypot.emulators.telnet import IAC, DO, WILL, OPT_ECHO, OPT_SGA, TelnetHoneypot, TelnetLineReader
from honeypot.security.rate_limiter import RateLimiter
from honeypot.security.refusals import MAX_RECORDS_PER_FLUSH, MAX_TRACKED, refusal_log

PORT = 24410
TELNET_PORT = 24423


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    login_policy.reset()
    reset_identity()
    yield
    login_policy.reset()
    reset_identity()


@pytest.fixture
def ingested(monkeypatch):
    queue: asyncio.Queue = asyncio.Queue()

    async def capture(session):
        await queue.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture)
    return queue


@pytest.fixture
async def ssh(monkeypatch, ingested):
    monkeypatch.setattr(
        SSHHoneypot, "_host_keys", lambda self: [asyncssh.generate_private_key("ssh-ed25519")]
    )
    honeypot = SSHHoneypot()
    honeypot.port = PORT
    await honeypot.start()
    try:
        yield honeypot
    finally:
        await honeypot.stop()


def _connect(username="root", password="root", **options):
    return asyncssh.connect(
        "127.0.0.1", PORT, username=username, password=password,
        known_hosts=None, client_keys=None, agent_path=None, **options,
    )


async def _read_until(stream, marker: str, timeout=5) -> str:
    seen = ""
    while marker not in seen:
        chunk = await asyncio.wait_for(stream.read(4096), timeout=timeout)
        if not chunk:
            break
        seen += chunk
    return seen


# -- terminal behaviour --------------------------------------------------------

async def test_a_terminal_gets_crlf_a_banner_and_a_prompt(ssh, ingested):
    async with _connect() as conn:
        process = await conn.create_process(term_type="xterm", encoding=None)
        banner = (await _read_until_bytes(process.stdout, b"# ")).decode()
        assert "Welcome to Ubuntu" in banner and "Last login" in banner
        # Every line feed is preceded by a carriage return.
        assert not re.search(r"(?<!\r)\n", banner)
        process.stdin.write(b"uname -s; id -u\r")
        reply = (await _read_until_bytes(process.stdout, b"# ")).decode()
        assert "Linux\r\n0\r\n" in reply
        assert not re.search(r"(?<!\r)\n", reply)
        process.stdin.write(b"exit\r")
        await asyncio.wait_for(process.wait(), timeout=5)


async def _read_until_bytes(stream, marker: bytes, timeout=5) -> bytes:
    seen = b""
    while marker not in seen:
        chunk = await asyncio.wait_for(stream.read(4096), timeout=timeout)
        if not chunk:
            break
        seen += chunk
    return seen


async def test_exec_and_a_shell_without_a_terminal_get_only_output(ssh, ingested):
    async with _connect() as conn:
        result = await conn.run("echo one; uname -s")
        assert result.stdout == "one\nLinux\n"

        process = await conn.create_process()
        process.stdin.write("echo first\nwhoami\n")
        process.stdin.write_eof()
        output = await asyncio.wait_for(process.stdout.read(), timeout=5)
        await asyncio.wait_for(process.wait(), timeout=5)
    # No MOTD, no prompt, no echo of what was typed, no carriage returns.
    assert output == "first\nroot\n"


async def test_exit_status_is_the_commands(ssh, ingested):
    async with _connect() as conn:
        assert (await conn.run("true")).exit_status == 0
        assert (await conn.run("cat /nope")).exit_status == 1
        assert (await conn.run("nosuchcommand")).exit_status == 127
        process = await conn.create_process()
        process.stdin.write("exit 7\n")
        await asyncio.wait_for(process.wait(), timeout=5)
        assert process.exit_status == 7
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert [t["exit_code"] for t in payload["transcript"][:3]] == [0, 1, 127]


async def test_each_user_starts_in_their_own_home(ssh, ingested):
    async with _connect("admin", "admin") as conn:
        assert (await conn.run("pwd")).stdout == "/home/admin\n"
        assert (await conn.run("echo ~; whoami")).stdout == "/home/admin\nadmin\n"
        process = await conn.create_process(term_type="xterm")
        prompt = await _read_until(process.stdout, "$ ")
        assert prompt.rstrip().endswith(f"admin@{get_identity().hostname}:~$")
        process.stdin.write("exit\r")


async def test_arrow_keys_and_ctrl_c_are_keys_not_text(ssh, ingested):
    async with _connect() as conn:
        process = await conn.create_process(term_type="xterm")
        await _read_until(process.stdout, "# ")
        process.stdin.write("echo first\r")
        await _read_until(process.stdout, "# ")
        # Left arrow, then a half-typed line abandoned with Ctrl-C.
        process.stdin.write("\x1b[Dwhoam\x03")
        abandoned = await _read_until(process.stdout, "# ")
        assert "^C" in abandoned and "[D" not in abandoned
        # Up arrow twice recalls the first command (the abandoned line was
        # never run, so it is not in the history).
        process.stdin.write("\x1b[A\r")
        recalled = await _read_until(process.stdout, "# ")
        assert "first" in recalled
        process.stdin.write("\x04")
        await asyncio.wait_for(process.wait(), timeout=5)
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert payload["commands"] == ["echo first", "echo first"]


def test_line_editor_handles_the_keys_a_terminal_sends():
    editor = shell_dispatch.LineEditor(100, ["ls", "pwd"])
    for char in "ab\x7fc":
        editor.feed(char)
    assert editor.buffer == "ac"
    echoed, event = editor.feed("\x15")       # Ctrl-U kills the line
    assert editor.buffer == "" and event is None
    editor.feed("\x1b"), editor.feed("["), editor.feed("A")
    assert editor.buffer == "pwd"
    editor.feed("\x1b"), editor.feed("["), editor.feed("A")
    assert editor.buffer == "ls"
    assert editor.feed("\r")[1] == ("line", "ls")
    assert editor.feed("\n") == (b"", None)  # the LF of CRLF is not a second line
    assert editor.feed("\x04")[1] == ("eof", "")


# -- what a connection leaves behind -------------------------------------------

async def test_client_fingerprints_are_recorded(ssh, ingested):
    async with _connect(client_version="TestClient_1.0") as conn:
        await conn.run("true")
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    prints = payload["fingerprints"]
    assert prints["ssh_client_version"] == "SSH-2.0-TestClient_1.0"
    assert re.fullmatch(r"[0-9a-f]{32}", prints["hassh"])
    assert re.fullmatch(r"[0-9a-f]{32}", prints["hassh_server"])
    kex, encryption, mac, compression = prints["hassh_algorithms"].split(";")
    assert "curve25519-sha256" in kex and "ext-info-c" in kex
    assert "none" in compression


def test_hassh_is_the_md5_of_the_four_lists():
    import hashlib
    import struct

    lists = ["kexA,kexB", "hostkey", "encC", "encS", "macC", "macS", "compC", "compS", "", ""]
    payload = bytes([20]) + bytes(16) + b"".join(
        struct.pack(">I", len(item)) + item.encode() for item in lists
    ) + b"\x00" + bytes(4)
    assert kexinit_name_lists(payload) == lists
    digest, algorithms = hassh(payload)
    assert algorithms == "kexA,kexB;encC;macC;compC"
    assert digest == hashlib.md5(algorithms.encode()).hexdigest()
    assert hassh(payload, server=True)[1] == "kexA,kexB;encS;macS;compS"
    assert hassh(b"\x14short") is None


async def test_direct_tcpip_is_recorded_and_refused(ssh, ingested):
    async with _connect() as conn:
        with pytest.raises(asyncssh.ChannelOpenError) as refused:
            await conn.open_connection("192.0.2.25", 25)
        assert refused.value.code == asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    [event] = [e for e in payload["events"] if e["event_type"] == "direct_tcpip"]
    assert (event["dest_host"], event["dest_port"]) == ("192.0.2.25", 25)


async def test_a_guessed_password_works_again_when_the_source_returns(ssh, ingested):
    # Three failures, then a guess that is let in.
    for attempt in range(3):
        with pytest.raises(asyncssh.PermissionDenied):
            await _connect("root", f"wrong{attempt}", preferred_auth="password")
    async with _connect("root", "hunter2") as conn:
        assert (await conn.run("whoami")).stdout == "root\n"
    # The source comes back later with the password that worked.
    async with _connect("root", "hunter2") as conn:
        assert (await conn.run("id -u")).stdout == "0\n"
    # ...and it is that password, not any password.
    with pytest.raises(asyncssh.PermissionDenied):
        await _connect("root", "something-else", preferred_auth="password")


def test_remembered_logins_survive_a_restart_and_expire(monkeypatch):
    policy = LoginPolicy()
    for _ in range(3):
        assert not policy.check("198.51.100.4", "admin", "nope")
    assert policy.check("198.51.100.4", "admin", "letmein")

    restarted = LoginPolicy()
    assert restarted.check("198.51.100.4", "admin", "letmein")
    assert not restarted.check("198.51.100.5", "admin", "letmein")

    monkeypatch.setattr(config, "accepted_login_ttl", 60)
    expiring = LoginPolicy()
    for _ in range(3):
        expiring.check("198.51.100.6", "admin", "nope")
    assert expiring.check("198.51.100.6", "admin", "once")
    monkeypatch.setattr("honeypot.core.login_policy.time.time", lambda: __import__("time").monotonic() + 4e9)
    assert not LoginPolicy().remembered("198.51.100.6", "admin", "once")


async def test_the_planted_login_is_accepted_and_reported(ssh, ingested):
    from honeypot.core import honeytokens

    tokens = honeytokens.get_honeytokens()
    async with _connect(tokens.username, tokens.password) as conn:
        assert (await conn.run("pwd")).stdout == f"/home/{tokens.username}\n"
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    [event] = [e for e in payload["events"] if e["event_type"] == "honeytoken_used"]
    assert event["token_id"] == "login_pair"


# -- one filesystem for the shell and SFTP -------------------------------------

async def test_sftp_and_the_shell_show_the_same_filesystem(ssh, ingested, tmp_path):
    from honeypot.core import hostfacts

    local = tmp_path / "bot"
    local.write_bytes(b"\x7fELF-not-really")
    async with _connect("admin", "admin") as conn:
        async with conn.start_sftp_client() as sftp:
            names = set(await sftp.listdir("/etc")) - {".", ".."}
            shell_names = set((await conn.run("ls -A1 /etc")).stdout.split())
            assert names == shell_names and "passwd" in names

            # The same bytes cat prints, and the size ls lists.
            await sftp.get("/etc/passwd", str(tmp_path / "passwd"))
            expected = hostfacts.passwd(get_identity()).encode()
            assert (tmp_path / "passwd").read_bytes() == expected
            assert (await sftp.stat("/etc/passwd")).size == len(expected)

            # Permissions are the user's, as in the shell.
            with pytest.raises(asyncssh.SFTPPermissionDenied):
                await sftp.get("/etc/shadow", str(tmp_path / "shadow"))
            with pytest.raises(asyncssh.SFTPError):
                await sftp.put(str(local), "/usr/bin/bot")

            # An upload is there when the shell looks.
            await sftp.put(str(local), "/tmp/bot")
        listing = (await conn.run("ls -l /tmp/bot && cat /tmp/bot | wc -c")).stdout
        assert "bot" in listing and listing.strip().endswith("15")
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    # Recorded once, by the transfer; not again when the session closed.
    assert [(u["remote_path"], u["source"]) for u in payload["uploads"]] == [("/tmp/bot", "sftp")]


# -- sessions are not lost -----------------------------------------------------

async def test_a_failure_while_flushing_files_still_ends_the_session(ssh, ingested, monkeypatch):
    async def broken(session_id, shell):
        raise OSError("disk full")

    monkeypatch.setattr(ssh_module, "flush_session_files", broken)
    async with _connect() as conn:
        await conn.run("echo data > /tmp/f")
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert payload["commands"] == ["echo data > /tmp/f"]


async def test_an_idle_connection_is_closed_at_the_session_cap(ssh, ingested, monkeypatch):
    monkeypatch.setattr(config, "max_session_seconds", 1)
    conn = await _connect()
    # Authenticated, then nothing: no shell, no exec, no SFTP.
    await asyncio.wait_for(conn.wait_closed(), timeout=6)
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert payload["credentials"][0]["success"] is True


async def test_a_command_is_recorded_even_when_emulating_it_fails(monkeypatch):
    session_id = await session_manager.create_session("ssh", "203.0.113.9", 40000)

    async def explode(*args, **kwargs):
        raise ValueError("emulator bug")

    monkeypatch.setattr(shell_dispatch.mode_handler, "handle_interaction", explode)
    state = ssh_module._SessionState()
    state.session_id, state.username, state.is_root = session_id, "root", True
    response, status = await shell_dispatch.run_command(session_id, "203.0.113.9", state, "echo x | tr a")
    assert (response, status) == ("", 1)
    record = await session_manager.get_session(session_id)
    assert [c["command"] for c in record.commands] == ["echo x | tr a"]
    shell_states.drop(session_id)


# -- telnet --------------------------------------------------------------------

def test_a_lone_cr_ends_the_line_at_once():
    parser = TelnetLineReader()
    # The command is complete after the CR; nothing more needs to arrive.
    assert parser.feed(b"uname -a\r") == b"uname -a\n"
    assert parser.feed(b"\nls\r\x00id\r") == b"ls\nid\n"


async def test_telnet_frees_its_shell_state_and_records_the_option_sequence(ingested):
    honeypot = TelnetHoneypot(port=TELNET_PORT)
    await honeypot.start()
    try:
        before = len(shell_states)
        reader, writer = await asyncio.open_connection("127.0.0.1", TELNET_PORT)
        writer.write(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA, IAC, WILL, OPT_SGA, IAC, WILL, 24]))
        await _read_until_bytes(reader, b"login: ")
        writer.write(b"root\r")
        await _read_until_bytes(reader, b"Password: ")
        writer.write(b"root\r")
        await _read_until_bytes(reader, b"# ")
        writer.write(b"echo payload > /tmp/x\r")
        await _read_until_bytes(reader, b"# ")
        assert len(shell_states) == before + 1
        writer.close()
        payload = await asyncio.wait_for(ingested.get(), timeout=10)
    finally:
        await honeypot.stop()
    assert len(shell_states) == before
    assert payload["fingerprints"]["telnet_options"] == ["DO 1", "DO 3", "WILL 3", "WILL 24"]
    assert payload["uploads"][0]["remote_path"] == "/tmp/x"


# -- refused connections -------------------------------------------------------

async def test_refusals_become_bounded_minimal_records(ingested):
    limiter = RateLimiter()
    limiter._max_per_ip = 1
    limiter._max_requests = 10_000
    refusal_log.reset()
    assert limiter.admit("198.51.100.20", protocol="telnet")
    for _ in range(50):
        assert not limiter.admit("198.51.100.20", protocol="telnet")
    assert await refusal_log.flush() == 1
    payload = await asyncio.wait_for(ingested.get(), timeout=10)
    assert payload["protocol"] == "telnet" and payload["attacker_ip"] == "198.51.100.20"
    [event] = payload["events"]
    assert event["event_type"] == "connection_refused"
    assert event["reason"] == "per_address_connection_cap" and event["count"] == 50

    # A flood from many sources: a fixed number of records, the rest counted.
    for index in range(MAX_TRACKED + 500):
        refusal_log.note(f"203.0.{index // 250}.{index % 250}", "ssh", "rate")
    assert refusal_log.suppressed == 500
    assert await refusal_log.flush() == MAX_RECORDS_PER_FLUSH
    assert refusal_log.suppressed == 500 + MAX_TRACKED - MAX_RECORDS_PER_FLUSH
    refusal_log.reset()
