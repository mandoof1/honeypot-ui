"""SSH emulator, speaking the real protocol.

This used to write a plaintext ``login as: `` prompt straight onto the socket
after exchanging version strings. That is a telnet conversation wearing an SSH
banner: a real client sends its identification string and then immediately
begins the binary key exchange, so the previous implementation read
``SSH_MSG_KEXINIT`` bytes as a username and hung. Nothing but ``nc`` could
drive it, which meant FR-1's "realistic SSH interactive access patterns" was
unmet for the one protocol the project leads with.

asyncssh terminates the transport properly — key exchange, encryption, the
binary packet protocol, and the userauth service — so ordinary ``ssh``, ``scp``
and automated scanners all connect. What they then talk to is still an
emulation: no command is executed, no shell is spawned, and every response
comes from the canned-response layer in ``core/modes.py``.

The dependency is worth its weight here. The engine's requirements are
otherwise deliberately tiny, but there is no way to speak SSH without
implementing the transport, and a hand-rolled one on the internet-facing
component would be a far worse trade than a maintained library.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import asyncssh

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.core.shell_state import shell_states
from honeypot.adaptive.ssh_profile import apply_extra_kex_algs, get_profile
from honeypot.core.modes import mode_handler
from honeypot.emulators.base import BaseEmulator
from honeypot.adaptive.fingerprint import fingerprint_engine
from honeypot.adaptive.response import adaptive_engine

logger = logging.getLogger(__name__)

#: Credentials the decoy accepts. Weak on purpose — the point is to let an
#: attacker in and record what they do next.
FAKE_USERS = {
    "root": "root",
    "admin": "admin",
    "user": "password",
    "test": "test",
    "ubuntu": "ubuntu",
    "pi": "raspberry",
    "oracle": "oracle",
    "postgres": "postgres",
}

MAX_COMMAND_LENGTH = 4096
MAX_AUTH_ATTEMPTS = 6

#: Attempts after which any password is accepted, so a brute-forcer that
#: never guesses the advertised credential still gets in and reveals what it
#: does next. Instant success on attempt one is a fingerprint.
SOFT_ACCEPT_AFTER = 3

#: Failed attempts per source address, not per connection. Most brute-force
#: tools open a fresh connection for every password, so a per-connection
#: counter would never reach the threshold and the soft accept above would be
#: dead code. Bounded so a long scan cannot grow it without limit.
_failures_by_ip: dict[str, int] = {}
_MAX_TRACKED_IPS = 4096


class _SessionState:
    def __init__(self) -> None:
        self.session_id: Optional[str] = None
        self.username: Optional[str] = None
        self.authenticated = False
        self.is_root = False
        self.cwd = "/home/user"
        self.auth_attempts = 0


class _HoneypotSSHServer(asyncssh.SSHServer):
    """Per-connection handler: capture the peer, then the auth attempts."""

    def __init__(self, emulator: "SSHHoneypot") -> None:
        self._emulator = emulator
        self.state = _SessionState()
        self.source_ip = "0.0.0.0"
        self.source_port = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        if peer:
            self.source_ip, self.source_port = peer[0], peer[1]
        conn.set_extra_info(honeypot_server=self)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self.state.session_id:
            # connection_lost is synchronous; hand the close off to the loop.
            session_manager.end_session_soon(self.state.session_id)
            shell_states.drop(self.state.session_id)

    async def begin_auth(self, username: str) -> bool:
        """Open the session here — the first point with a username and a loop.

        Returning True always requires authentication; a decoy that accepted
        an empty auth would never see the credentials that are the most
        valuable thing an SSH honeypot collects.
        """
        if self.state.session_id is None:
            if not await self._emulator.rate_limit_ok(self.source_ip):
                logger.warning("SSH rate limit exceeded for %s", self.source_ip)
                raise asyncssh.DisconnectError(
                    asyncssh.DISC_TOO_MANY_CONNECTIONS, "Too many connections"
                )
            self.state.session_id = await session_manager.create_session(
                "ssh", self.source_ip, self.source_port, {"protocol_version": "SSH-2.0"}
            )
            await session_manager.record_network_event(
                self.state.session_id,
                "ssh_client_banner",
                {"banner": self._client_version()},
            )
        return True

    def _client_version(self) -> str:
        return "unknown"

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        # Advertised so key-based attempts are captured too. Every key is
        # rejected, but the offered public key is recorded first — automated
        # campaigns reuse keys, which makes them a durable IoC.
        return True

    def kbdint_auth_supported(self) -> bool:
        return False

    async def validate_password(self, username: str, password: str) -> bool:
        """Decide whether this attempt "succeeds".

        Two ways in: the weak credential the decoy advertises for that user,
        or persistence — any password is accepted once an attacker has tried
        ``SOFT_ACCEPT_AFTER`` times.

        Letting every password through on the first attempt (the previous
        behaviour) is its own tell: real systems do not accept ``root`` with
        one random guess, and a brute-forcer that succeeds instantly learns it
        is talking to a decoy. Making it work only after a few failures keeps
        the credential list being recorded, and still gets the attacker to the
        far more valuable part — what they type once they are in.
        """
        state = self.state
        state.auth_attempts += 1
        state.username = username

        prior_failures = _failures_by_ip.get(self.source_ip, 0)
        expected = FAKE_USERS.get(username)
        accepted = expected is not None and (
            password == expected or prior_failures >= SOFT_ACCEPT_AFTER
        )
        if not accepted:
            if len(_failures_by_ip) >= _MAX_TRACKED_IPS:
                _failures_by_ip.clear()
            _failures_by_ip[self.source_ip] = prior_failures + 1
        else:
            _failures_by_ip.pop(self.source_ip, None)
        await session_manager.record_auth_attempt(
            state.session_id, username, password, accepted
        )

        if accepted:
            state.authenticated = True
            if username == "root":
                state.is_root = True
                state.cwd = "/root"
                # Keep the emulator's view of the shell in step with the
                # session's, or `pwd` and the prompt disagree from the first
                # command.
                shell_states.get(state.session_id).cwd = "/root"
            await adaptive_engine.profile_actor(
                state.session_id,
                self.source_ip,
                {
                    "auth_attempts": state.auth_attempts,
                    "username_used": username,
                    "password_used": password,
                },
            )
            return True

        if state.auth_attempts >= MAX_AUTH_ATTEMPTS:
            raise asyncssh.DisconnectError(
                asyncssh.DISC_NO_MORE_AUTH_METHODS_AVAILABLE, "Too many failures"
            )
        return False

    async def validate_public_key(self, username: str, key) -> bool:
        try:
            fingerprint = key.get_fingerprint()
        except Exception:
            fingerprint = "unparseable"
        await session_manager.record_network_event(
            self.state.session_id,
            "ssh_pubkey_offered",
            {"username": username, "fingerprint": fingerprint},
        )
        return False


class SSHHoneypot(BaseEmulator):
    """Real SSH transport in front of the existing emulation layer."""

    def __init__(self) -> None:
        super().__init__("ssh", config.ssh_port)
        self._hostname = fingerprint_engine.get_fake_hostname()
        self._acceptor: Optional[asyncssh.SSHAcceptor] = None

    def get_banner(self) -> str:
        return fingerprint_engine.get_ssh_banner()

    async def handle_client(self, reader, writer):  # pragma: no cover
        """Unused: asyncssh owns the connection lifecycle for this emulator."""
        raise NotImplementedError

    async def rate_limit_ok(self, source_ip: str) -> bool:
        return await self._check_rate_limit(source_ip)

    #: Key types a stock Ubuntu or Debian sshd has, because the package
    #: postinst generates all three. A server offering only ed25519 has been
    #: deliberately configured, which is not what an ordinary host looks like.
    HOST_KEY_TYPES = (
        ("ssh-ed25519", "ssh_host_ed25519_key"),
        ("ssh-rsa", "ssh_host_rsa_key"),
        ("ecdsa-sha2-nistp256", "ssh_host_ecdsa_key"),
    )

    def _host_keys(self) -> list[asyncssh.SSHKey]:
        """Load, or generate once and persist, the server host keys.

        Persisting matters: a host key that changes on every restart makes
        every returning client print a MITM warning, which is a louder
        giveaway than any banner.
        """
        key_dir = config.session_capture_dir
        os.makedirs(key_dir, exist_ok=True)

        keys = []
        for alg, filename in self.HOST_KEY_TYPES:
            keys.append(self._load_or_create_key(os.path.join(key_dir, filename), alg))
        return keys

    def _load_or_create_key(self, key_path: str, alg: str) -> asyncssh.SSHKey:
        if os.path.exists(key_path):
            try:
                return asyncssh.read_private_key(key_path)
            except Exception:
                logger.warning("Host key at %s unreadable; regenerating", key_path)

        # RSA at 3072 bits, matching what ssh-keygen -A produces since
        # OpenSSH 8.0. A 2048-bit key would be another small inconsistency.
        key = (
            asyncssh.generate_private_key(alg, key_size=3072)
            if alg == "ssh-rsa"
            else asyncssh.generate_private_key(alg)
        )
        try:
            with open(key_path, "wb") as handle:
                handle.write(key.export_private_key())
            os.chmod(key_path, 0o600)
        except OSError as exc:
            # A read-only container is expected; the key just won't persist.
            logger.warning("Could not persist SSH host key: %s", exc)
        return key

    async def start(self) -> None:
        # Banner and transport proposal come from one profile, not from two
        # independent choices. Vetterl and Clayton (USENIX WOOT '18)
        # fingerprint medium-interaction honeypots in a single packet by
        # comparing the KEXINIT an off-the-shelf library sends against the one
        # the claimed software actually sends; asyncssh's defaults offer 46 key
        # exchange algorithms, including GSSAPI and ML-KEM, where OpenSSH 8.2
        # offers nine. Pinning the proposal is what makes the banner true.
        profile = get_profile(config.ssh_profile)
        apply_extra_kex_algs(profile)

        self._acceptor = await asyncssh.listen(
            config.bind_address,
            self.port,
            server_factory=lambda: _HoneypotSSHServer(self),
            server_host_keys=self._host_keys(),
            process_factory=self._handle_process,
            server_version=profile.version_string,
            kex_algs=profile.kex_algs,
            encryption_algs=profile.encryption_algs,
            mac_algs=profile.mac_algs,
            compression_algs=profile.compression_algs,
            encoding=None,
        )
        self._running = True
        logger.info(
            "SSH honeypot listening on %s:%s as %s (profile %s)",
            config.bind_address,
            self.port,
            profile.version_string,
            profile.name,
        )

    async def stop(self) -> None:
        self._running = False
        if self._acceptor:
            self._acceptor.close()
            await self._acceptor.wait_closed()
        logger.info("SSH honeypot stopped")

    async def _handle_process(self, process: asyncssh.SSHServerProcess) -> None:
        conn = process.get_extra_info("connection")
        server: _HoneypotSSHServer = conn.get_extra_info("honeypot_server")
        state = server.state

        try:
            if process.command:
                # `ssh host 'command'` — how most automated campaigns arrive.
                # One shot: run it through the emulation layer and exit.
                await self._run_command(process, server, state, process.command)
            elif process.subsystem:
                await session_manager.record_network_event(
                    state.session_id,
                    "ssh_subsystem_request",
                    {"subsystem": process.subsystem},
                )
                process.stderr.write(b"subsystem request failed on channel 0\r\n")
                process.exit(1)
                return
            else:
                await self._interactive_shell(process, server, state)
        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
            pass
        except (BrokenPipeError, ConnectionResetError, asyncio.CancelledError):
            pass
        except Exception as exc:
            logger.error("SSH session error: %s", exc)
        finally:
            if not process.is_closing():
                process.exit(0)

    async def _run_command(self, process, server, state, command: str) -> None:
        command = command[:MAX_COMMAND_LENGTH]
        response = await self._dispatch(server, state, command)
        if response:
            process.stdout.write(response.encode())
        process.exit(0)

    async def _prompt(self, state) -> str:
        return await mode_handler.handle_interaction(
            state.session_id,
            "ssh",
            "prompt",
            {
                "username": state.username,
                "hostname": self._hostname,
                "cwd": state.cwd,
                "is_root": state.is_root,
            },
        )

    async def _interactive_shell(self, process, server, state) -> None:
        welcome = await mode_handler.handle_interaction(
            state.session_id,
            "ssh",
            "auth_success",
            {"source_ip": server.source_ip, "username": state.username},
        )
        if welcome:
            process.stdout.write(welcome.encode())
        process.stdout.write((await self._prompt(state)).encode())

        buffer = ""
        while not process.stdin.at_eof():
            try:
                data = await asyncio.wait_for(process.stdin.read(1024), timeout=300)
            except asyncio.TimeoutError:
                process.stdout.write(b"\r\nConnection timed out.\r\n")
                return
            except asyncssh.TerminalSizeChanged:
                continue

            if not data:
                return

            for char in data.decode("utf-8", errors="replace"):
                await session_manager.record_keystroke(state.session_id, char)

                if char in ("\r", "\n"):
                    process.stdout.write(b"\r\n")
                    command = buffer.strip()
                    buffer = ""
                    if not command:
                        process.stdout.write((await self._prompt(state)).encode())
                        continue

                    if command in ("exit", "logout"):
                        process.stdout.write(b"logout\r\n")
                        return

                    await self._run_interactive_command(process, server, state, command)
                    process.stdout.write((await self._prompt(state)).encode())

                elif char in ("\x7f", "\x08"):
                    if buffer:
                        buffer = buffer[:-1]
                        process.stdout.write(b"\x08 \x08")

                elif char == "\x04":  # Ctrl-D
                    return

                elif ord(char) >= 32:
                    if len(buffer) < MAX_COMMAND_LENGTH:
                        buffer += char
                        # Echo locally: the client is in raw mode and shows
                        # nothing unless the server sends it back.
                        process.stdout.write(char.encode())

    async def _run_interactive_command(self, process, server, state, command: str) -> None:
        response = await self._dispatch(server, state, command)
        if response:
            process.stdout.write(response.encode())

    async def _dispatch(self, server, state, command: str) -> str:
        """Run one command and record it with what it actually printed.

        Both call sites used to record the command with a hardcoded empty
        output before the emulator had produced one, so every stored session
        held commands with no responses. The transcript an analyst reads is
        half the evidence: what the attacker typed only means something beside
        what the machine appeared to tell them.
        """
        await adaptive_engine.profile_actor(
            state.session_id, server.source_ip, {"command": command}
        )
        payload = {
            "command": command,
            "username": state.username,
            "cwd": state.cwd,
            "is_root": state.is_root,
        }
        response = await mode_handler.handle_interaction(
            state.session_id, "ssh", "command", payload
        )
        # The emulator reports a directory change through the payload dict so
        # the prompt and later commands agree with it.
        if payload.get("cwd_after"):
            state.cwd = payload["cwd_after"]
        await session_manager.record_command(
            state.session_id, command, response or "", 0
        )
        return response
