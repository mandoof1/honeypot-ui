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
import hashlib
import logging
import os
import struct
from typing import Optional

import asyncssh

from honeypot.capture.flow import FlowMeter
from honeypot.capture.sftp import DecoySFTPServer, wait_for_transfers
from honeypot.capture.shell_capture import flush_session_files
from honeypot.capture.shell_writes import HeredocBuffer, needs_continuation
from honeypot.core import shell_dispatch
from honeypot.core.config import config
from honeypot.core.login_policy import FAKE_USERS, SOFT_ACCEPT_AFTER, login_policy  # noqa: F401 - re-exported
from honeypot.core.session import session_manager
from honeypot.core.shell_dispatch import LineEditor
from honeypot.core.shell_state import shell_states
from honeypot.adaptive.ssh_profile import apply_extra_kex_algs, apply_host_key_algs, get_profile
from honeypot.core.modes import mode_handler
from honeypot.emulators.base import BaseEmulator
from honeypot.adaptive.fingerprint import fingerprint_engine
from honeypot.adaptive.response import adaptive_engine
from honeypot.security.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

#: Longest command line accepted. This was 4096, which cut base64 one-liners
#: off mid-payload: the part of the line that mattered most was the part
#: thrown away. An exec request has to fit in one SSH packet anyway, so this
#: mainly bounds what an interactive session can accumulate.
MAX_COMMAND_LENGTH = 256 * 1024
MAX_AUTH_ATTEMPTS = 6

#: Failed attempts per source address; the login policy owns it. Kept under
#: this name because the Telnet decoy and the tests reach it here.
_failures_by_ip = login_policy.failures
_MAX_TRACKED_IPS = 4096

#: Session-closing tasks spawned from connection_lost. asyncio keeps only a
#: weak reference to a task, so an unreferenced one can be collected before
#: it runs — and these are the tasks that flush captured files and deliver
#: the session.
_close_tasks: set[asyncio.Task] = set()

#: Default idle timeout for an interactive shell when HONEYPOT_CONN_TIMEOUT
#: is unset.
DEFAULT_IDLE_TIMEOUT = 300

#: Port-forward requests recorded per connection. A client using the decoy
#: as a proxy sends thousands; the first few dozen destinations say what it
#: is for.
MAX_FORWARD_EVENTS = 64


def kexinit_name_lists(payload: bytes) -> Optional[list[str]]:
    """The ten name-lists of an SSH_MSG_KEXINIT payload, or None if malformed."""
    if len(payload) < 17 or payload[0] != 20:
        return None
    offset = 17  # message type and the 16-byte cookie
    lists: list[str] = []
    for _ in range(10):
        if offset + 4 > len(payload):
            return None
        (length,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        if length > 65536 or offset + length > len(payload):
            return None
        lists.append(payload[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return lists


def hassh(payload: bytes, server: bool = False) -> Optional[tuple[str, str]]:
    """(digest, algorithm string) for a KEXINIT: HASSH, or hasshServer.

    HASSH is the MD5 of ``kex;encryption;mac;compression`` — the
    client-to-server lists for a client's KEXINIT, the server-to-client lists
    for a server's. It identifies the SSH *implementation* behind a
    connection, and so survives a change of address or credentials.
    """
    lists = kexinit_name_lists(payload)
    if lists is None:
        return None
    # Name-list order in KEXINIT: kex, host key, enc c2s, enc s2c, mac c2s,
    # mac s2c, compression c2s, compression s2c, languages c2s, languages s2c.
    chosen = (lists[0], lists[3], lists[5], lists[7]) if server else (lists[0], lists[2], lists[4], lists[6])
    algorithms = ";".join(chosen)
    return hashlib.md5(algorithms.encode("ascii", "replace")).hexdigest(), algorithms


class _SessionState:
    def __init__(self) -> None:
        self.session_id: Optional[str] = None
        self.username: Optional[str] = None
        self.authenticated = False
        self.is_root = False
        self.cwd = "/home/user"
        self.auth_attempts = 0
        #: Exit status of the last command, which is the channel's.
        self.exit_status = 0


async def _close_session(session_id: str, shell) -> None:
    """Record what the session wrote, then end it — whatever goes wrong.

    Each step used to follow the last with nothing guarding it, so an OSError
    while flushing a file skipped ``end_session`` and the session was never
    delivered at all.
    """
    try:
        await wait_for_transfers(session_id)
        await flush_session_files(session_id, shell)
    except Exception as exc:
        logger.warning("Could not flush files for session %s: %s", session_id, exc)
    finally:
        await session_manager.end_session(session_id)


class _HoneypotSSHServer(asyncssh.SSHServer):
    """Per-connection handler: capture the peer, then the auth attempts."""

    def __init__(self, emulator: "SSHHoneypot") -> None:
        self._emulator = emulator
        self.state = _SessionState()
        self.source_ip = "0.0.0.0"
        self.source_port = 0
        self.flow: Optional[FlowMeter] = None
        self.admitted = False
        self.connected_at = 0.0
        self._conn: Optional[asyncssh.SSHServerConnection] = None
        self._expiry: Optional[asyncio.TimerHandle] = None
        self._forward_events = 0
        self._tasks: set[asyncio.Task] = set()

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        if peer:
            self.source_ip, self.source_port = peer[0], peer[1]
        self._conn = conn
        loop = asyncio.get_running_loop()
        self.connected_at = loop.time()
        conn.set_extra_info(honeypot_server=self)
        # Admission before the key exchange: a blocked or over-quota address
        # used to be refused only in begin_auth, after it had cost a full KEX
        # on the event loop.
        self.admitted = rate_limiter.admit(self.source_ip, protocol="ssh")
        if not self.admitted:
            logger.warning("SSH connection from %s refused at accept", self.source_ip)
            conn.abort()
            return
        self._emulator.track(conn)
        # The session cap belongs to the connection, not to a channel. It was
        # enforced only around a shell or exec, so a client that authenticated
        # and then sat idle, or opened nothing but SFTP, held its slot — and
        # its undelivered session — for as long as it liked.
        self._expiry = loop.call_later(config.max_session_seconds, self._expire)
        # Before asyncssh sends its version string, so the key exchange is
        # counted too.
        self.flow = FlowMeter.for_ssh(conn)

    def _expire(self) -> None:
        if self._conn is not None:
            logger.info(
                "SSH connection from %s closed: over the %ss session limit",
                self.source_ip, config.max_session_seconds,
            )
            self._conn.close()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._expiry is not None:
            self._expiry.cancel()
            self._expiry = None
        if self.admitted:
            rate_limiter.release(self.source_ip)
            self.admitted = False
        if self._conn is not None:
            self._emulator.untrack(self._conn)
        if self.state.session_id:
            # connection_lost is synchronous; hand the close off to the loop.
            # The shell state is taken *now*, before anything else can drop
            # it: it holds the content of every file the session wrote, and
            # the session must not be finalised until those are recorded.
            shell = shell_states.pop(self.state.session_id)
            task = asyncio.create_task(_close_session(self.state.session_id, shell))
            _close_tasks.add(task)
            task.add_done_callback(_close_tasks.discard)

    def seconds_left(self) -> float:
        """Time remaining before the connection hits the session cap."""
        elapsed = asyncio.get_running_loop().time() - self.connected_at
        return max(0.0, config.max_session_seconds - elapsed)

    async def begin_auth(self, username: str) -> bool:
        """Open the session here — the first point with a username and a loop.

        Returning True always requires authentication; a decoy that accepted
        an empty auth would never see the credentials that are the most
        valuable thing an SSH honeypot collects.
        """
        if self.state.session_id is None:
            if not self.admitted or not await self._emulator.rate_limit_ok(self.source_ip):
                logger.warning("SSH rate limit exceeded for %s", self.source_ip)
                raise asyncssh.DisconnectError(
                    asyncssh.DISC_TOO_MANY_CONNECTIONS, "Too many connections"
                )
            self.state.session_id = await session_manager.create_session(
                "ssh", self.source_ip, self.source_port, {"protocol_version": "SSH-2.0"},
                flow=self.flow,
            )
            await session_manager.record_network_event(
                self.state.session_id,
                "ssh_client_banner",
                {"banner": self._client_version()},
            )
            await self._record_fingerprints()
        return True

    def _client_version(self) -> str:
        """The client's identification string, as it sent it."""
        version = self._conn.get_extra_info("client_version") if self._conn else None
        if not version:
            return "unknown"
        version = str(version)
        return (version if version.startswith("SSH-") else "SSH-2.0-" + version)[:255]

    async def _record_fingerprints(self) -> None:
        """Note what identifies the client's software, from the key exchange.

        The key exchange is over by the time authentication starts, so both
        KEXINIT packets are there to read. They are asyncssh's private
        attributes; if a later release renames them the fingerprint is simply
        absent, and the session is otherwise unaffected.
        """
        session = await session_manager.get_session(self.state.session_id)
        if session is None or self._conn is None:
            return
        version = self._client_version()
        if version != "unknown":
            session.fingerprints["ssh_client_version"] = version
        try:
            client = hassh(bytes(getattr(self._conn, "_client_kexinit", b"") or b""))
            server = hassh(bytes(getattr(self._conn, "_server_kexinit", b"") or b""), server=True)
        except Exception as exc:  # pragma: no cover - defensive against asyncssh internals
            logger.debug("Could not read KEXINIT for %s: %s", self.source_ip, exc)
            return
        if client is not None:
            session.fingerprints["hassh"], session.fingerprints["hassh_algorithms"] = client[0], client[1][:2048]
        if server is not None:
            session.fingerprints["hassh_server"] = server[0]

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

        The decision is the login policy's (``core/login_policy.py``): the
        weak credential the decoy advertises for that user, persistence, a
        credential this source was let in with before, or the planted one.

        Letting every password through on the first attempt (the original
        behaviour) is its own tell: real systems do not accept ``root`` with
        one random guess, and a brute-forcer that succeeds instantly learns it
        is talking to a decoy. Making it work only after a few failures keeps
        the credential list being recorded, and still gets the attacker to the
        far more valuable part — what they type once they are in.
        """
        state = self.state
        state.auth_attempts += 1
        state.username = username

        accepted = login_policy.check(self.source_ip, username, password)
        await session_manager.record_auth_attempt(
            state.session_id, username, password, accepted
        )

        if accepted:
            state.authenticated = True
            state.is_root = username == "root"
            # Each account starts in its own home, and the emulator's view of
            # the shell is set to match, or `pwd` and the prompt disagree from
            # the first command.
            state.cwd = shell_dispatch.start_shell(
                state.session_id, username, state.is_root, self.source_ip, self.source_port
            )
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

    # -- forwarding ----------------------------------------------------------

    def _note(self, event_type: str, details: dict) -> None:
        """Record an event from a synchronous asyncssh callback."""
        if not self.state.session_id or self._forward_events >= MAX_FORWARD_EVENTS:
            return
        self._forward_events += 1
        task = asyncio.ensure_future(
            session_manager.record_network_event(self.state.session_id, event_type, details)
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def connection_requested(self, dest_host: str, dest_port: int, orig_host: str, orig_port: int):
        """A ``direct-tcpip`` channel: the client wants the decoy to dial out.

        This is how compromised SSH hosts are used as proxies, and it was
        invisible: asyncssh's default refused the channel and nothing was
        written down. The destination is what matters — it is where the
        client's real traffic was headed — so it is recorded, and the channel
        is then refused the way sshd refuses it when forwarding is switched
        off. Nothing is ever dialled.
        """
        self._note("direct_tcpip", {
            "dest_host": str(dest_host)[:255],
            "dest_port": int(dest_port),
            "orig_host": str(orig_host)[:255],
            "orig_port": int(orig_port),
        })
        raise asyncssh.ChannelOpenError(
            asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED, "open failed"
        )

    def server_requested(self, listen_host: str, listen_port: int):
        """A ``tcpip-forward`` request: listen here and send it back. Refused."""
        self._note("ssh_tcpip_forward", {
            "listen_host": str(listen_host)[:255], "listen_port": int(listen_port),
        })
        return False


class SSHHoneypot(BaseEmulator):
    """Real SSH transport in front of the existing emulation layer."""

    def __init__(self) -> None:
        super().__init__("ssh", config.ssh_port)
        self._hostname = fingerprint_engine.get_fake_hostname()
        self._acceptor: Optional[asyncssh.SSHAcceptor] = None
        self._connections: set[asyncssh.SSHServerConnection] = set()

    def track(self, conn: asyncssh.SSHServerConnection) -> None:
        self._connections.add(conn)

    def untrack(self, conn: asyncssh.SSHServerConnection) -> None:
        self._connections.discard(conn)

    @property
    def active_connections(self) -> int:
        return len(self._connections)

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
        apply_host_key_algs(profile)

        self._acceptor = await asyncssh.listen(
            config.bind_address,
            self.port,
            server_factory=lambda: _HoneypotSSHServer(self),
            server_host_keys=self._host_keys(),
            process_factory=self._handle_process,
            # sftp and scp uploads land in an in-memory filesystem and are
            # captured; see capture/sftp.py. Refusing the subsystem, as this
            # used to, is not what a stock sshd does.
            sftp_factory=DecoySFTPServer,
            allow_scp=True,
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
        # The acceptor only stops listening; open connections used to live
        # on until the process was killed, which skipped their session close
        # and lost whatever they had captured.
        for conn in list(self._connections):
            try:
                conn.close()
            except Exception:
                pass
        pending = list(_close_tasks)
        if pending:
            await asyncio.wait(pending, timeout=5)
        logger.info("SSH honeypot stopped")

    # -- channels ------------------------------------------------------------

    async def _write(self, process, text: str, pty: bool) -> None:
        """Send output and wait for the client to take it.

        Writing without draining let a client that had stopped reading make
        the engine buffer everything it produced; the drain is what turns
        that into the client's problem instead of the engine's memory.
        """
        if not text:
            return
        process.stdout.write(shell_dispatch.encode(text, pty))
        await process.stdout.drain()

    async def _handle_process(self, process: asyncssh.SSHServerProcess) -> None:
        conn = process.get_extra_info("connection")
        server: _HoneypotSSHServer = conn.get_extra_info("honeypot_server")
        state = server.state

        try:
            # The whole channel, exec or shell, lives within the session cap.
            await asyncio.wait_for(
                self._serve_process(process, server, state), timeout=server.seconds_left()
            )
        except asyncio.TimeoutError:
            try:
                process.stdout.write(b"\r\nConnection closed by remote host.\r\n")
            except Exception:
                pass
        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
            pass
        except (BrokenPipeError, ConnectionResetError, asyncio.CancelledError):
            pass
        except Exception as exc:
            logger.error("SSH session error: %s", exc, exc_info=True)
        finally:
            if not process.is_closing():
                process.exit(state.exit_status & 0xFF)

    async def _serve_process(self, process, server, state) -> None:
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
                state.exit_status = 1
                return
            elif process.get_terminal_type() is None:
                await self._script_shell(process, server, state)
            else:
                await self._interactive_shell(process, server, state)
        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
            pass

    async def _dispatch(self, server, state, command: str, pty: bool) -> str:
        response, state.exit_status = await shell_dispatch.run_command(
            state.session_id, server.source_ip, state, command, pty
        )
        return response

    async def _run_command(self, process, server, state, command: str) -> None:
        command = command[:MAX_COMMAND_LENGTH]
        pty = process.get_terminal_type() is not None
        response = await self._dispatch(server, state, command, pty)
        await self._write(process, response, pty)

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

    def _leaves_shell(self, state, command: str) -> bool:
        """Whether ``command`` is an ``exit`` that ends the session.

        Sets the exit status it asks for. An ``exit`` typed inside a nested
        ``bash`` only leaves that.
        """
        status = shell_dispatch.parse_exit(command, state.exit_status)
        if status is None:
            return False
        shell = shell_states.get(state.session_id)
        if shell.subshells > 0:
            shell.subshells -= 1
            return False
        state.exit_status = status
        return True

    async def _script_shell(self, process, server, state) -> None:
        """A shell with no terminal: ``ssh host < script`` or ``ssh -T``.

        sshd runs the login shell non-interactively here, so there is no
        banner, no prompt and no echo — only what the commands print. Sending
        a MOTD and a prompt into a pipe, as this used to, is something a
        client reading that pipe notices at once.
        """
        buffer = ""
        pending: Optional[HeredocBuffer] = None
        idle_timeout = config.connection_timeout or DEFAULT_IDLE_TIMEOUT
        at_eof = False
        while not at_eof:
            try:
                data = await asyncio.wait_for(process.stdin.read(4096), timeout=idle_timeout)
            except asyncio.TimeoutError:
                return
            except asyncssh.TerminalSizeChanged:
                continue
            if data:
                text = data.decode("utf-8", errors="replace")
                session = await session_manager.get_session(state.session_id)
                if session is not None:
                    session.keystroke_total += len(text)
                buffer += text
            else:
                at_eof = True
                if buffer and not buffer.endswith("\n"):
                    buffer += "\n"
            if len(buffer) > 4 * MAX_COMMAND_LENGTH:
                buffer = buffer[-4 * MAX_COMMAND_LENGTH:]

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.rstrip("\r")[:MAX_COMMAND_LENGTH]
                if pending is not None:
                    # Inside a heredoc: the line is content, whitespace and
                    # all, until the delimiter closes it.
                    pending.feed(line)
                    if pending.open:
                        continue
                    command, pending = pending.text(), None
                else:
                    command = line.strip()
                    if command and needs_continuation(command):
                        # bash keeps reading until the heredoc closes.
                        pending = HeredocBuffer(command, MAX_COMMAND_LENGTH)
                        continue
                if not command:
                    continue
                if self._leaves_shell(state, command):
                    return
                await self._write(process, await self._dispatch(server, state, command, False), False)
        if pending is not None:
            # The input ended inside a heredoc: run what there is of it.
            await self._write(process, await self._dispatch(server, state, pending.text(), False), False)

    async def _interactive_shell(self, process, server, state) -> None:
        welcome = await mode_handler.handle_interaction(
            state.session_id,
            "ssh",
            "auth_success",
            {"source_ip": server.source_ip, "username": state.username},
        )
        await self._write(process, (welcome or "") + await self._prompt(state), True)

        shell = shell_states.get(state.session_id)
        editor = LineEditor(MAX_COMMAND_LENGTH, shell.history)
        #: Lines of a heredoc still waiting for their delimiter.
        pending: Optional[HeredocBuffer] = None
        idle_timeout = config.connection_timeout or DEFAULT_IDLE_TIMEOUT
        while not process.stdin.at_eof():
            try:
                data = await asyncio.wait_for(process.stdin.read(1024), timeout=idle_timeout)
            except asyncio.TimeoutError:
                process.stdout.write(b"\r\nConnection timed out.\r\n")
                return
            except asyncssh.TerminalSizeChanged:
                continue

            if not data:
                return

            echo = bytearray()
            for char in data.decode("utf-8", errors="replace"):
                await session_manager.record_keystroke(state.session_id, char)
                # Echo locally: the client is in raw mode and shows nothing
                # unless the server sends it back.
                echoed, event = editor.feed(char)
                echo += echoed
                if event is None:
                    continue
                process.stdout.write(bytes(echo))
                echo.clear()
                kind, line = event

                if kind == "eof":
                    process.stdout.write(b"logout\r\n")
                    return
                if kind == "interrupt":
                    # Ctrl-C abandons the line, and a heredoc being typed.
                    pending = None
                    await self._write(process, await self._prompt(state), True)
                    continue
                if kind == "redraw":
                    await self._write(process, await self._prompt(state) + editor.buffer, True)
                    continue

                if pending is not None:
                    # Inside a heredoc: the line is content, whitespace
                    # and all, until the delimiter closes it. Each line
                    # is checked against the delimiter owed, not re-lexed
                    # with everything before it.
                    pending.feed(line)
                    if pending.open:
                        process.stdout.write(b"> ")
                        continue
                    command, pending = pending.text(), None
                else:
                    command = line.strip()
                    if command and needs_continuation(command):
                        # bash keeps reading until the heredoc closes.
                        pending = HeredocBuffer(command, MAX_COMMAND_LENGTH)
                        process.stdout.write(b"> ")
                        continue
                if not command:
                    await self._write(process, await self._prompt(state), True)
                    continue

                if shell_dispatch.parse_exit(command, 0) is not None:
                    nested = shell.subshells > 0
                    if self._leaves_shell(state, command):
                        process.stdout.write(b"logout\r\n")
                        return
                    if nested:
                        await self._write(process, "exit\n" + await self._prompt(state), True)
                        continue

                response = await self._dispatch(server, state, command, True)
                await self._write(process, response + await self._prompt(state), True)
            if echo:
                process.stdout.write(bytes(echo))
                await process.stdout.drain()
