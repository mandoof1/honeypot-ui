"""Telnet decoy.

The protocol most IoT botnets still arrive over, and the one gap the audit
put first. Mirai and its descendants log in with a short credential list,
probe the shell with ``/bin/busybox <APPLET>`` and then fetch a loader with
wget or tftp — exactly the behaviour the SSH shell already emulates. So this
is a thin transport: Telnet option negotiation and line discipline in front
of the same login policy and the same command dispatcher as SSH, which means
busybox probes, download events and shell-written files are captured the
same way, and a session's transcript looks the same to the analyst.

Negotiation is answered minimally and correctly. The server offers ECHO and
SUPPRESS-GO-AHEAD (character-at-a-time mode, as every telnetd does), refuses
every other option and swallows sub-negotiations. Anything else is a
fingerprint: a server that never negotiates looks like a netcat listener.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from honeypot.adaptive.response import adaptive_engine
from honeypot.capture.flow import FlowMeter
from honeypot.capture.shell_capture import capture_command, flush_session_files
from honeypot.capture.shell_writes import HeredocBuffer, needs_continuation
from honeypot.core.config import config
from honeypot.core.identity import get_identity
from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.core.shell_state import shell_states
from honeypot.emulators.base import BaseEmulator
from honeypot.emulators.ssh import (
    FAKE_USERS,
    MAX_AUTH_ATTEMPTS,
    MAX_COMMAND_LENGTH,
    SOFT_ACCEPT_AFTER,
    _failures_by_ip,
    _MAX_TRACKED_IPS,
)

logger = logging.getLogger(__name__)

DEFAULT_IDLE_TIMEOUT = 300
#: How long a client may sit at the login prompt.
LOGIN_TIMEOUT = 60

# Telnet protocol bytes (RFC 854/855/857/858).
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
NOP, DM, BRK, IP, AO, AYT, EC, EL, GA = 241, 242, 243, 244, 245, 246, 247, 248, 249
OPT_ECHO, OPT_SGA = 1, 3
#: Options the server itself provides. Everything else is refused.
SERVER_OPTIONS = {OPT_ECHO, OPT_SGA}
#: Options the client is allowed to turn on at its end.
CLIENT_OPTIONS = {OPT_SGA}


class TelnetLineReader:
    """Strips Telnet commands out of a byte stream and yields text lines.

    Keeps the half-parsed IAC sequence across reads, so a command split over
    two TCP segments is still handled. Replies to negotiation are queued on
    ``replies`` for the caller to send.
    """

    def __init__(self) -> None:
        self._state = "data"
        self._verb: Optional[int] = None
        self._sb = bytearray()
        self._pending_cr = False
        self.replies = bytearray()
        #: Options the client WILLs that we agreed to (currently only SGA).
        self.client_will: set[int] = set()
        self.negotiations: list[tuple[str, int]] = []

    def feed(self, data: bytes) -> bytes:
        """Return the data bytes with Telnet commands removed and CR
        sequences normalised to ``\\n``; negotiation replies accumulate."""
        out = bytearray()
        for byte in data:
            if self._state == "data":
                if byte == IAC:
                    self._state = "iac"
                elif self._pending_cr:
                    self._pending_cr = False
                    # CR LF and CR NUL both mean end of line; a bare CR
                    # followed by anything else is also a line end here.
                    out.append(10)
                    if byte not in (10, 0):
                        out.append(byte)
                elif byte == 13:
                    self._pending_cr = True
                else:
                    out.append(byte)
            elif self._state == "iac":
                if byte == IAC:
                    out.append(IAC)
                    self._state = "data"
                elif byte in (WILL, WONT, DO, DONT):
                    self._verb = byte
                    self._state = "opt"
                elif byte == SB:
                    self._sb = bytearray()
                    self._state = "sb"
                else:
                    # NOP, AYT, IP, BRK, EC, EL, GA, DM: two-byte commands.
                    if byte == AYT:
                        self.replies += b"\r\n[Yes]\r\n"
                    self._state = "data"
            elif self._state == "opt":
                self._negotiate(self._verb, byte)
                self._state = "data"
            elif self._state == "sb":
                if byte == IAC:
                    self._state = "sb_iac"
                else:
                    if len(self._sb) < 256:
                        self._sb.append(byte)
            elif self._state == "sb_iac":
                if byte == SE:
                    self._state = "data"
                    self.negotiations.append(("SB", self._sb[0] if self._sb else -1))
                else:
                    if len(self._sb) < 256:
                        self._sb.append(byte)
                    self._state = "sb"
        return bytes(out)

    def _negotiate(self, verb: int, option: int) -> None:
        name = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}[verb]
        self.negotiations.append((name, option))
        if verb == DO:
            # Client asks us to enable: agree only for what we provide. Our
            # own WILLs for ECHO/SGA are sent at connect, so a DO for those
            # needs no further answer.
            if option not in SERVER_OPTIONS:
                self.replies += bytes([IAC, WONT, option])
        elif verb == DONT:
            if option not in SERVER_OPTIONS:
                self.replies += bytes([IAC, WONT, option])
        elif verb == WILL:
            if option in CLIENT_OPTIONS:
                if option not in self.client_will:
                    self.client_will.add(option)
                    self.replies += bytes([IAC, DO, option])
            else:
                self.replies += bytes([IAC, DONT, option])
        elif verb == WONT:
            self.client_will.discard(option)
            self.replies += bytes([IAC, DONT, option])


class _TelnetState:
    def __init__(self) -> None:
        self.session_id: Optional[str] = None
        self.username: Optional[str] = None
        self.authenticated = False
        self.is_root = False
        self.cwd = "/home/user"
        self.auth_attempts = 0


class TelnetHoneypot(BaseEmulator):
    def __init__(self, port: Optional[int] = None):
        super().__init__("telnet", port if port is not None else config.telnet_port)

    def get_banner(self) -> str:
        identity = get_identity()
        return (
            f"\r\nUbuntu {identity.os_version} LTS\r\n"
            f"{identity.hostname} login: "
        )

    # ------------------------------------------------------------------
    # Transport helpers

    async def _write(self, writer: asyncio.StreamWriter, text: str | bytes) -> None:
        if isinstance(text, str):
            text = text.encode("utf-8", "replace")
        if text:
            writer.write(text)
            await writer.drain()

    async def _flush_replies(self, writer: asyncio.StreamWriter, parser: TelnetLineReader) -> None:
        if parser.replies:
            writer.write(bytes(parser.replies))
            parser.replies.clear()
            await writer.drain()

    async def _read_line(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        parser: TelnetLineReader,
        state: _TelnetState,
        buffer: bytearray,
        *,
        echo: bool,
        timeout: float,
    ) -> Optional[str]:
        """Read one line of input, handling echo and backspace.

        Returns None at EOF. ``buffer`` carries bytes that arrived after a
        previous line in the same segment.
        """
        deadline = time.monotonic() + timeout
        while True:
            newline = buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(buffer[:newline])
                del buffer[: newline + 1]
                return self._apply_backspaces(raw).decode("utf-8", "replace")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            data = await asyncio.wait_for(reader.read(1024), timeout=remaining)
            if not data:
                return None
            text = parser.feed(data)
            await self._flush_replies(writer, parser)
            if state.session_id:
                for ch in text.decode("utf-8", "replace"):
                    await session_manager.record_keystroke(state.session_id, ch)
            if echo:
                # Character-at-a-time clients show nothing unless we echo;
                # a line-mode client sends whole lines, echoing those back
                # produces a double line, so only echo when the client
                # agreed to SGA (character mode) — the usual case.
                echoed = bytearray()
                for b in text:
                    if b == 10:
                        echoed += b"\r\n"
                    elif b in (8, 127):
                        echoed += b"\x08 \x08"
                    elif b >= 32:
                        echoed.append(b)
                if echoed and OPT_SGA in parser.client_will:
                    await self._write(writer, bytes(echoed))
            buffer += text
            if len(buffer) > MAX_COMMAND_LENGTH:
                del buffer[: len(buffer) - MAX_COMMAND_LENGTH]

    @staticmethod
    def _apply_backspaces(raw: bytes) -> bytes:
        out = bytearray()
        for b in raw:
            if b in (8, 127):
                if out:
                    out.pop()
            elif b >= 32 or b == 9:
                out.append(b)
        return bytes(out)

    # ------------------------------------------------------------------
    # Login

    def _check_credentials(self, source_ip: str, username: str, password: str) -> bool:
        """The SSH decoy's policy: the weak credential, or persistence."""
        prior_failures = _failures_by_ip.get(source_ip, 0)
        expected = FAKE_USERS.get(username)
        accepted = expected is not None and (
            password == expected or prior_failures >= SOFT_ACCEPT_AFTER
        )
        if not accepted:
            if len(_failures_by_ip) >= _MAX_TRACKED_IPS:
                _failures_by_ip.clear()
            _failures_by_ip[source_ip] = prior_failures + 1
        else:
            _failures_by_ip.pop(source_ip, None)
        return accepted

    async def _login(self, reader, writer, parser, state, buffer, source_ip) -> bool:
        await self._write(writer, self.get_banner())
        while state.auth_attempts < MAX_AUTH_ATTEMPTS:
            username = await self._read_line(
                reader, writer, parser, state, buffer, echo=True, timeout=LOGIN_TIMEOUT
            )
            if username is None:
                return False
            username = username.strip()[:64]
            if not username:
                await self._write(writer, f"{get_identity().hostname} login: ")
                continue
            # Password is not echoed; the server stays in ECHO mode and
            # simply prints nothing, as telnetd does.
            await self._write(writer, "Password: ")
            password = await self._read_line(
                reader, writer, parser, state, buffer, echo=False, timeout=LOGIN_TIMEOUT
            )
            if password is None:
                return False
            password = password[:256]
            await self._write(writer, "\r\n")
            state.auth_attempts += 1
            accepted = self._check_credentials(source_ip, username, password)
            await session_manager.record_auth_attempt(
                state.session_id, username, password, accepted
            )
            if accepted:
                state.username = username
                state.authenticated = True
                if username == "root":
                    state.is_root = True
                    state.cwd = "/root"
                    shell_states.get(state.session_id).cwd = "/root"
                await adaptive_engine.profile_actor(
                    state.session_id, source_ip,
                    {"auth_success": True, "username": username, "protocol": "telnet"},
                )
                return True
            # Real login(1) pauses before refusing.
            await asyncio.sleep(1.0 if config.enable_anti_fingerprinting else 0)
            await self._write(writer, f"\r\nLogin incorrect\r\n{get_identity().hostname} login: ")
        await self._write(writer, "\r\nMaximum number of tries exceeded (6)\r\n")
        return False

    # ------------------------------------------------------------------
    # Shell

    async def _prompt(self, state) -> str:
        return await mode_handler.handle_interaction(
            state.session_id, "ssh", "prompt",
            {"username": state.username, "cwd": state.cwd, "is_root": state.is_root},
        )

    async def _dispatch(self, source_ip: str, state: _TelnetState, command: str) -> str:
        """One command through the same path as the SSH shell."""
        await adaptive_engine.profile_actor(state.session_id, source_ip, {"command": command})
        await capture_command(
            state.session_id, command, "/root" if state.is_root else "/home/user"
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
        if payload.get("cwd_after"):
            state.cwd = payload["cwd_after"]
        await session_manager.record_command(state.session_id, command, response or "", 0)
        return response or ""

    async def _shell(self, reader, writer, parser, state, buffer, source_ip) -> None:
        welcome = await mode_handler.handle_interaction(
            state.session_id, "ssh", "auth_success",
            {"source_ip": source_ip, "username": state.username},
        )
        if welcome:
            await self._write(writer, welcome.replace("\n", "\r\n"))
        await self._write(writer, await self._prompt(state))
        idle_timeout = config.connection_timeout or DEFAULT_IDLE_TIMEOUT
        pending: Optional[HeredocBuffer] = None
        while True:
            try:
                line = await self._read_line(
                    reader, writer, parser, state, buffer, echo=True, timeout=idle_timeout
                )
            except asyncio.TimeoutError:
                await self._write(writer, "\r\nConnection timed out.\r\n")
                return
            if line is None:
                return
            if pending is not None:
                pending.feed(line)
                if pending.open:
                    await self._write(writer, "> ")
                    continue
                command, pending = pending.text(), None
            else:
                command = line.strip()
                if command and needs_continuation(command):
                    pending = HeredocBuffer(command, MAX_COMMAND_LENGTH)
                    await self._write(writer, "> ")
                    continue
            if not command:
                await self._write(writer, await self._prompt(state))
                continue
            if command in ("exit", "logout"):
                await self._write(writer, "logout\r\n")
                return
            response = await self._dispatch(source_ip, state, command)
            if response:
                await self._write(writer, response.replace("\r\n", "\n").replace("\n", "\r\n"))
            await self._write(writer, await self._prompt(state))

    # ------------------------------------------------------------------

    async def _observe_passively(self, session_id: str, reader: asyncio.StreamReader) -> None:
        await session_manager.record_network_event(
            session_id, "passive_observation", {"protocol": "telnet", "responded": False}
        )
        parser = TelnetLineReader()
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=15)
        except (asyncio.TimeoutError, ConnectionError, ValueError):
            data = b""
        text = parser.feed(data).decode("utf-8", "replace")
        for line in text.splitlines()[:20]:
            if line.strip():
                await session_manager.record_command(
                    session_id, line.strip(), output="(passive: no response sent)"
                )

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        source_ip, source_port = self._get_peer_info(writer)
        flow = FlowMeter.for_stream(reader, writer)
        logger.info("Telnet connection from %s:%s", source_ip, source_port)

        if not await self._check_rate_limit(source_ip):
            writer.close()
            await writer.wait_closed()
            return

        session_id = await session_manager.create_session(
            "telnet", source_ip, source_port, flow=flow
        )
        state = _TelnetState()
        state.session_id = session_id
        parser = TelnetLineReader()
        buffer = bytearray()
        try:
            if mode_handler.is_passive():
                await self._observe_passively(session_id, reader)
                return

            # Offer character-at-a-time mode like every telnetd, and ask the
            # client to suppress go-ahead too.
            await self._write(writer, bytes([IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA, IAC, DO, OPT_SGA]))
            await session_manager.record_network_event(
                session_id, "telnet_banner_sent", {"banner": get_identity().hostname}
            )
            try:
                if not await self._login(reader, writer, parser, state, buffer, source_ip):
                    return
            except asyncio.TimeoutError:
                await self._write(writer, "\r\nLogin timed out after 60 seconds\r\n")
                return
            if parser.negotiations:
                await session_manager.record_network_event(
                    session_id, "telnet_negotiation",
                    {"options": [f"{verb} {opt}" for verb, opt in parser.negotiations[:20]]},
                )
            await self._shell(reader, writer, parser, state, buffer, source_ip)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError) as exc:
            logger.debug("Telnet connection from %s ended: %s", source_ip, exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Telnet session error from %s: %s", source_ip, exc, exc_info=True)
        finally:
            try:
                await flush_session_files(session_id, shell_states.get(session_id))
            except Exception as exc:
                logger.warning("Telnet file flush failed for %s: %s", session_id, exc)
            await session_manager.end_session(session_id)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
