"""Telnet decoy.

The protocol most IoT botnets still arrive over, and the one gap the audit
put first. Mirai and its descendants log in with a short credential list,
probe the shell with ``/bin/busybox <APPLET>`` and then fetch a loader with
wget or tftp — exactly the behaviour the SSH shell already emulates. So this
is a thin transport: Telnet option negotiation and line discipline in front
of the same login policy and the same command dispatcher as SSH, which means
busybox probes, download events and shell-written files are captured the
same way, and a session's transcript looks the same to the analyst.

Negotiation follows the telnetd of Ubuntu 20.04, option for option, because
the opening exchange is the first thing a scanner sees and it arrives before
any login. The sequences are the ones recorded from the real daemon in
docs/evaluation/fingerprint/1-baseline/telnet-telnetd-focal.json: four requests
first, nothing more until the client has answered them, then five more, then
ECHO and the banner. Options the server neither asked for nor offered are
refused, and sub-negotiations are swallowed.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Optional

from honeypot.adaptive.response import adaptive_engine
from honeypot.capture.flow import FlowMeter
from honeypot.capture.shell_capture import flush_session_files
from honeypot.capture.shell_writes import HeredocBuffer, needs_continuation
from honeypot.core import shell_dispatch
from honeypot.core.config import config
from honeypot.core.identity import get_identity
from honeypot.core.login_delay import login_delay
from honeypot.core.login_policy import login_policy
from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.core.shell_state import shell_states
from honeypot.emulators.base import BaseEmulator
from honeypot.emulators.ssh import (
    FAKE_USERS,
    MAX_COMMAND_LENGTH,
    SOFT_ACCEPT_AFTER,
    _failures_by_ip,
    _MAX_TRACKED_IPS,
)

logger = logging.getLogger(__name__)

DEFAULT_IDLE_TIMEOUT = 300
#: How long a client may sit at the login prompt, or leave the opening
#: negotiation unanswered.
LOGIN_TIMEOUT = 60
#: Wrong passwords before login(1) hangs up. The reference closed after the
#: fifth with "Maximum number of tries exceeded (5)".
MAX_LOGIN_TRIES = 5

# Telnet protocol bytes (RFC 854/855/857/858).
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
NOP, DM, BRK, IP, AO, AYT, EC, EL, GA = 241, 242, 243, 244, 245, 246, 247, 248, 249
OPT_ECHO, OPT_SGA, OPT_STATUS = 1, 3, 5
OPT_TTYPE, OPT_NAWS, OPT_TSPEED, OPT_LFLOW, OPT_XDISPLOC, OPT_NEW_ENVIRON = 24, 31, 32, 33, 35, 39
#: What telnetd sends the moment a client connects, in this order. It sends
#: nothing else, not even the banner, until every one has been answered: the
#: reference's whole output to a client that says nothing is these four.
OPENING_REQUESTS = (OPT_TTYPE, OPT_TSPEED, OPT_XDISPLOC, OPT_NEW_ENVIRON)
#: What follows once they are answered, in the reference's order: WILL
#: SUPPRESS-GO-AHEAD, DO ECHO, DO NAWS, WILL STATUS, DO REMOTE-FLOW-CONTROL.
#: telnetd then waits for the answer about the window size.
SECOND_REQUESTS = (
    (WILL, OPT_SGA),
    (DO, OPT_ECHO),
    (DO, OPT_NAWS),
    (WILL, OPT_STATUS),
    (DO, OPT_LFLOW),
)
#: Options the server itself provides. Everything else is refused.
SERVER_OPTIONS = {OPT_ECHO, OPT_SGA}
#: Options the client is allowed to turn on at its end.
CLIENT_OPTIONS = {OPT_SGA}

#: Terminal escape sequences a character-mode client sends for arrow and
#: function keys. They are keystrokes, not text: left in, an up-arrow became
#: ``[A`` in the command line and in the echo.
_ESCAPE_SEQUENCE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z~]|\x1bO[A-Za-z]|\x1b.?")
#: Option negotiations kept as the client's fingerprint.
MAX_FINGERPRINT_OPTIONS = 32


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
        #: The byte after a CR is its LF or NUL partner and is dropped.
        self._after_cr = False
        self.replies = bytearray()
        #: Options the client WILLs that we agreed to (currently only SGA).
        self.client_will: set[int] = set()
        self.negotiations: list[tuple[str, int]] = []
        #: Options this side asked the client to turn on (DO) and offered to
        #: turn on itself (WILL). What the client says about one of those is
        #: an answer to us, not a request, and gets no reply.
        self.asked: set[int] = set()
        self.offered: set[int] = set()
        #: The client's answer to each DO: True for WILL, False for WONT.
        self.answers: dict[int, bool] = {}
        self._sga_offered_again = False

    def request(self, verb: int, option: int) -> bytes:
        """The bytes of a DO or WILL this side sends, noted so that the
        client's answer to it is recognised as one."""
        (self.asked if verb == DO else self.offered).add(option)
        return bytes([IAC, verb, option])

    def feed(self, data: bytes) -> bytes:
        """Return the data bytes with Telnet commands removed and CR
        sequences normalised to ``\\n``; negotiation replies accumulate."""
        out = bytearray()
        for byte in data:
            if self._state == "data":
                if byte == IAC:
                    self._state = "iac"
                elif self._after_cr and byte in (10, 0):
                    # CR LF and CR NUL both mean end of line, and the CR has
                    # already ended it.
                    self._after_cr = False
                elif byte == 13:
                    # The line ends at the CR, not at whatever follows it.
                    # Waiting for the next byte to decide left a client that
                    # sends a bare CR — and many bots do — staring at a shell
                    # that never ran its command.
                    self._after_cr = True
                    out.append(10)
                else:
                    self._after_cr = False
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
            # Client asks us to enable: agree only for what we provide. A DO
            # for something we offered with WILL is the client accepting, and
            # needs no further answer.
            if option not in SERVER_OPTIONS and option not in self.offered:
                self.replies += bytes([IAC, WONT, option])
        elif verb == DONT:
            if option == OPT_SGA and option in self.offered:
                # telnetd does not take the first no for SUPPRESS-GO-AHEAD:
                # the reference offered it a second time to a client that
                # refused it, and let the second refusal stand.
                if not self._sga_offered_again:
                    self._sga_offered_again = True
                    self.replies += bytes([IAC, WILL, OPT_SGA])
            elif option not in SERVER_OPTIONS and option not in self.offered:
                self.replies += bytes([IAC, WONT, option])
        elif verb == WILL and option in self.asked:
            # The answer to our DO. Nothing to add: the reference sent no
            # reply to any of them.
            self.answers[option] = True
        elif verb == WONT and option in self.asked:
            self.answers[option] = False
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
        # No blank line first: the reference's banner starts at "Ubuntu".
        return (
            f"Ubuntu {identity.os_version} LTS\r\n"
            f"{identity.hostname} login: "
        )

    # ------------------------------------------------------------------
    # Transport helpers

    async def _write(self, writer: asyncio.StreamWriter, text: str | bytes) -> None:
        if isinstance(text, str):
            # Bytes a command printed (a binary read with cat) travel inside
            # the text as surrogates and go out as the bytes they were.
            text = text.encode("utf-8", "surrogateescape")
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
                if b"\x03" in raw:
                    # Ctrl-C: the line is abandoned.
                    return ""
                if raw == b"\x04":
                    # Ctrl-D on an empty line: end of input.
                    return None
                return self._apply_backspaces(raw).decode("utf-8", "replace")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            data = await asyncio.wait_for(reader.read(1024), timeout=remaining)
            if not data:
                return None
            text = _ESCAPE_SEQUENCE.sub(b"", parser.feed(data))
            await self._flush_replies(writer, parser)
            if state.session_id:
                for ch in text.decode("utf-8", "replace"):
                    await session_manager.record_keystroke(state.session_id, ch)
            if echo:
                # The terminal behind telnetd echoes what is typed whatever
                # the client negotiated: the reference sent "root\r\n" back
                # to a client that had refused every option, ECHO included.
                # This used to depend on the client agreeing to SGA.
                echoed = bytearray()
                for b in text:
                    if b == 10:
                        echoed += b"\r\n"
                    elif b in (8, 127):
                        echoed += b"\x08 \x08"
                    elif b >= 32:
                        echoed.append(b)
                if echoed:
                    await self._write(writer, bytes(echoed))
            buffer += text
            if len(buffer) > MAX_COMMAND_LENGTH:
                del buffer[: len(buffer) - MAX_COMMAND_LENGTH]

    async def _await_answers(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        parser: TelnetLineReader,
        state: _TelnetState,
        buffer: bytearray,
        options: tuple[int, ...],
        deadline: float,
    ) -> bool:
        """Read until the client has said WILL or WONT to every option in
        ``options``. False when it closed or the deadline passed first.

        telnetd waits here for as long as it takes, sending nothing. Text
        that arrives meanwhile is recorded and kept for the login prompt.
        """
        while not all(option in parser.answers for option in options):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=remaining)
            except asyncio.TimeoutError:
                return False
            if not data:
                return False
            text = _ESCAPE_SEQUENCE.sub(b"", parser.feed(data))
            await self._flush_replies(writer, parser)
            for ch in text.decode("utf-8", "replace"):
                await session_manager.record_keystroke(state.session_id, ch)
            buffer += text
            if len(buffer) > MAX_COMMAND_LENGTH:
                del buffer[: len(buffer) - MAX_COMMAND_LENGTH]
        return True

    async def _negotiate(self, reader, writer, parser, state, buffer) -> bool:
        """The opening exchange, in telnetd's order. False when the client
        never answered, in which case nothing more is sent, as with the
        reference's silent client."""
        deadline = time.monotonic() + LOGIN_TIMEOUT
        opening = b"".join(parser.request(DO, option) for option in OPENING_REQUESTS)
        await self._write(writer, opening)
        if not await self._await_answers(reader, writer, parser, state, buffer, OPENING_REQUESTS, deadline):
            return False

        second = b"".join(parser.request(verb, option) for verb, option in SECOND_REQUESTS)
        await self._write(writer, second)
        if not await self._await_answers(reader, writer, parser, state, buffer, (OPT_NAWS,), deadline):
            return False

        # Last, the server turns its own echo on; the banner follows.
        await self._write(writer, parser.request(WILL, OPT_ECHO))
        return True

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
        """The SSH decoy's policy, shared with it: see core/login_policy.py."""
        return login_policy.check(source_ip, username, password)

    async def _login(self, reader, writer, parser, state, buffer, source_ip) -> bool:
        await self._write(writer, self.get_banner())
        hostname = get_identity().hostname
        while state.auth_attempts < MAX_LOGIN_TRIES:
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
                state.is_root = username == "root"
                # Each account starts in its own home directory.
                state.cwd = shell_dispatch.start_shell(
                    state.session_id, username, state.is_root, source_ip, 0
                )
                await adaptive_engine.profile_actor(
                    state.session_id, source_ip,
                    {"auth_success": True, "username": username, "protocol": "telnet"},
                )
                return True
            # Real login(1) pauses before refusing: 2.5 to 3.3 seconds in the
            # reference's ten refusals, 2.885 s in the row that times it.
            await login_delay.pause(config.telnet_fail_delay)
            if state.auth_attempts >= MAX_LOGIN_TRIES:
                # The last refusal is not followed by another prompt.
                await self._write(
                    writer,
                    f"\r\nLogin incorrect\r\nMaximum number of tries exceeded ({MAX_LOGIN_TRIES})\r\n",
                )
                return False
            await self._write(writer, f"\r\nLogin incorrect\r\n{hostname} login: ")
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
        response, _status = await shell_dispatch.run_command(
            state.session_id, source_ip, state, command, pty=True
        )
        return response

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
            if shell_dispatch.parse_exit(command, 0) is not None:
                shell = shell_states.get(state.session_id)
                if shell.subshells > 0:
                    # Leaves the nested shell, not the session.
                    shell.subshells -= 1
                    await self._write(writer, "exit\r\n" + await self._prompt(state))
                    continue
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

            if not await self._negotiate(reader, writer, parser, state, buffer):
                return
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
            # The option sequence is the client's fingerprint, and the most
            # useful one for the connections that never get past the login.
            if parser.negotiations:
                record = await session_manager.get_session(session_id)
                if record is not None:
                    record.fingerprints["telnet_options"] = [
                        f"{verb} {option}" for verb, option in parser.negotiations[:MAX_FINGERPRINT_OPTIONS]
                    ]
            try:
                # Taken out of the store, not just read: the state holds every
                # file the session wrote, and leaving it there kept all of it
                # in memory after the connection had gone.
                await flush_session_files(session_id, shell_states.pop(session_id))
            except Exception as exc:
                logger.warning("Telnet file flush failed for %s: %s", session_id, exc)
            finally:
                await session_manager.end_session(session_id)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
