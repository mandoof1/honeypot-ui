"""What SSH and Telnet do with a command line and a terminal, in one place.

Both transports ran the same steps in their own copy of the code — profile,
capture, emulate, record — and both had the same fault: the command was
recorded *after* the emulation, so any exception in the emulation lost the
command altogether and closed the attacker's shell with it. One malformed
``tr`` was enough. Here the command is recorded first and everything that
interprets attacker text runs inside a guard; whatever happens, the record
has the line and the shell carries on.

The line editor is here too. A PTY client sends raw keystrokes: arrow keys
arrive as escape sequences and Ctrl-C as a byte, and a shell that echoes
``^[[A`` back or ignores Ctrl-C is not bash.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from honeypot.adaptive.response import adaptive_engine
from honeypot.capture.shell_capture import capture_command
from honeypot.core.identity import get_identity
from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.core.shell_state import shell_states

logger = logging.getLogger(__name__)


def home_for(username: Optional[str], is_root: bool) -> str:
    if is_root or username == "root":
        return "/root"
    return get_identity().home_for(username or "user")


def start_shell(session_id: str, username: str, is_root: bool, source_ip: str, source_port: int) -> str:
    """Set a session's shell up for the account that just logged in.

    Returns the home directory, which is where the shell starts: each user in
    their own, not everyone but root in ``/home/user``.
    """
    shell = shell_states.get(session_id)
    home = home_for(username, is_root)
    shell.home = shell.cwd = home
    shell.username = username
    shell.client_ip, shell.client_port = source_ip, source_port
    return home


def printable(text: str) -> str:
    """Output as it can be stored: raw bytes carried in the text made safe."""
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def encode(text: str, crlf: bool) -> bytes:
    """Output as it goes on the wire.

    A terminal needs CRLF: the client put its side in raw mode when it asked
    for a PTY, so a bare line feed moves down without returning to the left
    margin and every line of output staircases across the screen. Without a
    PTY the bytes are a program's output and are sent as they are.
    """
    if crlf:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return text.encode("utf-8", "surrogateescape")


async def run_command(session_id: str, source_ip: str, state, command: str, pty: bool = True) -> tuple[str, int]:
    """Run one command line: (what it prints, its exit status).

    ``state`` is the transport's per-connection state (``username``,
    ``is_root``, ``cwd``); its ``cwd`` is kept in step with the shell's.
    """
    # Recorded before anything interprets it, so no failure below can lose it.
    entry = await session_manager.record_command(session_id, command)
    response, status = "", 0
    try:
        await adaptive_engine.profile_actor(session_id, source_ip, {"command": command})
        # Capture runs on the raw command, before anything lowercases it, and
        # in passive mode too: recording what an attacker wrote is observation.
        await capture_command(
            session_id, command, home_for(state.username, state.is_root),
            state.username, state.is_root,
        )
        payload = {
            "command": command,
            "username": state.username,
            "cwd": state.cwd,
            "is_root": state.is_root,
            "pty": pty,
            "source_ip": source_ip,
        }
        response = await mode_handler.handle_interaction(session_id, "ssh", "command", payload) or ""
        status = int(payload.get("exit_status", 0))
        # The emulator reports a directory change through the payload dict so
        # the prompt and later commands agree with it.
        if payload.get("cwd_after"):
            state.cwd = payload["cwd_after"]
    except asyncio.CancelledError:
        raise
    except Exception:
        # An emulation bug must cost one command's output, not the session.
        logger.exception("Emulating a command failed; the session continues")
        response, status = "", 1
    finally:
        await session_manager.set_command_result(session_id, entry, printable(response), status)
    return response, status


def parse_exit(command: str, last_status: int) -> Optional[int]:
    """The status ``exit [n]`` / ``logout`` asks for, or None if it is neither."""
    words = command.split()
    if not words or words[0] not in ("exit", "logout") or len(words) > 2:
        return None
    if len(words) == 2:
        try:
            return int(words[1][:6]) & 0xFF
        except ValueError:
            return 2
    return last_status


class LineEditor:
    """Turns a PTY client's keystrokes into lines, as readline would.

    ``feed`` takes one character and returns what to echo and, when the
    keystroke completes something, an event: ``("line", text)``,
    ``("interrupt", "")`` for Ctrl-C or ``("eof", "")`` for Ctrl-D on an empty
    line. Escape sequences are consumed whole — an arrow key recalls history
    or is ignored, and never lands in the command.
    """

    def __init__(self, max_length: int, history: Optional[list[str]] = None) -> None:
        self.buffer = ""
        self.max_length = max_length
        self.history = history if history is not None else []
        self._escape = ""
        self._recall = 0
        self._after_cr = False

    def _replace(self, text: str) -> bytes:
        erase = b"\x08 \x08" * len(self.buffer)
        self.buffer = text[: self.max_length]
        return erase + self.buffer.encode("utf-8", "replace")

    def _finish_escape(self, sequence: str) -> bytes:
        if sequence in ("[A", "OA") and self.history:
            # Up: one line further back.
            self._recall = min(self._recall + 1, len(self.history))
            return self._replace(self.history[-self._recall])
        if sequence in ("[B", "OB"):
            self._recall = max(self._recall - 1, 0)
            return self._replace(self.history[-self._recall] if self._recall else "")
        return b""

    def feed(self, char: str) -> tuple[bytes, Optional[tuple[str, str]]]:
        if self._escape:
            self._escape += char
            body = self._escape[1:]
            # CSI and SS3 sequences end on a letter or a tilde; anything else
            # after ESC is a two-character sequence.
            if body[0] in "[O":
                if len(body) > 1 and (char.isalpha() or char == "~" or len(body) > 16):
                    self._escape = ""
                    return self._finish_escape(body), None
                return b"", None
            self._escape = ""
            return b"", None
        if char == "\x1b":
            self._escape = char
            return b"", None

        if char == "\n" and self._after_cr:
            # The LF of a CRLF: the CR already ended the line.
            self._after_cr = False
            return b"", None
        self._after_cr = char == "\r"

        if char in ("\r", "\n"):
            line, self.buffer, self._recall = self.buffer, "", 0
            return b"\r\n", ("line", line)
        if char == "\x03":
            self.buffer, self._recall = "", 0
            return b"^C\r\n", ("interrupt", "")
        if char == "\x04":
            return (b"", ("eof", "")) if not self.buffer else (b"", None)
        if char in ("\x7f", "\x08"):
            if not self.buffer:
                return b"", None
            self.buffer = self.buffer[:-1]
            return b"\x08 \x08", None
        if char == "\x15":
            return self._replace(""), None
        if char == "\x17":
            return self._replace(self.buffer.rstrip().rpartition(" ")[0] + (" " if " " in self.buffer.rstrip() else "")), None
        if char == "\x0c":
            return b"\x1b[H\x1b[2J", ("redraw", "")
        if ord(char) < 32:
            # Tab and the other control keys: no completion, nothing to echo.
            return b"", None
        if len(self.buffer) >= self.max_length:
            return b"", None
        self.buffer += char
        return char.encode("utf-8", "replace"), None
