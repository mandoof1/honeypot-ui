"""The emulated shell: one command line in, what the terminal shows out.

SSH and Telnet both hand every line an attacker types to
:meth:`ModeHandler.handle_interaction`. In passive mode the line is only
noted. In active mode it is run the way a shell would run it — split into
statements and pipelines, variables and ``$(…)`` expanded, loops walked,
each stage's output fed to the next — with every command answered by the
emulation in ``core/commands.py`` and nothing executed.

A few commands are handled here rather than there because they need the
session or the event loop: fetches (``wget``, ``curl``, ``tftp``,
``ftpget``), which are recorded as indicators; anything that runs a file or
a script, which is recorded as a payload execution; ``cd``; nested shells;
and ``sleep``, which really waits, within a bound.

The capture interpreter (``capture/shell_writes.py``) reads the same line to
work out what it writes. The two share their lexer, their expansion rules
and their ``cd`` (``core/shell_syntax.py``), so the file a redirection
created is where ``ls`` and ``cat`` will look for it.
"""

from __future__ import annotations

import asyncio
import logging
import posixpath
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from honeypot.capture.shell_writes import (
    INTERPRETERS,
    MAX_NESTING,
    TRANSPARENT_PREFIXES,
    _Lexer,
)
from honeypot.core import canary, dropper, honeytokens
from honeypot.core.commands import (
    MAX_OUTPUT_CHARS,
    CommandEmulator,
    base_environment,
    lookup_variable,
)
from honeypot.core.commands_files import to_bytes, to_text
from honeypot.core.config import OperationalMode, config
from honeypot.core.identity import get_identity
from honeypot.core.session import session_manager
from honeypot.core.shell_state import DroppedFile, ShellState, resolve_path, shell_states
from honeypot.core.shell_syntax import (
    ASSIGNMENT,
    MAX_VARIABLE_CHARS,
    Expander,
    ProgramWalker,
    change_directory,
    compile_program,
    strip_markers,
)
from honeypot.core.textfilters import RegexBudget
from honeypot.core.vfs import FsView

logger = logging.getLogger(__name__)

#: Tools whose whole purpose is to bring a file onto the box.
FETCH_TOOLS = {"wget", "curl", "tftp", "ftpget"}
_SHELLS = {"sh", "bash", "dash", "ash", "ksh", "zsh"}

#: Longest one ``sleep`` really waits, and the most one command line may
#: wait in total. Returning instantly from ``sleep 5`` is a tell; honouring
#: ``sleep 99999`` would let a visitor park the session for nothing.
MAX_SLEEP_SECONDS = 5.0
MAX_SLEEP_PER_LINE = 10.0

#: Wrappers that run the rest of their arguments as the command.
_PREFIXES = TRANSPARENT_PREFIXES | {"doas", "stdbuf", "ionice", "env", "busybox-exec"}


@dataclass
class _Line:
    """Everything one command line's evaluation needs to carry around."""

    session_id: str
    shell: ShellState
    data: dict
    username: str
    is_root: bool
    depth: int
    emulator: CommandEmulator
    expander: Optional[Expander] = None
    printed: int = 0
    sleep_left: float = MAX_SLEEP_PER_LINE
    #: Seconds of emulation this line may still spend; see LINE_WORK_SECONDS.
    work_left: float = 0.25
    #: The fetch feeding the current pipeline, if any: ``curl … | sh``.
    fetch: Optional[dropper.Download] = None
    pipes_to_shell: bool = False
    pty: bool = True
    fs: FsView = field(default=None)  # type: ignore[assignment]


def session_variables(shell: ShellState, username: str, is_root: bool) -> dict[str, str]:
    """Every variable a ``$NAME`` could expand to right now, as a snapshot."""
    identity = get_identity()
    variables = base_environment(shell, identity, username, is_root)
    variables.update(shell.env)
    variables.update(shell.variables)
    for special in ("$", "#", "0", "UID", "EUID", "HOSTNAME", "PPID"):
        value = lookup_variable(shell, identity, username, is_root, special)
        if value is not None:
            variables[special] = value
    return variables


def substitute_command(shell: ShellState, username: str, is_root: bool, text: str, depth: int = 0) -> str:
    """The output of ``$(text)``, for commands that only read.

    Synchronous and side-effect free on purpose: both evaluators call it,
    possibly for the same substitution, so it must give the same answer
    twice. A substitution that fetches, runs a script or changes directory
    yields nothing.
    """
    if depth >= MAX_NESTING:
        return ""
    identity = get_identity()
    emulator = CommandEmulator(identity, terminal=False)
    expander = Expander(
        lambda name: lookup_variable(shell, identity, username, is_root, name),
        lambda inner: substitute_command(shell, username, is_root, inner, depth + 1),
    )
    out: list[str] = []
    try:
        statements = _Lexer(text[:4096], mark=True).run()
    except Exception:
        return ""
    for _connector, pipeline in statements[:8]:
        piped: Optional[bytes] = None
        result: Optional[str] = ""
        for stage in pipeline:
            words = expander.words(list(stage.words))
            while words and words[0] in TRANSPARENT_PREFIXES:
                words.pop(0)
            if not words:
                continue
            base = posixpath.basename(words[0])
            if base in FETCH_TOOLS or base in INTERPRETERS or base in ("cd", "busybox", "sleep", "eval"):
                result = ""
                break
            result, _status = emulator.run(
                [base if "/" in words[0] and emulator.can_run(base) else words[0]] + words[1:],
                shell, username, is_root, piped,
            )
            piped = to_bytes(result) if result else b""
        if result:
            out.append(result)
    return "".join(out)[:MAX_VARIABLE_CHARS]


def capture_context(session_id: str, username: str, is_root: bool) -> dict:
    """What the capture interpreter needs to agree with this emulator.

    The session's variables (as a snapshot it may change freely), the
    directories that exist, and the evaluator for ``$(…)``.
    """
    shell = shell_states.get(session_id)
    name = username or ("root" if is_root else "user")
    return {
        "env": session_variables(shell, name, is_root),
        "dirs": FsView(shell, name, is_root),
        "substitute": lambda text: substitute_command(shell, name, is_root, text),
    }


class ModeHandler:
    def __init__(self):
        self._mode = config.operational_mode

    @property
    def mode(self) -> OperationalMode:
        return self._mode

    @mode.setter
    def mode(self, value: OperationalMode):
        self._mode = value

    def is_active(self) -> bool:
        return self._mode == OperationalMode.ACTIVE_EMULATION

    def is_passive(self) -> bool:
        return self._mode == OperationalMode.PASSIVE_MONITORING

    async def handle_interaction(
        self,
        session_id: str,
        protocol: str,
        interaction_type: str,
        data: Optional[dict] = None,
    ) -> str:
        if self.is_passive():
            if data:
                await self._log_passive(session_id, protocol, interaction_type, data)
            return ""
        # Only the shell is answered from here. FTP and the web decoys build
        # their own responses; the template responders this class used to
        # carry for them were never called.
        if protocol != "ssh":
            return ""
        return await self._ssh_response(session_id, interaction_type, data if data is not None else {})

    async def _log_passive(
        self, session_id: str, protocol: str, interaction_type: str, data: dict
    ):
        """Record an interaction that the emulator itself does not capture.

        Emulators already persist commands, credentials, keystrokes and
        network events as they read them off the wire, so passive mode only
        needs to note that a request arrived and was deliberately not answered.
        Re-recording here would duplicate every command in the session.
        """
        await session_manager.record_network_event(
            session_id,
            "passive_observation",
            {
                "protocol": protocol,
                "interaction_type": interaction_type,
                "responded": False,
            },
        )

    # -- login banner and prompt -------------------------------------------

    def _welcome(self, data: dict) -> str:
        """The MOTD and the "Last login" line, as Ubuntu 20.04 prints them.

        The identity decides the OS, and the login line shows the *previous*
        login — a plausible earlier session from somewhere else — rather than
        the attacker's own address at the current instant, which no real sshd
        would show on a first connection and which was a giveaway here.
        """
        identity = get_identity()
        when = datetime.fromtimestamp(identity.last_login_time, tz=timezone.utc)
        welcome = (
            f"Welcome to Ubuntu {identity.os_version} LTS "
            f"(GNU/Linux {identity.kernel} {identity.arch})\n\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n"
            " * Support:        https://ubuntu.com/advantage\n\n"
            f"Last login: {when.strftime('%a %b %d %H:%M:%S %Y')} from {identity.last_login_ip}\n"
        )
        # Advance the stored last-login so a second connection sees this one.
        source_ip = data.get("source_ip")
        if source_ip:
            identity.note_login(source_ip)
        return welcome

    @staticmethod
    def _who(data: dict) -> tuple[str, bool]:
        is_root = bool(data.get("is_root"))
        return data.get("username") or ("root" if is_root else "user"), is_root

    def _prompt(self, session_id: str, data: dict) -> str:
        identity = get_identity()
        username, is_root = self._who(data)
        shell = shell_states.get(session_id)
        shell.home = "/root" if is_root else identity.home_for(username)
        return f"{username}@{identity.hostname}:{shell.display_cwd()}{'#' if is_root else '$'} "

    async def _ssh_response(self, session_id: str, interaction_type: str, data: dict) -> str:
        if interaction_type in ("welcome", "auth_success"):
            return self._welcome(data)
        if interaction_type == "prompt":
            return self._prompt(session_id, data)
        if interaction_type == "command":
            # Case preserved: lowercasing corrupts base64 payloads and the
            # case-sensitive paths a dropper checks (``./Mozi.m``).
            return await self._process_command_line(session_id, data.get("command", ""), data)
        return ""

    # -- one command line --------------------------------------------------

    async def _process_command_line(
        self, session_id: str, raw: str, data: dict, depth: int = 0
    ) -> str:
        """Run one command line the attacker typed, as a real shell would.

        The line is split into statements on ``;`` ``&&`` ``||`` and into
        pipeline stages on ``|`` by the same quote-aware lexer that captures
        shell writes, so a compound loader line is handled one segment at a
        time with the previous segment's exit code honoured. ``for``,
        ``while`` and ``if`` are walked rather than run as unknown commands.
        """
        shell = shell_states.get(session_id)
        identity = get_identity()
        username, is_root = self._who(data)
        shell.home = "/root" if is_root else identity.home_for(username)
        shell.username = username
        if depth == 0:
            shell.remember(raw.strip())
            # A planted secret typed back at us, in any command.
            for hit in honeytokens.scan_text(raw):
                await session_manager.record_network_event(session_id, "honeytoken_used", hit)

        line = _Line(
            session_id=session_id, shell=shell, data=data, username=username,
            is_root=is_root, depth=depth, pty=bool(data.get("pty", True)),
            emulator=CommandEmulator(identity, RegexBudget(), terminal=bool(data.get("pty", True))),
        )
        line.fs = FsView(shell, username, is_root)
        line.expander = Expander(
            lambda name: lookup_variable(shell, identity, line.username, line.is_root, name),
            lambda text: substitute_command(shell, line.username, line.is_root, text, depth + 1),
            lambda pattern: line.fs.glob(pattern, shell.cwd, shell.home),
        )

        try:
            statements = _Lexer(raw, mark=True).run()
        except Exception:
            logger.warning("Could not parse a command line; treating it as one command", exc_info=True)
            statements = []

        def set_variable(name: str, value: str) -> None:
            self._assign(shell, name, value)

        walker = ProgramWalker(compile_program(statements), line.expander.words, set_variable)
        out_parts: list[str] = []
        last_status = shell.last_status
        while True:
            # Expansion (including command substitution) happens in next(),
            # synchronously, so it is charged to the line's allowance.
            started = time.perf_counter()
            step = walker.next(last_status)
            line.work_left -= time.perf_counter() - started
            if step is None:
                break
            if line.work_left <= 0:
                # One line has had its share. A real shell would keep going;
                # this one shares a single event loop with every other
                # session, the heartbeat and the health check, and a loop
                # over a large variable through a long pipeline held it for
                # seconds. What was produced so far is returned.
                last_status = 130
                break
            # Let other sessions run between pipelines.
            await asyncio.sleep(0)
            connector, pipeline = step
            if connector == "&&" and last_status != 0:
                continue
            if connector == "||" and last_status == 0:
                continue
            text, last_status = await self._run_pipeline(line, pipeline)
            shell.last_status = last_status
            if text and line.printed < MAX_OUTPUT_CHARS:
                text = text[: MAX_OUTPUT_CHARS - line.printed]
                line.printed += len(text)
                out_parts.append(text)
        shell.last_status = last_status
        data["exit_status"] = last_status
        return "".join(out_parts)

    @staticmethod
    def _emulate(line: _Line, *args) -> tuple[str, int]:
        """Run one emulated command, charged to the line's work allowance.

        Past the allowance a command produces nothing and reports the status
        of one that was interrupted, so a pipeline of thirty filters over
        64 KiB stops costing the loop anything after the first few.
        """
        if line.work_left <= 0:
            return "", 130
        started = time.perf_counter()
        try:
            return line.emulator.run(*args)
        finally:
            line.work_left -= time.perf_counter() - started

    @staticmethod
    def _assign(shell: ShellState, name: str, value: str) -> None:
        if name in shell.variables or len(shell.variables) < 256:
            shell.variables[name] = value[:MAX_VARIABLE_CHARS]
        if name in shell.env:
            shell.env[name] = value[:MAX_VARIABLE_CHARS]

    async def _run_pipeline(self, line: _Line, pipeline) -> tuple[str, int]:
        """Run a single pipeline (stages joined by ``|``)."""
        piped: Optional[bytes] = None
        display = ""
        status = 0
        line.fetch = None
        # A fetch piped into an interpreter (``curl … | sh``) is the loader
        # handing its payload straight to a shell; the download recorder needs
        # to know even though the ``| sh`` is a later stage.
        line.pipes_to_shell = any(
            posixpath.basename(strip_markers((getattr(s, "words", None) or [""])[0])) in INTERPRETERS
            for s in pipeline[1:]
        )
        for index, stage in enumerate(pipeline):
            if index:
                await asyncio.sleep(0)
            redirects = getattr(stage, "redirects", [])
            is_last = index == len(pipeline) - 1
            stdin = piped
            if getattr(stage, "heredoc", None) is not None:
                stdin = stage.heredoc
            for redirect in redirects:
                target = line.expander.text(redirect.target)
                if redirect.op == "<<<":
                    stdin = to_bytes(target) + b"\n"
                elif redirect.op == "<" and redirect.fd == 0:
                    stdin = line.fs.read(resolve_path(line.shell.cwd, target, line.shell.home))
                    if stdin is None:
                        return f"-bash: {strip_markers(target)}: No such file or directory\n", 1

            # Only a stage that prints straight to the terminal has one.
            to_terminal = line.pty and is_last and not any(
                r.op in (">", ">>") and r.fd == 1 for r in redirects
            )
            text, status = await self._run_stage(line, list(stage.words), stdin, to_terminal)

            discarded = {r.fd for r in redirects if r.op in (">", ">>")}
            if 2 in discarded and status != 0:
                # `2>/dev/null` on a command that failed: what it printed was
                # its complaint, and that is what was thrown away.
                text = ""
            if 1 in discarded:
                # Written to a file (the capture layer has the bytes).
                text = ""
            piped = to_bytes(text) if text else b""
            if is_last:
                display = text or ""
        return display, status

    # -- one stage ---------------------------------------------------------

    async def _run_stage(self, line: _Line, raw_words: list[str], stdin: Optional[bytes],
                         to_terminal: bool) -> tuple[Optional[str], int]:
        words = line.expander.words(raw_words)
        assignments = []
        while words and ASSIGNMENT.match(words[0]):
            assignments.append(words.pop(0))
        if not words:
            # `NAME=value` alone sets a shell variable; before a command it
            # applies to that command only, which nothing here reads.
            for assignment in assignments:
                name, value = ASSIGNMENT.match(assignment).groups()
                self._assign(line.shell, name, value)
            return ("" if stdin is None else to_text(stdin)) if not assignments else "", 0
        # Tilde expansion, for the arguments: `echo ~`, `ls ~/.ssh`.
        home = line.shell.home
        words = [words[0]] + [
            home if word == "~" else (home + word[1:] if word.startswith("~/") else word)
            for word in words[1:]
        ]
        return await self._dispatch(line, words, stdin, to_terminal, line.username, line.is_root)

    async def _dispatch(self, line: _Line, words: list[str], stdin: Optional[bytes],
                        to_terminal: bool, username: str, is_root: bool,
                        busybox: bool = False) -> tuple[Optional[str], int]:
        shell = line.shell
        name = words[0]
        base = posixpath.basename(name)

        # A path names a file: something the host ships, or something the
        # attacker put there. Bare names are looked up as commands.
        if "/" in name or name.startswith("~"):
            path = resolve_path(shell.cwd, name, shell.home)
            entry = line.fs.lookup(path)
            if entry is None:
                return f"-bash: {name}: No such file or directory\n", 127
            if entry.kind == "dir":
                return f"-bash: {name}: Is a directory\n", 126
            if entry.session:
                return await self._run_dropped(line, name, path, entry, words[1:])
            if not entry.executable:
                return f"-bash: {name}: Permission denied\n", 126
            words = [base] + words[1:]
            name = base

        if base in ("sudo", "doas"):
            rest = [w for w in words[1:]]
            while rest and rest[0].startswith("-"):
                # -u USER and friends take a value; the rest are switches.
                takes_value = rest[0] in ("-u", "-g", "-h", "-p", "-C", "-U")
                rest = rest[2:] if takes_value else rest[1:]
            if not rest or words[1:2] and words[1] in ("-l", "-v", "-k", "-K", "-n", "-i", "-s", "-V"):
                text, status = self._emulate(line, ["sudo"] + words[1:], shell, username, is_root, stdin, to_terminal)
                return text, status
            # A passwordless sudoer: the command runs as root.
            return await self._dispatch(line, rest, stdin, to_terminal, "root", True)

        if base in _PREFIXES or base == "timeout":
            rest = words[1:]
            if base == "timeout":
                while rest and rest[0].startswith("-"):
                    rest = rest[1:]
                rest = rest[1:]
            elif base == "env":
                while rest and (ASSIGNMENT.match(rest[0]) or rest[0].startswith("-")):
                    rest = rest[1:]
            elif base in ("nice", "ionice", "stdbuf"):
                while rest and rest[0].startswith("-"):
                    rest = rest[2:] if rest[0] in ("-n", "-c") else rest[1:]
            elif base == "command" and rest and rest[0] in ("-v", "-V"):
                return self._emulate(line, words, shell, username, is_root, stdin, to_terminal)
            if not rest:
                return self._emulate(line, words, shell, username, is_root, stdin, to_terminal)
            return await self._dispatch(line, rest, stdin, to_terminal, username, is_root)

        if base in FETCH_TOOLS:
            return await self._emulate_download(line, [base] + words[1:], busybox)

        if base == "busybox":
            return await self._busybox(line, words, stdin, to_terminal, username, is_root)

        if base == "cd":
            target, error = change_directory(
                words[1:], shell.cwd, shell.home, shell.previous_cwd, line.fs
            )
            if target is None:
                return error, 1
            shell.previous_cwd, shell.cwd = shell.cwd, target
            line.data["cwd_after"] = target
            return (target + "\n" if words[1:2] == ["-"] else ""), 0

        if base in INTERPRETERS:
            return await self._interpreter(line, base, words[1:], stdin, username, is_root)

        if base == "eval":
            if line.depth >= MAX_NESTING:
                return "", 0
            text = await self._process_command_line(line.session_id, " ".join(words[1:]), line.data, line.depth + 1)
            return text, shell.last_status

        if base == "sleep":
            return await self._sleep(line, words[1:])

        if base in ("exit", "logout"):
            # At the top level the transport ends the session; reached here
            # it is inside a compound line or a script, where it ends that.
            return "", 0

        text, status = self._emulate(line, words, shell, username, is_root, stdin, to_terminal)
        if line.emulator.canary_hit is not None:
            await session_manager.record_network_event(
                line.session_id, "ai_canary_triggered", line.emulator.canary_hit
            )
            line.emulator.canary_hit = None
        return text, status

    async def _sleep(self, line: _Line, args: list[str]) -> tuple[str, int]:
        if not args:
            return "sleep: missing operand\nTry 'sleep --help' for more information.\n", 1
        total = 0.0
        for arg in args:
            scale = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(arg[-1:], None)
            number = arg[:-1] if scale else arg
            try:
                total += float(number[:12]) * (scale or 1)
            except ValueError:
                return f"sleep: invalid time interval ‘{arg}’\nTry 'sleep --help' for more information.\n", 1
        wait = max(0.0, min(total, MAX_SLEEP_SECONDS, line.sleep_left))
        line.sleep_left -= wait
        if wait:
            await asyncio.sleep(wait)
        return "", 0

    async def _busybox(self, line: _Line, words, stdin, to_terminal, username, is_root):
        if len(words) < 2:
            return (
                "BusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6.4) multi-call binary.\n"
                "BusyBox is copyrighted by many authors between 1998-2015.\n"
                "Licensed under GPLv2. See source distribution for detailed\n"
                "copyright notices.\n\n"
                "Usage: busybox [function [arguments]...]\n"
                "   or: busybox --list[-full]\n"
            ), 0
        applet = words[1]
        known = (
            applet in FETCH_TOOLS or applet in _SHELLS
            or applet in ("cd", "sleep", "echo", "printf", "test", "[", "true", "false")
            or line.emulator.can_run(applet)
        )
        if "/" not in applet and known:
            # A known applet: run it as the bare command.
            return await self._dispatch(line, words[1:], stdin, to_terminal, username, is_root, busybox=True)
        # Mirai probes with an invented applet name and reads the reply; real
        # busybox answers exactly this, which also satisfies the probe.
        return f"{applet}: applet not found\n", 127

    # -- things that run ---------------------------------------------------

    async def _record_execution(self, line: _Line, path: str, source_url: Optional[str],
                                size: int, interpreter: Optional[str] = None) -> None:
        details = {"path": path, "source_url": source_url, "bytes": size, "executed": False}
        if interpreter:
            details["interpreter"] = interpreter
        await session_manager.record_network_event(line.session_id, "payload_execution", details)

    async def _run_script(self, line: _Line, content: bytes) -> tuple[str, int]:
        """Walk a shell script whose text is known, as nested command lines.

        Nothing is executed; this is what lets the ``wget`` inside a script
        the attacker wrote and then ran be recorded as a download.
        """
        if line.depth >= MAX_NESTING:
            return "", 0
        text = await self._process_command_line(
            line.session_id, to_text(content[:64 * 1024]), line.data, line.depth + 1
        )
        return text, line.shell.last_status

    @staticmethod
    def _is_script(content: Optional[bytes]) -> bool:
        if not content or content.startswith(b"\x7fELF"):
            return False
        head = content[:256]
        if head.startswith(b"#!"):
            first = head.split(b"\n", 1)[0]
            return any(shell.encode() in first for shell in _SHELLS)
        return b"\x00" not in head

    async def _run_dropped(self, line: _Line, name: str, path: str, entry, args: list[str]):
        """``./x``: run something the attacker put here."""
        if not entry.executable:
            return f"-bash: {name}: Permission denied\n", 126
        await self._record_execution(line, path, entry.source_url, entry.size)
        content = line.shell.contents.get(path)
        if content is not None and self._is_script(bytes(content[:256])):
            return await self._run_script(line, bytes(content))
        # A real loader daemonises and prints nothing; silence keeps the
        # session going and is the accurate answer.
        return "", 0

    async def _interpreter(self, line: _Line, base: str, args: list[str], stdin: Optional[bytes],
                           username: str, is_root: bool) -> tuple[Optional[str], int]:
        """``sh``, ``bash``, ``python`` … with a script, ``-c``, stdin or nothing."""
        shell = line.shell
        is_shell = base in _SHELLS
        if not is_shell and not line.emulator.can_run(base) and base not in ("python", "php", "ruby"):
            return self._emulate(line, [base] + args, shell, username, is_root, stdin)
        if base in ("python", "python2", "php", "ruby"):
            # Not installed on a stock Ubuntu 20.04 server.
            return f"{base}: command not found\n", 127

        if "-c" in args or (not is_shell and "-e" in args):
            flag = "-c" if "-c" in args else "-e"
            index = args.index(flag)
            inner = args[index + 1] if index + 1 < len(args) else ""
            if is_shell and inner and line.depth < MAX_NESTING:
                # `sh -c '<inner>'`: run the inner line through the same machinery.
                text = await self._process_command_line(line.session_id, inner, line.data, line.depth + 1)
                return text, shell.last_status
            return "", 0

        scripts = [a for a in args if not a.startswith("-")]
        if scripts:
            # `sh bins.sh`: the commonest way a fetched loader is started.
            shown = scripts[0]
            path = resolve_path(shell.cwd, shown, shell.home)
            entry = line.fs.lookup(path)
            if entry is None or entry.kind == "dir":
                if base == "bash":
                    reason = "Is a directory" if entry is not None else "No such file or directory"
                    return f"bash: {shown}: {reason}\n", 126 if entry is not None else 127
                if is_shell:
                    return f"{base}: 0: Can't open {shown}\n", 127
                return f"{base}: can't open file '{shown}': [Errno 2] No such file or directory\n", 2
            await self._record_execution(line, path, entry.source_url, entry.size, base)
            content = shell.contents.get(path)
            if is_shell and content is not None and self._is_script(bytes(content[:256])):
                return await self._run_script(line, bytes(content))
            return "", 0

        if stdin is not None:
            if line.fetch is not None:
                # `curl … | sh`: the payload goes straight to an interpreter
                # and never touches disk. Nothing was fetched, so there is no
                # content — but the execution, and where it came from, is
                # exactly what an analyst needs to see.
                await self._record_execution(
                    line, "(stdin)", line.fetch.url, dropper.size_for(line.fetch, get_identity().seed), base
                )
                return "", 0
            if stdin:
                await self._record_execution(line, "(stdin)", None, len(stdin), base)
                if is_shell and self._is_script(stdin[:256]):
                    return await self._run_script(line, stdin)
            return "", 0

        if is_shell:
            # A nested interactive shell: the next `exit` leaves it.
            shell.subshells = min(shell.subshells + 1, 8)
            return "", 0
        return self._emulate(line, [base] + args, shell, username, is_root, stdin)

    # -- fetches -----------------------------------------------------------

    async def _emulate_download(self, line: _Line, argv: list[str], busybox: bool) -> tuple[str, int]:
        """Answer wget/curl/tftp/ftpget as though the fetch worked.

        No request is made. The URL is parsed, recorded against the session as
        a network event so it reaches the backend as an indicator, and a
        plausible transcript is returned. Letting the fetch "succeed" is the
        whole point: the attacker's next commands — chmod, execute, the second
        stage, the kill-competitor loop — only happen if this one does.
        """
        tool = argv[0]
        downloads = dropper.parse_argv(argv, piped=line.pipes_to_shell, busybox=busybox)
        if not downloads:
            # A bare `wget` or a form we cannot read: reply the way the real
            # tool does for a missing argument rather than inventing output.
            return dropper.usage_error(tool, busybox), 1

        seed = get_identity().seed
        shell = line.shell
        out: list[str] = []
        status = 0
        for download in downloads:
            size = dropper.size_for(download, seed)
            await session_manager.record_network_event(
                line.session_id,
                "file_download",
                {
                    "tool": download.tool,
                    "url": download.url,
                    "host": download.host,
                    "port": download.port,
                    "filename": download.filename,
                    "piped_to_shell": download.piped,
                    "bytes": size,
                    # Recorded so an analyst reading the session knows the honeypot
                    # never actually retrieved the payload.
                    "fetched": False,
                },
            )
            line.fetch = download
            if download.saves:
                path = resolve_path(shell.cwd, download.target, shell.home)
                if not line.fs.is_dir(posixpath.dirname(path)):
                    out.append(f"{download.target}: No such file or directory\n")
                    status = 1
                    continue
                shell.add_file(path, DroppedFile(name=download.filename, size=size, source_url=download.url))
            out.append(dropper.transcript(download, size, seed))
        return "".join(out), status


mode_handler = ModeHandler()
