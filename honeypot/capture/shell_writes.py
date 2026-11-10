"""Recover the files an attacker writes through the shell.

When a host has no ``wget``, ``curl`` or ``tftp``, loaders write the payload
themselves. The Mirai "echoloader" is the canonical case: the binary arrives
as dozens of ``echo -ne '\\x7f\\x45\\x4c\\x46…' >> .s`` commands, each carrying
a few hundred bytes, and the assembled file is then marked executable and run.
Base64 blobs piped through ``base64 -d``, heredocs and ``printf`` do the same
job. In every one of these the payload travels *inbound*, inside the command
line, so — unlike a URL fetch — it can be captured without the honeypot making
a single outbound connection.

The emulator threw all of it away. It lowercased every command before
dispatch, which corrupts base64 beyond recovery, and answered ``echo "x" > f``
by printing ``"x" > f`` back, which is both a fingerprint and the end of the
session. Nothing here fixes that by running anything: this module is a
deliberately small interpreter for the handful of shell constructs that
*produce bytes*, evaluated over literal text. No command is executed and no
path on the real filesystem is read or written.

Variables, ``for``/``while`` loops and the working directory are handled by
``core/shell_syntax.py``, which the emulator uses too. They have to agree:
this module decides which path a redirection writes, the emulator decides
what ``ls`` and ``cat`` show afterwards, and a payload that one of them puts
under ``/data/local/tmp`` while the other is in ``/tmp`` is a payload split
in two. Run without a session — in tests, or on a bare string — nothing is
expanded and every ``cd`` is assumed to work, as before.

What it returns is the set of writes the command line would have performed,
with paths resolved against the session's working directory, plus any content
piped straight into an interpreter (``… | base64 -d | sh``), which never
touches disk but is the payload all the same.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional

from honeypot.core.shell_syntax import (
    ASSIGNMENT,
    CLOSE,
    GLOB,
    MAX_VARIABLE_CHARS,
    OPEN,
    AnyDirectory,
    Directories,
    Expander,
    ProgramWalker,
    change_directory,
    compile_program,
    resolve_path,
    scrub,
    strip_markers,
)

#: Largest single piece of content one operation may produce. Matches the
#: engine's per-upload capture cap; anything larger is not a dropper stage.
MAX_OUTPUT_BYTES = 16 * 1024 * 1024

#: Bounds on how much structure one command line may carry. A line with
#: thousands of statements is an attempt to make the parser the expensive part.
MAX_STATEMENTS = 512
MAX_STAGES = 32
MAX_WORDS = 4096
#: ``sh -c "sh -c '…'"`` — real loaders nest once, occasionally twice.
MAX_NESTING = 3

#: Interpreters whose stdin *is* the program.
INTERPRETERS = {
    "sh", "bash", "dash", "ash", "zsh", "ksh",
    "python", "python2", "python3", "perl", "php", "ruby",
}

#: Wrappers that change nothing about what the wrapped command writes.
TRANSPARENT_PREFIXES = {"nohup", "exec", "command", "sudo", "time", "nice", "setsid"}
_TRANSPARENT_PREFIXES = TRANSPARENT_PREFIXES

#: Writes to these are discarded by the kernel, not stored.
_DISCARD_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero"}

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_B64_JUNK = re.compile(rb"[^A-Za-z0-9+/=_-]")
_HEX_JUNK = re.compile(rb"[^0-9A-Fa-f]")
#: ``$NAME`` and the single-character parameters ``$?`` ``$$`` ``$#`` ``$1``…
_VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[?$#!@*0-9]")
#: One printf conversion. The flags and the width may not both match a
#: ``0``: when they could, ``%`` followed by a long run of zeros and no
#: conversion letter was retried from every split point, quadratically, on
#: the event loop.
_PRINTF_SPEC = re.compile(rb"%[-+ #0]*(?:[1-9][0-9]*)?(?:\.[0-9]+)?([sbcdixXo%])")
_PRINTF_SPECIAL = re.compile(rb"[%\\]")
#: Characters that mean nothing to the lexer: not a separator, a quote, an
#: escape, an expansion or a wildcard.
_PLAIN_RUN = re.compile(r"[^ \t\r\n;|&<>\\'\"$`*?\[]+")


@dataclass
class Write:
    """Content the command line would have written to a file."""

    path: str
    content: bytes
    append: bool
    #: How the bytes were produced — ``echo``, ``printf``, ``base64``, … —
    #: so an analyst can see an echoloader for what it is.
    method: str


@dataclass
class Execution:
    """Content piped straight into an interpreter, never written to disk."""

    content: bytes
    interpreter: str
    method: str


@dataclass
class Interpretation:
    writes: list[Write] = field(default_factory=list)
    executions: list[Execution] = field(default_factory=list)
    #: What the line prints, where that is knowable. ``None`` when any stage
    #: that reaches the terminal is a command this module does not model.
    stdout: Optional[bytes] = b""


# --------------------------------------------------------------------------
# Lexing
# --------------------------------------------------------------------------


@dataclass
class _Redirect:
    op: str      # ">", ">>", "<", "<<<"
    fd: int      # 1 for stdout, 2 for stderr, 0 for stdin
    target: str


@dataclass
class _Stage:
    words: list[str] = field(default_factory=list)
    redirects: list[_Redirect] = field(default_factory=list)
    heredoc: Optional[bytes] = None


@dataclass
class _Pending:
    stage: _Stage
    delimiter: str
    strip_tabs: bool


class _Lexer:
    """Split a command line into statements of pipeline stages.

    Handles the quoting forms droppers actually use — single, double, ANSI-C
    ``$'…'`` — plus heredocs, which are why this cannot simply split on ``;``.
    Anything it does not recognise is kept as literal text rather than
    guessed at.
    """

    def __init__(self, text: str, mark: bool = False) -> None:
        #: With ``mark``, expansions found outside single quotes are wrapped
        #: in markers for the evaluator to resolve when the statement runs
        #: (see core/shell_syntax.py) instead of being kept as literal text.
        #: Expanding here would be too early: ``X=1; echo $X`` is lexed
        #: before the assignment has happened.
        self.mark = mark
        self.text = scrub(text) if mark else text
        self.pos = 0
        #: (connector, stages): how each statement joins the one before it.
        self.statements: list[tuple[str, list[_Stage]]] = []
        self._pipeline: list[_Stage] = [_Stage()]
        self._connector = ";"
        self._pending_heredocs: list[_Pending] = []
        self._words = 0
        #: A heredoc was opened but its closing delimiter never arrived. An
        #: interactive shell keeps reading lines until it does.
        self.incomplete = False
        #: The delimiters still owed when the text ran out, in order, with
        #: whether leading tabs are stripped before comparing (``<<-``).
        self.open_delimiters: list[tuple[str, bool]] = []

    # -- helpers ----------------------------------------------------------

    def _peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.text[index] if index < len(self.text) else ""

    @property
    def _stage(self) -> _Stage:
        return self._pipeline[-1]

    def _end_stage(self) -> None:
        if len(self._pipeline) < MAX_STAGES:
            self._pipeline.append(_Stage())

    def _end_statement(self, next_connector: str = ";") -> None:
        stages = [s for s in self._pipeline if s.words or s.redirects or s.heredoc]
        if stages and len(self.statements) < MAX_STATEMENTS:
            self.statements.append((self._connector, stages))
            self._connector = next_connector
        elif not stages and next_connector != ";":
            self._connector = next_connector
        self._pipeline = [_Stage()]

    # -- main loop --------------------------------------------------------

    def run(self) -> list[tuple[str, list[_Stage]]]:
        while self.pos < len(self.text):
            ch = self._peek()

            if ch == "\n":
                self.pos += 1
                self._end_statement()
                self._read_heredoc_bodies()
                continue
            if ch in " \t\r":
                self.pos += 1
                continue
            if ch == "#" and self._at_word_start():
                while self.pos < len(self.text) and self._peek() != "\n":
                    self.pos += 1
                continue
            if ch == ";" or (ch == "&" and self._peek(1) != "&" and self._peek(1) != ">"):
                self.pos += 1
                self._end_statement()
                continue
            if ch == "&" and self._peek(1) == "&":
                self.pos += 2
                self._end_statement("&&")
                continue
            if ch == "|" and self._peek(1) == "|":
                self.pos += 2
                self._end_statement("||")
                continue
            if ch == "|":
                self.pos += 1
                self._end_stage()
                continue
            if self._try_redirect():
                continue

            before = self.pos
            word = self._read_word()
            if word is not None and self._words < MAX_WORDS:
                self._stage.words.append(word)
                self._words += 1
            if self.pos == before:
                # Never stall on input this lexer does not model.
                self.pos += 1

        self._end_statement()
        if self._pending_heredocs:
            self.incomplete = True
            self.open_delimiters.extend(
                (p.delimiter, p.strip_tabs) for p in self._pending_heredocs
            )
        return self.statements

    def _at_word_start(self) -> bool:
        return self.pos == 0 or self.text[self.pos - 1] in " \t\n;|&"

    def _try_redirect(self) -> bool:
        """Consume a redirection operator and its target, if one starts here."""
        text, pos = self.text, self.pos
        fd = None
        start = pos
        if pos < len(text) and text[pos].isdigit() and pos + 1 < len(text) and text[pos + 1] in "<>":
            # Only a digit that begins a word is a file descriptor.
            if start == 0 or text[start - 1] in " \t\n;|&":
                fd = int(text[pos])
                pos += 1
            else:
                return False
        if pos >= len(text) or text[pos] not in "<>&":
            return False

        if text.startswith("&>>", pos):
            op, fd, pos = ">>", 1, pos + 3
        elif text.startswith("&>", pos):
            op, fd, pos = ">", 1, pos + 2
        elif text[pos] == "&":
            return False
        elif text.startswith("<<<", pos):
            op, pos = "<<<", pos + 3
        elif text.startswith("<<-", pos):
            op, pos = "<<-", pos + 3
        elif text.startswith("<<", pos):
            op, pos = "<<", pos + 2
        elif text.startswith(">>", pos):
            op, pos = ">>", pos + 2
        elif text.startswith(">|", pos):
            op, pos = ">", pos + 2
        elif text.startswith(">&", pos) or text.startswith("<&", pos):
            # fd duplication (2>&1): no file involved.
            pos += 2
            while pos < len(text) and (text[pos].isdigit() or text[pos] == "-"):
                pos += 1
            self.pos = pos
            return True
        elif text[pos] == ">":
            op, pos = ">", pos + 1
        else:
            op, pos = "<", pos + 1

        self.pos = pos
        while self.pos < len(self.text) and self._peek() in " \t":
            self.pos += 1
        target = self._read_word()
        if target is None:
            return True

        if op in ("<<", "<<-"):
            # A delimiter is compared with the lines that follow as text; it
            # is never expanded.
            self._pending_heredocs.append(_Pending(self._stage, strip_markers(target), op == "<<-"))
            return True
        if fd is None:
            fd = 0 if op in ("<", "<<<") else 1
        self._stage.redirects.append(_Redirect(op, fd, target))
        return True

    def _read_heredoc_bodies(self) -> None:
        """Consume the lines after a newline that belong to pending heredocs."""
        for pending in self._pending_heredocs:
            lines: list[str] = []
            size = 0
            terminated = False
            while self.pos < len(self.text):
                end = self.text.find("\n", self.pos)
                if end == -1:
                    line, self.pos = self.text[self.pos:], len(self.text)
                else:
                    line, self.pos = self.text[self.pos:end], end + 1
                candidate = line.lstrip("\t") if pending.strip_tabs else line
                if candidate.rstrip("\r") == pending.delimiter:
                    terminated = True
                    break
                size += len(candidate) + 1
                if size > MAX_OUTPUT_BYTES:
                    continue
                lines.append(candidate)
            body = "".join(line + "\n" for line in lines)
            pending.stage.heredoc = body.encode("utf-8", errors="surrogateescape")
            if not terminated:
                self.incomplete = True
                self.open_delimiters.append((pending.delimiter, pending.strip_tabs))
        self._pending_heredocs = []

    def _read_word(self) -> Optional[str]:
        """Read one shell word, removing quotes the way the shell would."""
        out: list[str] = []
        text = self.text
        started = self.pos
        has_glob = False
        while self.pos < len(text):
            # A run of ordinary characters is taken in one step. Character by
            # character, a 256 KiB base64 argument was a quarter of a million
            # trips round this loop, three times per command, on the event
            # loop.
            plain = _PLAIN_RUN.match(text, self.pos)
            if plain:
                out.append(plain.group(0))
                self.pos = plain.end()
                continue
            ch = text[self.pos]
            if ch in " \t\r\n;|&<>":
                break
            if self.mark and ch in "$`" and not text.startswith("$'", self.pos):
                marker = self._read_expansion(quoted=False)
                if marker is not None:
                    out.append(marker)
                    continue
            if self.mark and ch in "*?[":
                has_glob = True
            if ch == "\\":
                if self.pos + 1 < len(text):
                    nxt = text[self.pos + 1]
                    if nxt != "\n":
                        out.append(nxt)
                    self.pos += 2
                else:
                    self.pos += 1
                continue
            if ch == "'":
                end = text.find("'", self.pos + 1)
                if end == -1:
                    end = len(text)
                out.append(text[self.pos + 1:end])
                self.pos = end + 1
                continue
            if ch == "$" and self.pos + 1 < len(text) and text[self.pos + 1] == "'":
                end = self._find_ansi_c_end(self.pos + 2)
                out.append(_ansi_c(text[self.pos + 2:end]))
                self.pos = end + 1
                continue
            if ch == '"':
                self.pos += 1
                while self.pos < len(text) and text[self.pos] != '"':
                    if text[self.pos] == "\\" and self.pos + 1 < len(text) and text[self.pos + 1] in '"\\$`\n':
                        if text[self.pos + 1] != "\n":
                            out.append(text[self.pos + 1])
                        self.pos += 2
                        continue
                    if self.mark and text[self.pos] in "$`":
                        marker = self._read_expansion(quoted=True)
                        if marker is not None:
                            out.append(marker)
                            continue
                    out.append(text[self.pos])
                    self.pos += 1
                self.pos += 1
                continue
            out.append(ch)
            self.pos += 1
        if self.pos == started:
            return None
        word = "".join(out)
        return GLOB + word if has_glob else word

    def _read_expansion(self, quoted: bool) -> Optional[str]:
        """Consume ``$NAME``, ``${…}``, ``$(…)``, ``$((…))`` or backticks.

        Returns the marker that stands for it, or None — with the position
        untouched — when what is here is just a dollar sign or a backtick.
        """
        text, pos = self.text, self.pos

        def marker(kind: str, body: str, end: int) -> str:
            self.pos = end
            return OPEN + (kind.upper() if quoted else kind) + body + CLOSE

        if text[pos] == "`":
            end = text.find("`", pos + 1)
            if end == -1:
                return None
            return marker("c", text[pos + 1:end], end + 1)
        if text.startswith("$((", pos):
            end = text.find("))", pos + 3)
            if end != -1:
                return marker("a", text[pos + 3:end], end + 2)
        if text.startswith("$(", pos):
            end = self._matching_paren(pos + 1)
            if end == -1:
                return None
            return marker("c", text[pos + 2:end], end + 1)
        if text.startswith("${", pos):
            end = text.find("}", pos + 2)
            if end == -1:
                return None
            return marker("v", text[pos + 2:end], end + 1)
        name = _VARIABLE_NAME.match(text, pos + 1)
        if name:
            return marker("v", name.group(0), name.end())
        return None

    def _matching_paren(self, start: int) -> int:
        """Index of the ``)`` closing the ``(`` at ``start``, or -1."""
        text = self.text
        depth = 0
        pos = start
        while pos < len(text):
            ch = text[pos]
            if ch == "\\":
                pos += 2
                continue
            if ch in "'\"":
                closing = text.find(ch, pos + 1)
                if closing == -1:
                    return -1
                pos = closing + 1
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return pos
            pos += 1
        return -1

    def _find_ansi_c_end(self, start: int) -> int:
        pos = start
        while pos < len(self.text):
            if self.text[pos] == "\\":
                pos += 2
                continue
            if self.text[pos] == "'":
                return pos
            pos += 1
        return len(self.text)


# --------------------------------------------------------------------------
# Escape handling
# --------------------------------------------------------------------------


_SIMPLE_ESCAPES = {
    "a": b"\a", "b": b"\b", "e": b"\x1b", "E": b"\x1b", "f": b"\f",
    "n": b"\n", "r": b"\r", "t": b"\t", "v": b"\v", "\\": b"\\",
    "'": b"'", '"': b'"', "?": b"?",
}


def _to_bytes(text: str) -> bytes:
    """Encode a word back to the bytes the shell would have had.

    ``surrogateescape`` round-trips any byte an ANSI-C escape produced.
    """
    return text.encode("utf-8", errors="surrogateescape")


def _ansi_c(body: str) -> str:
    data = _interpret_escapes(_to_bytes(body), octal_prefix_zero=False)[0]
    return data.decode("utf-8", errors="surrogateescape")


def _interpret_escapes(data: bytes, octal_prefix_zero: bool) -> tuple[bytes, bool]:
    """Interpret backslash escapes as ``echo -e`` / ``printf`` do.

    Returns the bytes and whether a ``\\c`` asked for output to stop there.
    ``echo -e`` writes octal as ``\\0nnn``; ``printf`` and ``$'…'`` as ``\\nnn``.
    """
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        byte = data[i]
        if byte != 0x5C or i + 1 >= n:  # backslash
            out.append(byte)
            i += 1
            continue
        esc = chr(data[i + 1])
        if esc == "c":
            return bytes(out), True
        if esc == "x":
            digits = re.match(rb"[0-9A-Fa-f]{1,2}", data[i + 2:i + 4])
            if digits:
                out.append(int(digits.group(0), 16))
                i += 2 + len(digits.group(0))
                continue
            out += b"\\x"
            i += 2
            continue
        if esc in ("u", "U"):
            width = 4 if esc == "u" else 8
            digits = re.match(rb"[0-9A-Fa-f]{1,%d}" % width, data[i + 2:i + 2 + width])
            if digits:
                try:
                    out += chr(int(digits.group(0), 16)).encode("utf-8")
                except (ValueError, OverflowError):
                    pass
                i += 2 + len(digits.group(0))
                continue
        if octal_prefix_zero and esc == "0":
            digits = re.match(rb"[0-7]{0,3}", data[i + 2:i + 5])
            out.append(int(digits.group(0) or b"0", 8) & 0xFF)
            i += 2 + len(digits.group(0))
            continue
        if not octal_prefix_zero and esc in "01234567":
            digits = re.match(rb"[0-7]{1,3}", data[i + 1:i + 4])
            out.append(int(digits.group(0), 8) & 0xFF)
            i += 1 + len(digits.group(0))
            continue
        if esc in _SIMPLE_ESCAPES:
            out += _SIMPLE_ESCAPES[esc]
            i += 2
            continue
        out += data[i:i + 2]
        i += 2
    return bytes(out), False


# --------------------------------------------------------------------------
# Command models
# --------------------------------------------------------------------------


def _echo(args: list[str]) -> bytes:
    interpret, newline = False, True
    while args and re.fullmatch(r"-[neE]+", args[0]):
        flags = args.pop(0)[1:]
        for flag in flags:
            if flag == "n":
                newline = False
            elif flag == "e":
                interpret = True
            elif flag == "E":
                interpret = False
    data = _to_bytes(" ".join(args))
    if interpret:
        data, stop = _interpret_escapes(data, octal_prefix_zero=True)
        if stop:
            return data
    return data + (b"\n" if newline else b"")


def _printf(args: list[str]) -> Optional[bytes]:
    if not args:
        return None
    fmt, rest = _to_bytes(args[0]), [_to_bytes(a) for a in args[1:]]
    out = bytearray()
    # printf reuses the format for as long as arguments remain and the format
    # actually consumes them; the pass count is bounded either way.
    for _ in range(256 if rest else 1):
        consumed_any = False
        i = 0
        while i < len(fmt):
            # Literal text between conversions is copied in one piece. Byte
            # by byte, a 256 KiB format reused for 256 arguments was tens of
            # millions of interpreter steps on the event loop.
            special = _PRINTF_SPECIAL.search(fmt, i)
            if special is None or special.start() > i:
                end = len(fmt) if special is None else special.start()
                out += fmt[i:end]
                i = end
                if len(out) > MAX_OUTPUT_BYTES:
                    return None
                continue
            byte = fmt[i]
            if byte == 0x5C:  # backslash
                length = _escape_length(fmt, i)
                chunk, stop = _interpret_escapes(fmt[i:i + length], octal_prefix_zero=False)
                out += chunk
                if stop:
                    return bytes(out)
                i += length
                continue
            if byte == 0x25 and i + 1 < len(fmt):  # %
                spec = _PRINTF_SPEC.match(fmt, i)
                if not spec:
                    out.append(byte)
                    i += 1
                    continue
                conv = spec.group(1)
                i += len(spec.group(0))
                if conv == b"%":
                    out += b"%"
                    continue
                value = rest.pop(0) if rest else b""
                consumed_any = True
                if conv == b"s":
                    out += value
                elif conv == b"b":
                    decoded, stop = _interpret_escapes(value, octal_prefix_zero=True)
                    out += decoded
                    if stop:
                        return bytes(out)
                elif conv == b"c":
                    out += value[:1]
                else:
                    try:
                        number = int(value or b"0", 0)
                    except ValueError:
                        number = 0
                    formatted = {b"d": "%d", b"i": "%d", b"x": "%x", b"X": "%X", b"o": "%o"}[conv]
                    out += (formatted % number).encode()
                if len(out) > MAX_OUTPUT_BYTES:
                    return None
                continue
            out.append(byte)
            i += 1
        if not rest or not consumed_any:
            break
    return bytes(out)


def _escape_length(fmt: bytes, i: int) -> int:
    if i + 1 >= len(fmt):
        return 1
    esc = chr(fmt[i + 1])
    if esc == "x":
        digits = re.match(rb"[0-9A-Fa-f]{1,2}", fmt[i + 2:i + 4])
        return 2 + (len(digits.group(0)) if digits else 0)
    if esc in "01234567":
        digits = re.match(rb"[0-7]{1,3}", fmt[i + 1:i + 4])
        return 1 + len(digits.group(0))
    return 2


def _base64_decode(data: bytes, ignore_garbage: bool) -> Optional[bytes]:
    cleaned = _B64_JUNK.sub(b"", data) if ignore_garbage else re.sub(rb"\s+", b"", data)
    if not cleaned:
        return b""
    cleaned = cleaned.replace(b"-", b"+").replace(b"_", b"/")
    cleaned += b"=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=not ignore_garbage)
    except (binascii.Error, ValueError):
        return None


def _hex_decode(data: bytes) -> Optional[bytes]:
    cleaned = _HEX_JUNK.sub(b"", data)
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return binascii.unhexlify(cleaned)
    except binascii.Error:
        return None


def _gzip_decompresses(args: list[str]) -> bool:
    """``gzip -d``, ``-dc``, ``--decompress`` — but not ``--stdout``."""
    for arg in args:
        if arg in ("--decompress", "--uncompress"):
            return True
        if re.fullmatch(r"-[a-zA-Z0-9]*d[a-zA-Z0-9]*", arg):
            return True
    return False


def _gunzip(data: bytes) -> Optional[bytes]:
    """Decompress with a hard output cap; a gzip bomb stops at the cap."""
    try:
        decompressor = zlib.decompressobj(47)  # auto-detect gzip or zlib header
        out = decompressor.decompress(data, MAX_OUTPUT_BYTES)
        if decompressor.unconsumed_tail:
            return None
        return out
    except zlib.error:
        return None


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


ReadFile = Callable[[str], Optional[bytes]]


class _LineDirectories:
    """The session's directories plus the ones this line has made so far.

    ``mkdir -p /tmp/.x && cd /tmp/.x`` has to work inside one line, before
    the emulator has run the ``mkdir`` for real.
    """

    def __init__(self, base: Directories) -> None:
        self._base = base
        self.made: set[str] = set()

    def exists(self, path: str) -> bool:
        return path in self.made or self._base.exists(path)

    def is_dir(self, path: str) -> bool:
        return path in self.made or self._base.is_dir(path)

    def can_enter(self, path: str) -> bool:
        return path in self.made or self._base.can_enter(path)


class _Evaluator:
    def __init__(
        self,
        cwd: str,
        home: str,
        read_file: ReadFile,
        depth: int,
        env: Optional[dict[str, str]] = None,
        dirs: Optional[Directories] = None,
        substitute: Optional[Callable[[str], str]] = None,
    ) -> None:
        self.cwd = cwd
        self.home = home
        self.read_file = read_file
        self.depth = depth
        self.result = Interpretation()
        self.shadow = False
        #: Exit status of the last statement that ran, for ``&&`` and ``||``.
        #: Only what this module can know fails: a ``cd`` to somewhere that is
        #: not there, and ``false``. Everything else is taken to succeed.
        self.status = 0
        self._stage_status = 0
        self.previous_cwd: Optional[str] = None
        #: A private copy of the session's variables. The emulator runs the
        #: same line afterwards and makes the assignments for real; doing
        #: them twice on the shared state would double ``X=$X:more``.
        self.env = dict(env) if env is not None else None
        self.dirs = _LineDirectories(dirs or AnyDirectory())
        self.substitute = substitute
        self.expander = (
            Expander(self._lookup, substitute) if env is not None else None
        )
        #: Files written earlier in this same line, visible to later stages:
        #: whole contents for a path this line (re)wrote, and for a path that
        #: existed before the line only the bytes appended to it. Appending
        #: used to copy the whole file each time, so an echoloader's N chunks
        #: on one line cost N²/2 bytes of copying.
        self._local: dict[str, bytearray] = {}
        self._appended: dict[str, bytearray] = {}

    # -- variables ---------------------------------------------------------

    def _lookup(self, name: str) -> Optional[str]:
        if name == "PWD":
            return self.cwd
        if name == "HOME":
            return self.home
        if name == "?":
            return str(self.status)
        return (self.env or {}).get(name)

    def _set_variable(self, name: str, value: str) -> None:
        if self.env is not None and not self.shadow:
            self.env[name] = value[:MAX_VARIABLE_CHARS]

    def _words(self, words: list[str]) -> list[str]:
        if self.expander is None:
            return list(words)
        return self.expander.words(words, MAX_WORDS)

    def _text(self, word: str) -> str:
        return word if self.expander is None else self.expander.text(word)

    # -- files -------------------------------------------------------------

    def resolve(self, path: str) -> str:
        return resolve_path(self.cwd, path, self.home)

    def read(self, path: str) -> Optional[bytes]:
        resolved = self.resolve(path)
        if resolved in self._local:
            return bytes(self._local[resolved])
        if resolved in self._appended:
            return (self.read_file(resolved) or b"") + bytes(self._appended[resolved])
        return self.read_file(resolved)

    # -- control flow ------------------------------------------------------

    def run(self, statements: list[tuple[str, list[_Stage]]]) -> Interpretation:
        stdout = bytearray()
        known = True
        if self.expander is not None:
            ops = compile_program(statements)
        else:
            ops = [("run", connector, pipeline) for connector, pipeline in statements]
        walker = ProgramWalker(ops, self._words, self._set_variable)
        while True:
            step = walker.next(self.status)
            if step is None:
                break
            connector, pipeline = step
            # A branch the shell would skip — the right of `||` after a
            # success, the right of `&&` after a failure — is still read for
            # what it carries: `wget … || echo -ne … > f` holds the payload
            # in the fallback. But it must not move the working directory,
            # set a variable or print anything.
            self.shadow = (connector == "||" and self.status == 0) or (
                connector == "&&" and self.status != 0
            )
            self._stage_status = 0
            printed = self._pipeline(pipeline)
            if self.shadow:
                continue
            self.status = self._stage_status
            if printed is None:
                known = False
            elif known:
                stdout += printed
        self.result.stdout = bytes(stdout) if known else None
        return self.result

    def _pipeline(self, stages: list[_Stage]) -> Optional[bytes]:
        """Run one pipeline; return what reaches the terminal."""
        data: Optional[bytes] = b""
        method = ""
        for index, stage in enumerate(stages):
            piped_in = data if index > 0 else None
            self._stage_status = 0
            data, method = self._stage(stage, piped_in, method)
            data = self._apply_redirects(stage, data, method)
        return data

    def _stage(
        self, stage: _Stage, piped_in: Optional[bytes], method: str
    ) -> tuple[Optional[bytes], str]:
        words = self._words(stage.words)
        assignments = []
        while words and ASSIGNMENT.match(words[0]):
            assignments.append(words.pop(0))
        if assignments and not words:
            # `NAME=value` on its own sets a shell variable; in front of a
            # command it only applies to that command, which nothing here
            # reads.
            for assignment in assignments:
                name, value = ASSIGNMENT.match(assignment).groups()
                self._set_variable(name, value)
        while words and words[0] in TRANSPARENT_PREFIXES:
            words.pop(0)
        if words and words[0] == "timeout" and len(words) > 2:
            words = words[2:]
        if words and posixpath.basename(words[0]) == "busybox" and len(words) > 1:
            words = words[1:]

        stdin = piped_in
        if stage.heredoc is not None:
            stdin, method = stage.heredoc, "heredoc"
        for redirect in stage.redirects:
            if redirect.op == "<<<":
                stdin, method = _to_bytes(self._text(redirect.target)) + b"\n", "herestring"
            elif redirect.op == "<" and redirect.fd == 0:
                stdin = self.read(self._text(redirect.target))

        if not words:
            return stdin, method

        name = posixpath.basename(words[0])
        args = words[1:]

        if name == "cd":
            target, _error = change_directory(
                args, self.cwd, self.home, self.previous_cwd, self.dirs
            )
            if target is None:
                self._stage_status = 1
            elif not self.shadow:
                self.previous_cwd, self.cwd = self.cwd, target
            return b"", method
        if name == "mkdir":
            if not self.shadow:
                parents = any(a.startswith("-") and "p" in a for a in args)
                for arg in (a for a in args if not a.startswith("-")):
                    path = self.resolve(arg)
                    while path != "/" and len(self.dirs.made) < 256:
                        self.dirs.made.add(path)
                        if not parents:
                            break
                        path = posixpath.dirname(path)
            return b"", method
        if name in ("export", "declare", "local", "readonly"):
            for arg in args:
                match = ASSIGNMENT.match(arg)
                if match:
                    self._set_variable(match.group(1), match.group(2))
            return b"", method
        if name == "unset":
            if self.env is not None and not self.shadow:
                for arg in args:
                    self.env.pop(arg, None)
            return b"", method
        if name == "false":
            self._stage_status = 1
            return b"", method
        if name == "echo":
            return _echo(args), "echo"
        if name == "printf":
            return _printf(args), "printf"
        if name == "cat":
            files = [a for a in args if not a.startswith("-") or a == "-"]
            if not files:
                return stdin, method or "cat"
            parts = []
            total = 0
            for f in files:
                content = stdin if f == "-" else self.read(f)
                if content is None:
                    return None, method
                # `cat f f f …` with thousands of arguments: stop as soon as
                # the result is past anything that could be captured, rather
                # than assembling hundreds of megabytes to throw away.
                total += len(content)
                if total > MAX_OUTPUT_BYTES:
                    return None, method
                parts.append(content)
            return b"".join(parts), method or "cat"
        if name == "base64":
            flags = [a for a in args if a.startswith("-")]
            decode = any(f in ("-d", "--decode", "-D") or re.fullmatch(r"-[a-zA-Z]*d[a-zA-Z]*", f) for f in flags)
            files = [a for a in args if not a.startswith("-")]
            source = self.read(files[0]) if files else stdin
            if source is None:
                return None, method
            if not decode:
                return base64.b64encode(source) + b"\n", method
            ignore = any(f in ("-i", "--ignore-garbage") or ("i" in f and not f.startswith("--")) for f in flags)
            return _base64_decode(source, ignore), "base64"
        if name == "openssl" and args:
            if ("base64" in args or "-base64" in args or "-a" in args) and "-d" in args:
                return (_base64_decode(stdin, True) if stdin is not None else None), "base64"
            return None, method
        if name == "xxd":
            if ("-r" in args and "-p" in args) or "-rp" in args or "-pr" in args:
                return (_hex_decode(stdin) if stdin is not None else None), "xxd"
            return None, method
        if name in ("gunzip", "zcat") or (name == "gzip" and _gzip_decompresses(args)):
            return (_gunzip(stdin) if stdin is not None else None), (method + "+gzip" if method else "gzip")
        if name == "tee":
            append = any(a in ("-a", "--append") for a in args)
            for target in (a for a in args if not a.startswith("-")):
                self._write(target, stdin, append, method or "tee")
            return stdin, method
        if name in INTERPRETERS:
            return self._interpreter(name, args, stdin, method)
        if name in ("true", ":"):
            return b"", method
        return None, method

    def _interpreter(
        self, name: str, args: list[str], stdin: Optional[bytes], method: str
    ) -> tuple[Optional[bytes], str]:
        if name in ("sh", "bash", "dash", "ash", "zsh", "ksh") and "-c" in args:
            index = args.index("-c")
            if index + 1 < len(args) and self.depth < MAX_NESTING:
                nested = interpret(
                    args[index + 1], self.cwd, self.home, self.read, self.depth + 1,
                    env=self.env, dirs=self.dirs, substitute=self.substitute,
                )
                self.result.writes.extend(nested.writes)
                self.result.executions.extend(nested.executions)
                return nested.stdout, method
            return None, method
        script_args = [a for a in args if not a.startswith("-")]
        if not script_args and stdin:
            self.result.executions.append(
                Execution(content=stdin, interpreter=name, method=method or "pipe")
            )
        # Output of an executed program is unknowable without running it.
        return None, method

    def _apply_redirects(
        self, stage: _Stage, data: Optional[bytes], method: str
    ) -> Optional[bytes]:
        for redirect in stage.redirects:
            if redirect.fd != 1 or redirect.op not in (">", ">>"):
                continue
            self._write(self._text(redirect.target), data, redirect.op == ">>", method)
            data = b""
        return data

    def _write(
        self, target: str, data: Optional[bytes], append: bool, method: str
    ) -> None:
        if data is None or not target:
            return
        path = self.resolve(target)
        if path in _DISCARD_TARGETS or (path.startswith(("/dev/", "/proc/", "/sys/")) and not path.startswith("/dev/shm/")):
            return
        if len(data) > MAX_OUTPUT_BYTES:
            return
        # Appends extend a buffer in place; nothing here reads the file that
        # is being appended to, let alone copies it.
        if not append:
            self._local[path] = bytearray(data)
            self._appended.pop(path, None)
        else:
            buffer = self._local.get(path)
            if buffer is None:
                buffer = self._appended.setdefault(path, bytearray())
            if len(buffer) + len(data) <= MAX_OUTPUT_BYTES:
                buffer += data
        self.result.writes.append(
            Write(path=path, content=data, append=append, method=method or "redirect")
        )


def interpret(
    command_line: str,
    cwd: str = "/home/user",
    home: str = "/home/user",
    read_file: Optional[ReadFile] = None,
    depth: int = 0,
    env: Optional[dict[str, str]] = None,
    dirs: Optional[Directories] = None,
    substitute: Optional[Callable[[str], str]] = None,
) -> Interpretation:
    """Work out what a command line writes, without running any of it.

    ``env`` turns on variable expansion and loops, with those variables as
    the starting values (it is copied, not modified). ``dirs`` says which
    directories exist, so a ``cd`` fails here exactly when the emulator's
    does. ``substitute`` evaluates ``$(…)``; without it the text is kept as
    typed. With none of the three the line is read literally and every
    ``cd`` works.
    """
    statements = _Lexer(command_line, mark=env is not None).run()
    evaluator = _Evaluator(
        cwd, home, read_file or (lambda _path: None), depth,
        env=env, dirs=dirs, substitute=substitute,
    )
    return evaluator.run(statements)


def needs_continuation(command_line: str) -> bool:
    """Whether bash would keep reading lines before running this.

    True while a heredoc is open. An interactive session receives a pasted or
    piped script one line at a time, so without this the body of every
    ``cat > f << EOF`` would be dispatched as separate commands and lost.
    """
    lexer = _Lexer(command_line)
    lexer.run()
    return lexer.incomplete


def open_heredoc_delimiters(command_line: str) -> list[tuple[str, bool]]:
    """The heredoc delimiters a command line is still waiting for, in order."""
    lexer = _Lexer(command_line)
    lexer.run()
    return list(lexer.open_delimiters) if lexer.incomplete else []


class HeredocBuffer:
    """Lines of a command whose heredoc has not closed yet.

    The interactive shell used to re-lex the whole accumulated text on every
    new line to ask whether the heredoc was still open, which made a body of
    L lines cost L²/2 work on the event loop every other connection shares:
    twenty thousand blank lines after ``cat > x <<EOF`` froze the engine for
    minutes. The delimiters are now worked out once, when the heredoc opens,
    and each new line is compared against the next one owed.
    """

    #: Lines one heredoc may run to before it is closed by force. Droppers
    #: that arrive this way are a few hundred lines; the byte cap below is
    #: the real bound on content.
    MAX_LINES = 5000

    def __init__(self, first_line: str, max_bytes: int) -> None:
        self._lines = [first_line]
        self._size = len(first_line) + 1
        self._max_bytes = max_bytes
        self._delimiters = open_heredoc_delimiters(first_line)

    @property
    def open(self) -> bool:
        """Whether bash would still be reading lines."""
        return bool(self._delimiters) and not self.exhausted

    @property
    def exhausted(self) -> bool:
        return len(self._lines) >= self.MAX_LINES or self._size >= self._max_bytes

    def feed(self, line: str) -> None:
        self._lines.append(line)
        self._size += len(line) + 1
        if not self._delimiters:
            return
        delimiter, strip_tabs = self._delimiters[0]
        candidate = line.lstrip("\t") if strip_tabs else line
        if candidate.rstrip("\r") == delimiter:
            self._delimiters.pop(0)

    def text(self) -> str:
        return "\n".join(self._lines)
