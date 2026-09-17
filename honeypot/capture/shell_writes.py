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
*produce bytes*, evaluated over literal text. No command is executed, no
variable or command substitution is expanded, and no path on the real
filesystem is read or written.

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
_TRANSPARENT_PREFIXES = {"nohup", "exec", "command", "sudo", "time", "nice", "setsid"}

#: Writes to these are discarded by the kernel, not stored.
_DISCARD_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero"}

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_B64_JUNK = re.compile(rb"[^A-Za-z0-9+/=_-]")
_HEX_JUNK = re.compile(rb"[^0-9A-Fa-f]")


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

    def __init__(self, text: str) -> None:
        self.text = text
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
            self._pending_heredocs.append(_Pending(self._stage, target, op == "<<-"))
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
        self._pending_heredocs = []

    def _read_word(self) -> Optional[str]:
        """Read one shell word, removing quotes the way the shell would."""
        out: list[str] = []
        text = self.text
        started = self.pos
        while self.pos < len(text):
            ch = text[self.pos]
            if ch in " \t\r\n;|&<>":
                break
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
                    out.append(text[self.pos])
                    self.pos += 1
                self.pos += 1
                continue
            out.append(ch)
            self.pos += 1
        if self.pos == started:
            return None
        return "".join(out)

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
                spec = re.match(rb"%[-+ #0]*[0-9]*(?:\.[0-9]+)?([sbcdixXo%])", fmt[i:])
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
                continue
            out.append(byte)
            i += 1
            if len(out) > MAX_OUTPUT_BYTES:
                return None
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


class _Evaluator:
    def __init__(self, cwd: str, home: str, read_file: ReadFile, depth: int) -> None:
        self.cwd = cwd
        self.home = home
        self.read_file = read_file
        self.depth = depth
        self.result = Interpretation()
        self.shadow = False
        #: Files written earlier in this same line, visible to later stages.
        self._local: dict[str, bytes] = {}

    def resolve(self, path: str) -> str:
        from honeypot.core.shell_state import resolve_path

        return resolve_path(self.cwd, path, self.home)

    def read(self, path: str) -> Optional[bytes]:
        resolved = self.resolve(path)
        if resolved in self._local:
            return self._local[resolved]
        return self.read_file(resolved)

    def run(self, statements: list[tuple[str, list[_Stage]]]) -> Interpretation:
        stdout = bytearray()
        known = True
        for connector, pipeline in statements:
            # In the emulated host everything the attacker tries succeeds, so
            # the right-hand side of `||` is a branch that would not run. Its
            # content is still captured — `wget … || echo -ne … > f` carries
            # the payload in the fallback — but it must not move the working
            # directory or print anything.
            self.shadow = connector == "||"
            printed = self._pipeline(pipeline)
            if self.shadow:
                continue
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
            data, method = self._stage(stage, piped_in, method)
            data = self._apply_redirects(stage, data, method)
        return data

    def _stage(
        self, stage: _Stage, piped_in: Optional[bytes], method: str
    ) -> tuple[Optional[bytes], str]:
        words = list(stage.words)
        while words and _ASSIGNMENT.match(words[0]):
            words.pop(0)
        while words and words[0] in _TRANSPARENT_PREFIXES:
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
                stdin, method = _to_bytes(redirect.target) + b"\n", "herestring"
            elif redirect.op == "<" and redirect.fd == 0:
                stdin = self.read(redirect.target)

        if not words:
            return stdin, method

        name = posixpath.basename(words[0])
        args = words[1:]

        if name == "cd":
            if not self.shadow:
                self.cwd = self.resolve(args[0]) if args else self.home
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
            for f in files:
                content = stdin if f == "-" else self.read(f)
                if content is None:
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
                    args[index + 1], self.cwd, self.home, self.read, self.depth + 1
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
            self._write(redirect.target, data, redirect.op == ">>", method)
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
        previous = self._local.get(path, b"") if append else b""
        if append and path not in self._local:
            previous = self.read_file(path) or b""
        self._local[path] = (previous + data)[:MAX_OUTPUT_BYTES]
        self.result.writes.append(
            Write(path=path, content=data, append=append, method=method or "redirect")
        )


def interpret(
    command_line: str,
    cwd: str = "/home/user",
    home: str = "/home/user",
    read_file: Optional[ReadFile] = None,
    depth: int = 0,
) -> Interpretation:
    """Work out what a command line writes, without running any of it."""
    statements = _Lexer(command_line).run()
    evaluator = _Evaluator(cwd, home, read_file or (lambda _path: None), depth)
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
