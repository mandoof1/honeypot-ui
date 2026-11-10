"""A small, bounded shell reader for attacker command lines.

The rule layer used to match regular expressions against the whole session
text, so a verdict followed *mentions*: a comment naming a tool raised the
severity, ``ls /etc/cron.d`` read as persistence, and ``w'g'et`` or
``a=wg; b=et; $a$b`` read as nothing at all. This turns each recorded line
into the simple commands a shell would run — command name in command
position, arguments, pipes and redirections — so rules can look at what was
done rather than what was typed near it.

It is not a shell. It handles what attackers actually use to dodge string
matching (quotes, backslashes, ``${IFS}``, variables assigned earlier in the
session, ``{a,b}`` braces, ``$(...)`` and backticks, ``sh -c '...'``) and
ignores the rest. One pass over the input, every loop bounded: the text is
hostile and this runs inside the ingest budget.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

#: Characters of one recorded line that are read. A longer line keeps its
#: start and its end, which is where a command and its target are.
MAX_LINE_CHARS = 8192
#: Words kept per simple command, and characters kept per word.
MAX_WORDS = 128
MAX_WORD_CHARS = 2048
#: Simple commands produced from one recorded line, nested ones included.
MAX_COMMANDS_PER_LINE = 64
#: ``sh -c "sh -c '...'"`` and ``$(...)`` nesting that is followed.
MAX_DEPTH = 3
#: Variables remembered across a session, and the length of each value.
MAX_VARIABLES = 64
MAX_VARIABLE_CHARS = 1024

_OPERATOR_CHARS = "|&;\n"
_WORD_BREAK = " \t\r"
_NAME_START = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
_NAME_CHARS = _NAME_START + "0123456789"

#: Runs of characters with no meaning to the reader are copied in one step
#: rather than one character at a time.
_PLAIN = re.compile(r"[^ \t\r\n\\'\"$`#<>|&;()]+")
_PLAIN_QUOTED = re.compile(r'[^"\\$`]+')

#: Programs that run their arguments as a command. The name maps to the
#: options that take a value, so ``nice -n 5 id`` skips both words.
_WRAPPERS: Dict[str, frozenset] = {
    "nohup": frozenset(),
    "time": frozenset(),
    "exec": frozenset({"-a"}),
    "command": frozenset(),
    "builtin": frozenset(),
    "setsid": frozenset(),
    "nice": frozenset({"-n"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "timeout": frozenset({"-s", "-k"}),
    "env": frozenset({"-u"}),
    "xargs": frozenset({"-I", "-n", "-P", "-L", "-d", "-s", "-E"}),
    "watch": frozenset({"-n"}),
}
SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh", "ksh"})
_SUDO_VALUE_OPTIONS = frozenset({"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-D"})
_DECLARATIONS = frozenset({"export", "declare", "local", "readonly", "typeset"})


@dataclass
class Command:
    """One simple command, as a shell would have run it."""

    argv: List[str]
    #: Index of the recorded line it came from.
    line: int
    #: The command's own text, for the analyst and the evidence trail.
    raw: str = ""
    pipe_in: bool = False
    pipe_out: bool = False
    #: Redirection targets: files written (``>``, ``>>``) and read (``<``).
    writes: List[str] = field(default_factory=list)
    reads: List[str] = field(default_factory=list)
    #: Ran through sudo or doas.
    elevated: bool = False
    #: Ran as a busybox applet.
    busybox: bool = False
    #: How it came to run when not typed directly: "sh -c", "$()", "eval",
    #: "echo | sh".
    via: str = ""
    depth: int = 0

    @property
    def name(self) -> str:
        """The program, without its directory and lower-cased."""
        if not self.argv:
            return ""
        return self.argv[0].rsplit("/", 1)[-1].lower()

    @property
    def args(self) -> List[str]:
        return self.argv[1:]


@dataclass
class _Raw:
    """A simple command before wrappers are unwrapped."""

    words: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    reads: List[str] = field(default_factory=list)
    nested: List[str] = field(default_factory=list)
    pipe_in: bool = False
    pipe_out: bool = False
    start: int = 0
    end: int = 0


class ShellSession:
    """Variables assigned so far, carried from one recorded line to the next."""

    def __init__(self) -> None:
        self.variables: Dict[str, str] = {}

    def assign(self, name: str, value: str) -> None:
        if name in self.variables or len(self.variables) < MAX_VARIABLES:
            self.variables[name] = value[:MAX_VARIABLE_CHARS]


def bounded_line(text: str) -> str:
    """One recorded line, cut to its start and end when it is too long."""
    if len(text) <= MAX_LINE_CHARS:
        return text
    head = MAX_LINE_CHARS * 3 // 4
    # A newline between the two halves, so the cut cannot join two commands
    # into one that neither of them was.
    return text[:head] + "\n" + text[-(MAX_LINE_CHARS - head):]


def _ansi_c(body: str) -> str:
    """Decode the escapes of a ``$'...'`` string."""
    out: List[str] = []
    i, n = 0, len(body)
    simple = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "", "e": "\x1b"}
    while i < n:
        ch = body[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "x":
            digits = body[i + 2 : i + 4]
            try:
                out.append(chr(int(digits, 16)))
                i += 2 + len(digits)
                continue
            except ValueError:
                pass
        if nxt in "01234567":
            j = i + 1
            while j < n and j < i + 4 and body[j] in "01234567":
                j += 1
            out.append(chr(int(body[i + 1 : j], 8) & 0xFF))
            i = j
            continue
        out.append(simple.get(nxt, nxt))
        i += 2
    return "".join(out)


def _matching_paren(text: str, start: int) -> int:
    """Index just past the ``)`` that closes the ``(`` before ``start``."""
    depth = 1
    quote = ""
    i, n = start, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            i += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _is_assignment(word: str) -> Optional[Tuple[str, str]]:
    cut = word.find("=")
    if cut <= 0 or word[0] not in _NAME_START:
        return None
    name = word[:cut]
    if any(c not in _NAME_CHARS for c in name):
        return None
    return name, word[cut + 1 :]


class _Reader:
    """Splits one line into raw simple commands."""

    def __init__(self, text: str, session: ShellSession) -> None:
        self.text = text
        self.session = session
        self.commands: List[_Raw] = []
        self._current = _Raw()
        self._word: List[str] = []
        self._has_word = False
        #: Where the next redirection target goes: "w", "r" or "".
        self._redirect = ""

    # -- word assembly ------------------------------------------------------

    def _end_word(self) -> None:
        if not self._has_word:
            return
        word = "".join(self._word)[:MAX_WORD_CHARS]
        self._word, self._has_word = [], False
        if self._redirect:
            target = self._current.writes if self._redirect == "w" else self._current.reads
            target.append(word)
            self._redirect = ""
            return
        if len(self._current.words) < MAX_WORDS:
            self._current.words.append(word)

    def _end_command(self, position: int, pipe: bool = False) -> None:
        self._end_word()
        self._redirect = ""
        current = self._current
        current.end = position
        self._remember_assignments(current)
        if current.words or current.writes or current.reads or current.nested:
            current.pipe_out = pipe
            self.commands.append(current)
        self._current = _Raw(pipe_in=pipe, start=position + 1)

    def _remember_assignments(self, command: _Raw) -> None:
        """Record ``NAME=value`` as soon as its command ends.

        Done here rather than after the whole line is read, so that
        ``a=wg; b=et; $a$b http://…`` expands on the same line it was set.
        """
        words = command.words
        while words:
            assignment = _is_assignment(words[0])
            if assignment is None:
                break
            self.session.assign(*assignment)
            words = words[1:]
        command.words = words
        if words and words[0] in _DECLARATIONS:
            for word in words[1:]:
                assignment = _is_assignment(word)
                if assignment:
                    self.session.assign(*assignment)

    def _add(self, text: str) -> None:
        self._word.append(text)
        self._has_word = True

    def _expand(self, name: str) -> None:
        """Substitute a variable, splitting on IFS as an unquoted one would."""
        if name == "IFS":
            self._end_word()
            return
        value = self.session.variables.get(name)
        if value:
            self._add(value)

    # -- the scan -----------------------------------------------------------

    def read(self) -> List[_Raw]:
        text = self.text
        i, n = 0, len(text)
        while i < n and len(self.commands) < MAX_COMMANDS_PER_LINE:
            ch = text[i]

            if ch in _WORD_BREAK:
                self._end_word()
                i += 1
            elif ch == "\\":
                if i + 1 < n and text[i + 1] != "\n":
                    self._add(text[i + 1])
                i += 2
            elif ch == "'":
                end = text.find("'", i + 1)
                end = n if end < 0 else end
                self._add(text[i + 1 : end])
                i = end + 1
            elif ch == '"':
                i = self._double_quoted(i + 1)
            elif ch == "$":
                i = self._dollar(i, quoted=False)
            elif ch == "`":
                end = text.find("`", i + 1)
                end = n if end < 0 else end
                self._current.nested.append(text[i + 1 : end])
                self._has_word = True
                i = end + 1
            elif ch == "#" and not self._has_word:
                # A comment runs to the end of the line and is not evidence.
                end = text.find("\n", i)
                i = n if end < 0 else end
            elif ch in "<>":
                i = self._redirection(i)
            elif ch == "&" and i + 1 < n and text[i + 1] == ">":
                # "&> file" writes both streams; it does not end the command.
                i = self._redirection(i + 1)
            elif ch in _OPERATOR_CHARS:
                pipe = ch == "|" and not text.startswith("||", i)
                self._end_command(i, pipe=pipe)
                i += 1
                # "||", "&&", ";;" and "|&" are one operator.
                if i < n and ch != "\n" and text[i] in "|&;":
                    i += 1
                self._current.start = i
            elif ch in "()":
                # Subshell grouping: the commands inside run as usual.
                self._end_command(i)
                i += 1
            else:
                run = _PLAIN.match(text, i)
                if run is None:
                    self._add(ch)
                    i += 1
                else:
                    self._add(run.group())
                    i = run.end()
        self._end_command(n)
        return self.commands

    def _double_quoted(self, i: int) -> int:
        text, n = self.text, len(self.text)
        self._has_word = True
        while i < n:
            ch = text[i]
            if ch == '"':
                return i + 1
            if ch == "\\":
                if i + 1 < n and text[i + 1] in '"\\$`':
                    self._word.append(text[i + 1])
                else:
                    self._word.append(text[i : i + 2])
                i += 2
            elif ch == "$":
                i = self._dollar(i, quoted=True)
            elif ch == "`":
                end = text.find("`", i + 1)
                end = n if end < 0 else end
                self._current.nested.append(text[i + 1 : end])
                i = end + 1
            else:
                run = _PLAIN_QUOTED.match(text, i)
                self._word.append(run.group())
                i = run.end()
        return n

    def _dollar(self, i: int, quoted: bool) -> int:
        text, n = self.text, len(self.text)
        nxt = text[i + 1] if i + 1 < n else ""
        if nxt == "'" and not quoted:
            end = i + 2
            while end < n and text[end] != "'":
                end += 2 if text[end] == "\\" else 1
            self._add(_ansi_c(text[i + 2 : end]))
            return min(end, n) + 1
        if nxt == "(":
            end = _matching_paren(text, i + 2)
            inner = text[i + 2 : end - 1]
            # "$((1+2))" is arithmetic, not a command.
            if not inner.startswith("("):
                self._current.nested.append(inner)
            self._has_word = True
            return end
        if nxt == "{":
            end = text.find("}", i + 2)
            end = n if end < 0 else end
            body = text[i + 2 : end]
            name = body
            for separator in (":-", ":=", ":+", ":?", "-", "=", "#", "%", "/", ":"):
                cut = body.find(separator)
                if cut > 0:
                    name = body[:cut]
                    break
            self._substitute(name, quoted)
            return end + 1
        if nxt and nxt in _NAME_START:
            end = i + 2
            while end < n and text[end] in _NAME_CHARS:
                end += 1
            self._substitute(text[i + 1 : end], quoted)
            return end
        if nxt and nxt in "0123456789@*?!$#-":
            # Positional and special parameters have no value here.
            return i + 2
        self._add("$")
        return i + 1

    def _substitute(self, name: str, quoted: bool) -> None:
        if not quoted:
            self._expand(name)
            return
        # Inside double quotes nothing is split, so IFS is just a space.
        self._word.append(" " if name == "IFS" else self.session.variables.get(name, ""))
        self._has_word = True

    def _redirection(self, i: int) -> int:
        text, n = self.text, len(self.text)
        # "2>" names a file descriptor, not an argument.
        if self._has_word and all(c in "0123456789" for c in "".join(self._word)):
            self._word, self._has_word = [], False
        self._end_word()
        direction = "w" if text[i] == ">" else "r"
        i += 1
        while i < n and text[i] in "<>|":
            i += 1
        if i < n and text[i] == "&":
            # ">&2" duplicates a descriptor; ">& file" writes one.
            i += 1
            j = i
            while j < n and text[j] in "0123456789-":
                j += 1
            if j > i and (j >= n or text[j] in _WORD_BREAK + _OPERATOR_CHARS):
                return j
        self._redirect = direction
        return i


def _brace_expand(words: List[str]) -> List[str]:
    """``{cat,/etc/passwd}`` is ``cat /etc/passwd``."""
    out: List[str] = []
    for word in words:
        if (
            len(word) > 3 and word[0] == "{" and word[-1] == "}"
            and "," in word and "{" not in word[1:] and " " not in word
        ):
            out.extend(part for part in word[1:-1].split(",") if part)
        else:
            out.append(word)
    return out


def _skip_options(words: List[str], value_options: frozenset, allow_assignments: bool = False) -> int:
    """How many leading words are the wrapper's own options."""
    i = 0
    while i < len(words):
        word = words[i]
        if word == "--":
            return i + 1
        if allow_assignments and _is_assignment(word):
            i += 1
        elif word.startswith("-") and len(word) > 1:
            i += 2 if word in value_options else 1
        else:
            break
    return i


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def parse_line(
    text: str,
    line: int,
    session: Optional[ShellSession] = None,
    depth: int = 0,
    via: str = "",
) -> List[Command]:
    """The simple commands in one recorded line, nested ones after their parent."""
    session = session or ShellSession()
    text = bounded_line(text or "")
    commands: List[Command] = []
    raws = _Reader(text, session).read()

    for index, raw in enumerate(raws):
        words = _brace_expand(raw.words)
        snippet = text[raw.start : raw.end].strip()[:400]
        commands.extend(_unwrap(words, raw, line, snippet, depth, via, session))

        # "echo <text> | sh" runs the text.
        if (
            raw.pipe_out and words and depth < MAX_DEPTH and index + 1 < len(raws)
            and _base(words[0]) in ("echo", "printf")
            and _runs_stdin(raws[index + 1].words)
        ):
            script = " ".join(w for w in words[1:] if not w.startswith("-"))
            commands.extend(parse_line(script, line, session, depth + 1, "echo | sh"))

        if depth < MAX_DEPTH:
            for inner in raw.nested[:8]:
                commands.extend(parse_line(inner, line, session, depth + 1, "$()"))

        if len(commands) >= MAX_COMMANDS_PER_LINE:
            break

    return commands[:MAX_COMMANDS_PER_LINE]


def _runs_stdin(words: List[str]) -> bool:
    """Whether a command is a shell reading its script from the pipe."""
    words = _brace_expand(words)
    while words and _base(words[0]) in ("sudo", "doas", "nohup", "exec", "env", "command"):
        words = words[1:]
    if not words or _base(words[0]) not in SHELLS:
        return False
    # "sh script.sh" and "sh -c ..." take their script from elsewhere.
    rest = words[1:]
    return rest == ["-"] or all(word.startswith("-") and "c" not in word for word in rest)


def _unwrap(
    words: List[str],
    raw: _Raw,
    line: int,
    snippet: str,
    depth: int,
    via: str,
    session: ShellSession,
) -> Iterator[Command]:
    """Yield the command itself, then whatever it was a wrapper for."""
    elevated = False
    busybox = False

    def command(argv: List[str]) -> Command:
        return Command(
            argv=argv, line=line, raw=snippet, pipe_in=raw.pipe_in, pipe_out=raw.pipe_out,
            writes=list(raw.writes), reads=list(raw.reads), elevated=elevated,
            busybox=busybox, via=via, depth=depth,
        )

    for _ in range(6):
        if not words:
            return
        name = _base(words[0])
        if name in ("sudo", "doas"):
            # sudo is something the rules want to see in its own right:
            # "sudo -l" and "sudo -i" have no inner command at all.
            yield command(list(words))
            used = 1 + _skip_options(words[1:], _SUDO_VALUE_OPTIONS, allow_assignments=True)
            words, elevated = words[used:], True
        elif name == "busybox" and len(words) > 1:
            words, busybox = words[1:], True
        elif name in _WRAPPERS:
            rest = words[1:]
            used = _skip_options(rest, _WRAPPERS[name], allow_assignments=name == "env")
            # "timeout 5 cmd": the duration is not the command.
            if name == "timeout" and used < len(rest):
                used += 1
            if used >= len(rest):
                # Nothing wrapped ("env" on its own prints the environment).
                break
            words = rest[used:]
        else:
            break

    if not words:
        return
    yield command(list(words))

    if depth >= MAX_DEPTH:
        return
    name = _base(words[0])
    if name in SHELLS or name == "su":
        # "sh -c '<script>'": the script is the word after the -c flag.
        for position, word in enumerate(words[1:], start=1):
            if word.startswith("-") and not word.startswith("--") and "c" in word:
                if position + 1 < len(words):
                    yield from parse_line(words[position + 1], line, session, depth + 1, f"{name} -c")
                break
            # "su root -c '<script>'": the user comes before the flag.
            if not word.startswith("-") and name != "su":
                break
    elif name == "eval":
        yield from parse_line(" ".join(words[1:]), line, session, depth + 1, "eval")


def select_lines(lines: List[str], max_chars: int) -> Tuple[List[Tuple[int, str]], bool]:
    """The lines to read within a total budget, and whether anything was cut.

    A session longer than the budget keeps the lines at its start and at its
    end and skips the middle. The caller is told, so nothing downstream
    treats a partial read as a full one.
    """
    truncated = any(len(text) > MAX_LINE_CHARS for text in lines)
    bounded = [(index, bounded_line(text)) for index, text in enumerate(lines)]
    if sum(len(text) for _, text in bounded) <= max_chars:
        return bounded, truncated

    head_budget, tail_budget = max_chars * 3 // 4, max_chars // 4
    head: List[Tuple[int, str]] = []
    for index, text in bounded:
        if len(text) > head_budget:
            break
        head.append((index, text))
        head_budget -= len(text)
    last_head = head[-1][0] if head else -1
    tail: List[Tuple[int, str]] = []
    for index, text in reversed(bounded):
        if index <= last_head or len(text) > tail_budget:
            break
        tail.append((index, text))
        tail_budget -= len(text)
    return head + list(reversed(tail)), True


def parse_session(lines: List[str], max_chars: int) -> Tuple[List[Command], bool]:
    """Every simple command of a session, in order, and whether input was cut."""
    session = ShellSession()
    commands: List[Command] = []
    selected, truncated = select_lines(lines, max_chars)
    for index, text in selected:
        commands.extend(parse_line(text, index, session))
    return commands, truncated
