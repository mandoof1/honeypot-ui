"""The parts of shell behaviour both evaluators must agree on.

Two pieces of code read every command line an attacker types. The capture
interpreter (``capture/shell_writes.py``) works out what the line *writes*,
and the emulator (``core/modes.py``) works out what it *prints*. They used to
decide independently what ``cd`` does, and disagreed: capture assumed every
``cd`` succeeds, so ``cd /data/local/tmp || cd /tmp; echo … > .s`` put the
first chunk of a payload under a directory the emulator had just refused,
and the next line's ``>> .s`` under ``/tmp``. One payload, two files.

Everything where a disagreement would split a payload or contradict the
transcript lives here instead, and both sides call it:

* ``change_directory`` — the one answer to "where does this ``cd`` leave us";
* variable, command and arithmetic expansion over the markers the lexer
  leaves in a word, so ``F=.s; echo x > $F`` writes the file the emulator
  will later list;
* ``compile_program`` / ``ProgramWalker`` — ``for``, ``while``/``until`` and
  ``if`` laid out as jumps over the flat statement list, so a loop body runs
  the same number of times, with the same variable values, in both.

Nothing here executes anything. Loops are bounded, expansion has a size
budget, and arithmetic is a small parser over integers rather than ``eval``.
"""

from __future__ import annotations

import dataclasses
import posixpath
import re
from typing import Callable, Optional, Protocol

#: Private-use characters the lexer wraps around an expansion it found
#: outside single quotes: ``OPEN + kind + body + CLOSE``. The kind is ``v``
#: for a variable, ``c`` for ``$(…)`` or backticks, ``a`` for ``$((…))``;
#: upper case when it stood inside double quotes, where the result is not
#: split into words. ``GLOB`` prefixes a word holding an unquoted ``*``,
#: ``?`` or ``[``. Input is scrubbed of all three before lexing, so an
#: attacker cannot type a marker.
OPEN = ""
CLOSE = ""
GLOB = ""

_MARKER = re.compile(f"{OPEN}([vVcCaA])([^{OPEN}{CLOSE}]*){CLOSE}")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)

#: Most text all expansions on one command line may produce. Without it,
#: ``X=<64 KiB>`` followed by a few thousand ``$X`` words is gigabytes.
EXPANSION_BUDGET = 1024 * 1024
#: Longest value a shell variable may hold.
MAX_VARIABLE_CHARS = 64 * 1024


def scrub(text: str) -> str:
    """Remove marker characters from raw input."""
    if OPEN in text or CLOSE in text or GLOB in text:
        return text.replace(OPEN, "�").replace(CLOSE, "�").replace(GLOB, "�")
    return text


def strip_markers(word: str) -> str:
    """A marked word as the literal text the attacker typed, near enough.

    Used where nothing can expand it: the word is shown rather than
    evaluated, so ``$(…)`` comes back as ``$(…)``.
    """
    def literal(match: re.Match) -> str:
        kind, body = match.group(1).lower(), match.group(2)
        if kind == "v":
            return "${" + body + "}" if not _NAME.fullmatch(body) and len(body) > 1 else "$" + body
        if kind == "c":
            return "$(" + body + ")"
        return "$((" + body + "))"

    return _MARKER.sub(literal, word.replace(GLOB, ""))


# --------------------------------------------------------------------------
# Arithmetic
# --------------------------------------------------------------------------

_ARITH_TOKEN = re.compile(r"\s*(\d+|[A-Za-z_][A-Za-z0-9_]*|\*\*|[<>=!]=|&&|\|\||[-+*/%()<>!])")
_ARITH_LIMIT = (1 << 63) - 1


class _Arithmetic:
    """``$((…))`` over integers: + - * / %, comparisons, parentheses.

    A parser rather than ``eval``: the expression is attacker text. Values
    wrap at 64 bits as the shell's do, and ``**`` is refused, so nothing
    here can be made to compute a large number.
    """

    def __init__(self, text: str, lookup: Callable[[str], Optional[str]]) -> None:
        self.tokens = _ARITH_TOKEN.findall(text[:256])
        self.pos = 0
        self.lookup = lookup

    def _peek(self) -> str:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ""

    def _take(self) -> str:
        token = self._peek()
        self.pos += 1
        return token

    @staticmethod
    def _wrap(value: int) -> int:
        value &= (1 << 64) - 1
        return value - (1 << 64) if value > _ARITH_LIMIT else value

    def parse(self) -> int:
        value = self._comparison()
        if self.pos < len(self.tokens):
            raise ValueError("trailing tokens")
        return value

    def _comparison(self) -> int:
        left = self._sum()
        while self._peek() in ("<", ">", "<=", ">=", "==", "!="):
            op = self._take()
            right = self._sum()
            left = int({
                "<": left < right, ">": left > right, "<=": left <= right,
                ">=": left >= right, "==": left == right, "!=": left != right,
            }[op])
        return left

    def _sum(self) -> int:
        left = self._product()
        while self._peek() in ("+", "-"):
            if self._take() == "+":
                left = self._wrap(left + self._product())
            else:
                left = self._wrap(left - self._product())
        return left

    def _product(self) -> int:
        left = self._unary()
        while self._peek() in ("*", "/", "%"):
            op = self._take()
            right = self._unary()
            if op == "*":
                left = self._wrap(left * right)
            elif right == 0:
                raise ValueError("division by zero")
            elif op == "/":
                left = int(left / right)
            else:
                left = left - int(left / right) * right
        return left

    def _unary(self) -> int:
        token = self._take()
        if token == "-":
            return self._wrap(-self._unary())
        if token == "+":
            return self._unary()
        if token == "!":
            return int(not self._unary())
        if token == "(":
            value = self._comparison()
            if self._take() != ")":
                raise ValueError("unbalanced")
            return value
        if token.isdigit():
            return self._wrap(int(token[:19]))
        if _NAME.fullmatch(token or ""):
            raw = (self.lookup(token) or "0").strip()
            try:
                return self._wrap(int(raw[:19]))
            except ValueError:
                return 0
        raise ValueError(f"unexpected {token!r}")


def evaluate_arithmetic(text: str, lookup: Callable[[str], Optional[str]]) -> Optional[int]:
    try:
        return _Arithmetic(text.replace("$", ""), lookup).parse()
    except (ValueError, IndexError, RecursionError):
        return None


# --------------------------------------------------------------------------
# Expansion
# --------------------------------------------------------------------------


class Expander:
    """Expand the markers in lexed words, within a per-line size budget.

    ``lookup`` returns a variable's value or None when it is unset.
    ``substitute`` runs a command substitution and returns its output; when
    it is None the substitution is left as the text that was typed, which is
    what capture did before it knew about either.
    """

    def __init__(
        self,
        lookup: Callable[[str], Optional[str]],
        substitute: Optional[Callable[[str], str]] = None,
        glob: Optional[Callable[[str], list[str]]] = None,
        budget: int = EXPANSION_BUDGET,
    ) -> None:
        self.lookup = lookup
        self.substitute = substitute
        self.glob = glob
        self.budget = budget

    def _spend(self, text: str) -> str:
        if len(text) > self.budget:
            text = text[: max(0, self.budget)]
        self.budget -= len(text)
        return text

    def _variable(self, body: str) -> str:
        # ${NAME:-word} and ${NAME-word}: the only parameter forms droppers
        # lean on. Everything else is looked up as a plain name.
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*|[?$#!@*0-9])(?::?[-=](.*))?$", body, re.DOTALL)
        if not match:
            return ""
        value = self.lookup(match.group(1))
        if (value is None or value == "") and match.group(2) is not None:
            return match.group(2)
        return value or ""

    def _one(self, kind: str, body: str) -> str:
        lowered = kind.lower()
        if lowered == "v":
            return self._spend(self._variable(body))
        if lowered == "a":
            value = evaluate_arithmetic(body, self.lookup)
            return "" if value is None else str(value)
        if self.substitute is None:
            return "$(" + body + ")"
        return self._spend(self.substitute(body).rstrip("\n"))

    def text(self, word: str) -> str:
        """Expand a word to one string: no splitting, no globbing."""
        word = word.replace(GLOB, "")
        if OPEN not in word:
            return word
        return _MARKER.sub(lambda m: self._one(m.group(1), m.group(2)), word)

    def word(self, word: str) -> list[str]:
        """Expand one word to the words it becomes.

        An unquoted expansion standing alone is split on whitespace and
        disappears when empty, as in the shell; mixed with other text it is
        joined in place. A word with an unquoted wildcard becomes the paths
        it matches, or stays as typed when it matches nothing.
        """
        globbing = word.startswith(GLOB)
        if globbing:
            word = word[len(GLOB):]
        alone = _MARKER.fullmatch(word)
        if alone and alone.group(1) in "vca":
            parts = self._one(alone.group(1), alone.group(2)).split()
        else:
            parts = [self.text(word)]
        if globbing and self.glob is not None:
            expanded: list[str] = []
            for part in parts:
                expanded.extend(self.glob(part) or [part])
            return expanded
        return parts

    def words(self, words: list[str], limit: int = 4096) -> list[str]:
        out: list[str] = []
        for word in words:
            out.extend(self.word(word))
            if len(out) >= limit:
                break
        return out[:limit]


def glob_match(pattern: str, name: str) -> bool:
    """``*`` and ``?`` matching, iteratively: linear in both lengths.

    ``fnmatch`` compiles the pattern to a regular expression; this pattern
    is attacker text, so it is matched by hand instead. Bracket expressions
    are treated as literal characters.
    """
    p = n = 0
    star = -1
    mark = 0
    while n < len(name):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == name[n]):
            p += 1
            n += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = n
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            n = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


# --------------------------------------------------------------------------
# Working directory
# --------------------------------------------------------------------------


class Directories(Protocol):
    """What ``cd`` needs to know about the filesystem."""

    def exists(self, path: str) -> bool: ...
    def is_dir(self, path: str) -> bool: ...
    def can_enter(self, path: str) -> bool: ...


class AnyDirectory:
    """Every path is an enterable directory.

    The capture interpreter's stand-in when it is run with no filesystem to
    ask — in unit tests, and for a line pasted in passive mode.
    """

    def exists(self, path: str) -> bool:
        return True

    def is_dir(self, path: str) -> bool:
        return True

    def can_enter(self, path: str) -> bool:
        return True


def resolve_path(cwd: str, arg: str, home: str = "/home/user") -> str:
    """Resolve a shell path argument the way a shell would.

    Handles ``~``, relative segments and ``..``. ``posixpath.normpath``
    collapses ``..`` textually, which is what a shell does for a path that has
    no symlinks in it.
    """
    arg = (arg or "").strip().strip("'\"")
    if not arg or arg == "~":
        return home
    if arg.startswith("~/"):
        arg = posixpath.join(home, arg[2:])
    if not arg.startswith("/"):
        arg = posixpath.join(cwd, arg)
    resolved = posixpath.normpath(arg)
    return resolved if resolved.startswith("/") else "/"


def change_directory(
    args: list[str], cwd: str, home: str, previous: Optional[str], dirs: Directories
) -> tuple[Optional[str], str]:
    """Where ``cd args`` leaves the shell: (new cwd, error text).

    The new cwd is None when the ``cd`` fails, and the text is then what
    bash prints. This is the only implementation of ``cd``; the emulator
    prints the error and the capture interpreter just reads the result, so
    the two cannot place a file in different directories.
    """
    operands = [a for a in args if a == "-" or not a.startswith("-")]
    if len(operands) > 1:
        return None, "-bash: cd: too many arguments\n"
    shown = operands[0] if operands else "~"
    if shown == "-":
        target = previous or cwd
    else:
        target = resolve_path(cwd, shown, home)
    if not dirs.exists(target):
        return None, f"-bash: cd: {shown}: No such file or directory\n"
    if not dirs.is_dir(target):
        return None, f"-bash: cd: {shown}: Not a directory\n"
    if not dirs.can_enter(target):
        return None, f"-bash: cd: {shown}: Permission denied\n"
    return target, ""


# --------------------------------------------------------------------------
# Loops and conditionals
# --------------------------------------------------------------------------

#: Statements one command line may execute, loops unrolled. The lexer caps
#: how many it will *parse*; a loop is how a short line asks for more.
MAX_STEPS = 512
#: Values a ``for`` loop iterates over.
FOR_MAX_VALUES = 64
#: Times a ``while``/``until`` body runs. A real ``while true`` never
#: returns; the body is run enough to record what it does and then the loop
#: is left, which is the nearest thing to it that still ends.
WHILE_MAX_ITERATIONS = 3


class _Unsupported(Exception):
    pass


def _first_word(stages) -> str:
    if stages and stages[0].words:
        return strip_markers(stages[0].words[0])
    return ""


def _without_first_word(stages) -> list:
    """The statement's stages with its leading keyword removed."""
    head = dataclasses.replace(stages[0], words=list(stages[0].words[1:]))
    rest = list(stages[1:])
    if head.words or head.redirects or head.heredoc is not None:
        return [head] + rest
    return rest


def compile_program(statements: list) -> list[tuple]:
    """Lay ``for`` / ``while`` / ``if`` out as jumps over the statements.

    The lexer returns a flat list: ``for i in a b``, ``do wget $i``,
    ``done`` arrive as three unrelated statements, which used to be run as
    three unknown commands. This recognises the keywords at the start of a
    statement and produces a small program:

    ``("run", connector, stages)``
        an ordinary statement;
    ``("for", variable, words, end)``
        bind the next value and fall through, or jump to ``end`` when none
        are left;
    ``("test", negate, end)``
        after a ``while``/``if`` condition: fall through when it held, else
        jump to ``end``;
    ``("done", start, is_while)`` and ``("jump", target)``
        the back edge of a loop, and the skip over an ``else`` branch.

    A line whose keywords do not balance is returned as plain statements,
    which is what it was before.
    """
    try:
        return _compile(statements)
    except _Unsupported:
        return [("run", connector, stages) for connector, stages in statements]


def _compile(statements: list) -> list[tuple]:
    ops: list[tuple] = []
    #: Open constructs: [kind, index of the op to patch, extra].
    stack: list[list] = []

    def run(connector: str, stages: list) -> None:
        if stages:
            ops.append(("run", connector, stages))

    for connector, stages in statements:
        keyword = _first_word(stages)

        if keyword == "for":
            words = [strip_markers(w) if i < 3 else w for i, w in enumerate(stages[0].words)]
            if len(words) < 2 or not _NAME.fullmatch(words[1]):
                raise _Unsupported
            values = list(stages[0].words[3:]) if len(words) > 2 and words[2] == "in" else []
            stack.append(["for", len(ops), None])
            ops.append(("for", words[1], values, -1))
        elif keyword in ("while", "until"):
            stack.append(["while", len(ops), keyword == "until", None])
            run(";", _without_first_word(stages))
        elif keyword == "if":
            stack.append(["if", None, None])
            run(";", _without_first_word(stages))
        elif keyword == "do":
            if not stack or stack[-1][0] not in ("for", "while"):
                raise _Unsupported
            if stack[-1][0] == "while":
                stack[-1][3] = len(ops)
                ops.append(("test", stack[-1][2], -1))
            run(";", _without_first_word(stages))
        elif keyword == "then":
            if not stack or stack[-1][0] != "if" or stack[-1][1] is not None:
                raise _Unsupported
            stack[-1][1] = len(ops)
            ops.append(("test", False, -1))
            run(";", _without_first_word(stages))
        elif keyword == "else":
            if not stack or stack[-1][0] != "if" or stack[-1][1] is None or stack[-1][2] is not None:
                raise _Unsupported
            stack[-1][2] = len(ops)
            ops.append(("jump", -1))
            # A failed condition lands on the first statement of the branch.
            test = ops[stack[-1][1]]
            ops[stack[-1][1]] = (test[0], test[1], len(ops))
            run(";", _without_first_word(stages))
        elif keyword == "fi":
            if not stack or stack[-1][0] != "if" or stack[-1][1] is None:
                raise _Unsupported
            _, test_index, jump_index = stack.pop()
            if jump_index is not None:
                ops[jump_index] = ("jump", len(ops))
            else:
                test = ops[test_index]
                ops[test_index] = (test[0], test[1], len(ops))
        elif keyword == "done":
            if not stack or stack[-1][0] not in ("for", "while"):
                raise _Unsupported
            frame = stack.pop()
            if frame[0] == "for":
                start = frame[1]
                ops.append(("done", start, False))
                op = ops[start]
                ops[start] = (op[0], op[1], op[2], len(ops))
            else:
                start, test_index = frame[1], frame[3]
                if test_index is None:
                    raise _Unsupported
                ops.append(("done", start, True))
                test = ops[test_index]
                ops[test_index] = (test[0], test[1], len(ops))
        elif keyword in ("elif", "case", "esac", "select", "function"):
            raise _Unsupported
        else:
            run(connector, stages)

    if stack:
        raise _Unsupported
    return ops


class ProgramWalker:
    """Step through a compiled program, one ordinary statement at a time.

    The evaluator asks for the next statement, passing the exit status of
    the one it just ran; the walker takes the jumps in between. It holds the
    loop counters and the step budget, so both evaluators stop a loop at the
    same point.
    """

    def __init__(
        self,
        ops: list[tuple],
        expand_values: Callable[[list[str]], list[str]],
        set_variable: Callable[[str, str], None],
        max_steps: int = MAX_STEPS,
    ) -> None:
        self.ops = ops
        self.expand_values = expand_values
        self.set_variable = set_variable
        self.pc = 0
        self.steps = 0
        self.max_steps = max_steps
        self._values: dict[int, list[str]] = {}
        self._iterations: dict[int, int] = {}

    def next(self, last_status: int) -> Optional[tuple[str, list]]:
        # The jump budget is separate from the step budget so an empty loop
        # body, which never returns a statement, still terminates.
        jumps = 0
        while self.pc < len(self.ops) and self.steps < self.max_steps and jumps < 4 * self.max_steps:
            op = self.ops[self.pc]
            kind = op[0]
            jumps += 1
            if kind == "run":
                self.pc += 1
                self.steps += 1
                return op[1], op[2]
            if kind == "for":
                if self.pc not in self._values:
                    self._values[self.pc] = self.expand_values(op[2])[:FOR_MAX_VALUES]
                remaining = self._values[self.pc]
                if remaining:
                    self.set_variable(op[1], remaining.pop(0))
                    self.pc += 1
                else:
                    del self._values[self.pc]
                    self.pc = op[3]
            elif kind == "test":
                held = (last_status == 0) != op[1]
                self.pc = self.pc + 1 if held else op[2]
            elif kind == "done":
                start, is_while = op[1], op[2]
                if not is_while:
                    self.pc = start
                    continue
                count = self._iterations.get(start, 0) + 1
                if count >= WHILE_MAX_ITERATIONS:
                    self._iterations.pop(start, None)
                    self.pc += 1
                else:
                    self._iterations[start] = count
                    self.pc = start
            elif kind == "jump":
                self.pc = op[1]
            else:  # pragma: no cover - compile_program emits nothing else
                self.pc += 1
        return None
