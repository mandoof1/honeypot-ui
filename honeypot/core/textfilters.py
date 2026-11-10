"""Pattern matching and text rewriting on attacker-supplied input, bounded.

``grep``, ``sed`` and ``awk`` take a pattern from the command line and run it
over text that also came from the command line. The emulator used to hand
that pattern to :mod:`re` and run it on the event loop. ``re`` backtracks:
``echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab | grep -E '(a+)+$'`` does not return in
any useful time, and while it runs nothing else does — every SSH, Telnet, FTP
and HTTP session, the heartbeat and the spool all share that loop. One line
from one unauthenticated-in-all-but-name visitor stopped the whole engine.

Everything here is built so that cannot happen:

* patterns are compiled by the third-party ``regex`` package, whose matching
  functions take a ``timeout``;
* all pattern work on one command line draws on one :class:`RegexBudget` — a
  fraction of a second in total, not per call, so chaining filters does not
  multiply it;
* when the budget is spent, the pattern is too long or too deeply counted, or
  ``regex`` cannot be imported, matching falls back to plain substring
  comparison, which is linear;
* the number of lines, the length of a line that is matched, and the size of
  what a substitution may produce are all capped.

The fallback is not silent nonsense: it still honours ``^`` and ``$`` anchors
and ``a|b`` alternation between literals, which covers what loader scripts
actually write (``grep -c ^processor``, ``grep -E 'wget|curl'``).
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

try:  # pragma: no cover - exercised by whichever branch the install gives
    import regex as _regex
except ImportError:  # pragma: no cover
    _regex = None

logger = logging.getLogger(__name__)

#: Seconds of pattern matching one command line may use in total.
REGEX_BUDGET_SECONDS = 0.25
#: Lines of input a filter looks at, and characters of each it matches on.
MAX_LINES = 5000
MAX_LINE_CHARS = 4096
MAX_PATTERN_CHARS = 512
#: Longest sed or awk program that is parsed at all. The parsers are simple
#: and not linear; real one-liners are a few dozen characters.
MAX_SCRIPT_CHARS = 1024
#: Most text one filter may produce.
MAX_OUTPUT_CHARS = 256 * 1024
#: Largest ``{n}`` a pattern may ask for before it is treated as literal.
MAX_REPEAT_COUNT = 255

_COUNTED_REPEAT = re.compile(r"\{(\d+)(?:,(\d*))?\}")


class RegexBudget:
    """The time all pattern matching on one command line may spend."""

    def __init__(self, seconds: float = REGEX_BUDGET_SECONDS) -> None:
        self.remaining = seconds
        self.exhausted = False

    def spend(self, seconds: float) -> None:
        self.remaining -= seconds
        if self.remaining <= 0.001:
            self.exhausted = True

    def exhaust(self) -> None:
        self.remaining = 0.0
        self.exhausted = True


def bre_to_ere(pattern: str) -> str:
    """Rewrite a POSIX basic regular expression as an extended one.

    Plain ``grep`` and ``sed`` read ``\\|``, ``\\(`` and ``\\+`` as operators
    and the bare characters as literals; everything else here compiles the
    extended form.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "[":
            # A bracket expression is the same in both syntaxes.
            end = pattern.find("]", i + 2)
            if end == -1:
                out.append("\\[")
                i += 1
                continue
            out.append(pattern[i:end + 1])
            i = end + 1
            continue
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            if nxt in "|(){}+?":
                out.append(nxt)
            elif nxt == "<" or nxt == ">":
                out.append("\\b")
            else:
                out.append(ch + nxt)
            i += 2
            continue
        if ch in "|(){}+?":
            out.append("\\" + ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _too_greedy(pattern: str) -> bool:
    """Whether the pattern asks for a repeat count worth refusing."""
    for low, high in _COUNTED_REPEAT.findall(pattern):
        if int(low[:6] or 0) > MAX_REPEAT_COUNT or int(high[:6] or 0) > MAX_REPEAT_COUNT:
            return True
    return False


class SafePattern:
    """A pattern that can be searched for without trusting it."""

    def __init__(
        self,
        pattern: str,
        budget: RegexBudget,
        *,
        extended: bool = False,
        fixed: bool = False,
        ignore_case: bool = False,
        whole_word: bool = False,
    ) -> None:
        self.budget = budget
        self.ignore_case = ignore_case
        self.source = pattern if (extended or fixed) else bre_to_ere(pattern)
        self._rx = None
        self._alternatives = self._literal_alternatives(self.source, fixed)
        usable = (
            not fixed
            and _regex is not None
            and len(pattern) <= MAX_PATTERN_CHARS
            and not _too_greedy(self.source)
        )
        if usable:
            source = rf"\b(?:{self.source})\b" if whole_word else self.source
            flags = _regex.IGNORECASE if ignore_case else 0
            try:
                self._rx = _regex.compile(source, flags)
            except Exception:
                # Not a pattern this engine accepts: grep would have printed
                # an error; matching it as text is the quieter answer.
                self._rx = None

    @staticmethod
    def _literal_alternatives(source: str, fixed: bool) -> list[tuple[str, bool, bool]]:
        """(text, anchored at start, anchored at end) for each ``|`` branch."""
        if fixed:
            return [(source, False, False)]
        alternatives = []
        for branch in source.split("|"):
            start = branch.startswith("^")
            end = branch.endswith("$") and not branch.endswith("\\$")
            text = branch[1 if start else 0: len(branch) - (1 if end else 0)]
            # Unescape what the translation escaped, so the text is literal.
            text = re.sub(r"\\(.)", r"\1", text)
            alternatives.append((text, start, end))
        return alternatives

    def _literal_span(self, line: str) -> Optional[tuple[int, int]]:
        haystack = line.lower() if self.ignore_case else line
        for text, start, end in self._alternatives:
            needle = text.lower() if self.ignore_case else text
            if start and end:
                if haystack == needle:
                    return 0, len(line)
            elif start:
                if haystack.startswith(needle):
                    return 0, len(needle)
            elif end:
                if haystack.endswith(needle):
                    return len(line) - len(needle), len(line)
            else:
                index = haystack.find(needle)
                if index >= 0:
                    return index, index + len(needle)
        return None

    def search(self, line: str) -> Optional[tuple[int, int]]:
        """Span of the first match in ``line``, or None."""
        line = line[:MAX_LINE_CHARS]
        if self._rx is not None and not self.budget.exhausted:
            started = time.perf_counter()
            try:
                match = self._rx.search(line, timeout=max(0.001, self.budget.remaining))
            except TimeoutError:
                self.budget.exhaust()
                logger.warning("Pattern %r ran out of time; matching it as text", self.source[:80])
            else:
                self.budget.spend(time.perf_counter() - started)
                return match.span() if match else None
        return self._literal_span(line)

    def substitute(self, replacement: str, line: str, everywhere: bool) -> tuple[str, bool]:
        """``s/pattern/replacement/`` on one line: (result, whether it matched).

        ``replacement`` is in sed's syntax (``&``, ``\\1``).
        """
        line = line[:MAX_LINE_CHARS]
        if self._rx is not None and not self.budget.exhausted:
            template = _sed_replacement(replacement)
            started = time.perf_counter()
            try:
                result, count = self._rx.subn(
                    template, line, count=0 if everywhere else 1,
                    timeout=max(0.001, self.budget.remaining),
                )
            except TimeoutError:
                self.budget.exhaust()
            except Exception:
                # A replacement naming a group the pattern does not have.
                self.budget.spend(time.perf_counter() - started)
                return line, False
            else:
                self.budget.spend(time.perf_counter() - started)
                return result[:MAX_OUTPUT_CHARS], count > 0
        span = self._literal_span(line)
        if span is None:
            return line, False
        plain = replacement.replace("\\&", "\x00").replace("&", line[span[0]:span[1]]).replace("\x00", "&")
        result = line[:span[0]] + plain + line[span[1]:]
        return result[:MAX_OUTPUT_CHARS], True


def _sed_replacement(replacement: str) -> str:
    """sed's replacement syntax as a ``regex`` template."""
    out: list[str] = []
    i = 0
    while i < len(replacement):
        ch = replacement[i]
        if ch == "\\" and i + 1 < len(replacement):
            nxt = replacement[i + 1]
            if nxt.isdigit():
                out.append(f"\\g<{nxt}>")
            elif nxt == "n":
                out.append("\n")
            elif nxt == "t":
                out.append("\t")
            elif nxt == "&":
                out.append("&")
            else:
                out.append("\\\\" if nxt == "\\" else nxt)
            i += 2
            continue
        if ch == "&":
            out.append("\\g<0>")
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def split_lines(text: str) -> list[str]:
    """The lines a filter works on, within the line cap."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines[:MAX_LINES]


def join_lines(lines: list[str]) -> str:
    """Lines back to text, cut at the output cap."""
    out: list[str] = []
    size = 0
    for line in lines:
        size += len(line) + 1
        if size > MAX_OUTPUT_CHARS:
            break
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


# --------------------------------------------------------------------------
# sed
# --------------------------------------------------------------------------

_SED_ADDRESS = re.compile(r"^\s*(\d+|\$|/(?:[^/\\]|\\.)*/)?(?:\s*,\s*(\d+|\$|/(?:[^/\\]|\\.)*/))?\s*")


def _sed_split(script: str) -> list[str]:
    """Split a sed script on ``;`` and newlines outside an ``s`` command."""
    commands: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(script):
        ch = script[i]
        stripped = "".join(current).lstrip()
        address = _SED_ADDRESS.match(stripped)
        rest = stripped[address.end():] if address else stripped
        if ch == "s" and rest == "" and i + 1 < len(script):
            # Copy the whole s<d>…<d>…<d>flags unit, delimiter and all.
            delimiter = script[i + 1]
            j = i + 2
            seen = 0
            while j < len(script) and seen < 2:
                if script[j] == "\\":
                    j += 2
                    continue
                if script[j] == delimiter:
                    seen += 1
                j += 1
            while j < len(script) and script[j] not in ";\n}":
                j += 1
            current.append(script[i:j])
            i = j
            continue
        if ch in ";\n":
            commands.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    commands.append("".join(current))
    return [c.strip() for c in commands if c.strip()]


class SedProgram:
    """The subset of sed that shows up in loader scripts.

    ``s///`` with the ``g``, ``i`` and ``p`` flags, and ``d``, ``p``, ``q``,
    each optionally behind a line number, ``$``, a ``/regex/`` or a range of
    those. A script using anything else is not run: the input passes through
    unchanged, which is what an unrecognised but harmless edit looks like.
    """

    def __init__(self, scripts: list[str], budget: RegexBudget, extended: bool, quiet: bool) -> None:
        self.budget = budget
        self.extended = extended
        self.quiet = quiet
        self.supported = True
        self.commands: list[tuple] = []
        for script in scripts:
            if len(script) > MAX_SCRIPT_CHARS:
                self.supported = False
                return
            for command in _sed_split(script)[:32]:
                parsed = self._parse(command)
                if parsed is None:
                    self.supported = False
                    return
                self.commands.append(parsed)

    def _pattern(self, source: str, ignore_case: bool = False) -> SafePattern:
        return SafePattern(source, self.budget, extended=self.extended, ignore_case=ignore_case)

    def _address(self, token: Optional[str]):
        if token is None:
            return None
        if token == "$":
            return "$"
        if token.isdigit():
            return int(token[:9])
        return self._pattern(token[1:-1].replace("\\/", "/"))

    def _parse(self, command: str) -> Optional[tuple]:
        match = _SED_ADDRESS.match(command)
        first = self._address(match.group(1))
        second = self._address(match.group(2))
        body = command[match.end():].strip()
        if not body:
            return None
        verb = body[0]
        if verb == "s" and len(body) > 3:
            delimiter = body[1]
            parts: list[str] = []
            current: list[str] = []
            i = 2
            while i < len(body) and len(parts) < 2:
                ch = body[i]
                if ch == "\\" and i + 1 < len(body):
                    # An escaped delimiter is the delimiter itself.
                    current.append(body[i + 1] if body[i + 1] == delimiter else body[i:i + 2])
                    i += 2
                    continue
                if ch == delimiter:
                    parts.append("".join(current))
                    current = []
                else:
                    current.append(ch)
                i += 1
            if len(parts) < 2:
                return None
            flags = body[i:].strip()
            pattern = self._pattern(parts[0], ignore_case="i" in flags.lower().replace("g", "").replace("p", ""))
            return ("s", first, second, pattern, parts[1], "g" in flags, "p" in flags)
        if verb in "dpq" and body[1:].strip() == "":
            return (verb, first, second)
        return None

    @staticmethod
    def _selected(first, second, number: int, last: bool, line: str, state: dict, key: int) -> bool:
        def hit(address) -> bool:
            if address == "$":
                return last
            if isinstance(address, int):
                return number == address
            return address.search(line) is not None

        if first is None:
            return True
        if second is None:
            return hit(first)
        # A range: on from the first address until the second matches.
        if state.get(key):
            if (isinstance(second, int) and number >= second) or (not isinstance(second, int) and hit(second)):
                state[key] = False
            return True
        if hit(first):
            state[key] = not (isinstance(second, int) and second <= number)
            return True
        return False

    def run(self, lines: list[str]) -> list[str]:
        if not self.supported:
            return lines
        out: list[str] = []
        size = 0
        ranges: dict[int, bool] = {}
        for index, line in enumerate(lines):
            number = index + 1
            last = number == len(lines)
            deleted = False
            quit_after = False
            extra: list[str] = []
            for key, command in enumerate(self.commands):
                verb, first, second = command[0], command[1], command[2]
                if not self._selected(first, second, number, last, line, ranges, key):
                    continue
                if verb == "s":
                    line, matched = command[3].substitute(command[4], line, command[5])
                    if matched and command[6]:
                        extra.append(line)
                elif verb == "d":
                    deleted = True
                    break
                elif verb == "p":
                    extra.append(line)
                elif verb == "q":
                    quit_after = True
            produced = extra + ([] if (deleted or self.quiet) else [line])
            for item in produced:
                size += len(item) + 1
                if size > MAX_OUTPUT_CHARS:
                    return out
                out.append(item)
            if quit_after:
                break
        return out


# --------------------------------------------------------------------------
# awk
# --------------------------------------------------------------------------

_AWK_RULE = re.compile(r"\s*([^{]*?)\s*\{([^}]*)\}")
_AWK_TOKEN = re.compile(
    r'\s*(?:"((?:[^"\\]|\\.)*)"|\$\(\s*NF\s*-\s*(\d+)\s*\)|\$NF|\$(\d+)|(NR|NF)|(-?\d+)|(,))'
)


class AwkProgram:
    """``awk '{print $N}'`` and its near relatives.

    Rules of the form ``[pattern] { print … }`` where the pattern is empty,
    ``/regex/``, ``NR==n`` (or another comparison), ``BEGIN`` or ``END``, and
    print takes fields, ``NF``/``NR``, string literals and numbers, joined by
    commas or written side by side. That is how fields are picked out of
    ``ps``, ``df`` and ``/proc`` in practice. A program beyond it prints
    nothing rather than something invented.
    """

    def __init__(self, program: str, separator: Optional[str], budget: RegexBudget) -> None:
        self.separator = separator
        self.budget = budget
        self.rules: list[tuple] = []
        self.supported = True
        consumed = 0
        if len(program) > MAX_SCRIPT_CHARS:
            self.supported = False
            return
        for match in _AWK_RULE.finditer(program):
            if program[consumed:match.start()].strip():
                self.supported = False
                return
            consumed = match.end()
            condition = self._condition(match.group(1).strip())
            action = self._action(match.group(2).strip())
            if condition is None or action is None:
                self.supported = False
                return
            self.rules.append((condition, action))
        if program[consumed:].strip() or not self.rules:
            self.supported = False

    def _condition(self, text: str):
        if text == "":
            return ("all",)
        if text in ("BEGIN", "END"):
            return (text,)
        if text.startswith("/") and text.endswith("/") and len(text) >= 2:
            return ("match", SafePattern(text[1:-1], self.budget, extended=True))
        comparison = re.fullmatch(r"NR\s*(==|!=|<=|>=|<|>)\s*(\d+)", text)
        if comparison:
            return ("nr", comparison.group(1), int(comparison.group(2)[:9]))
        return None

    @staticmethod
    def _action(text: str):
        if text in ("print", "print $0"):
            return [[("line",)]]
        if not text.startswith("print") or (len(text) > 5 and text[5] not in " \t$\"("):
            return None
        body = text[5:].rstrip(";").strip()
        groups: list[list[tuple]] = [[]]
        position = 0
        while position < len(body):
            match = _AWK_TOKEN.match(body, position)
            if not match:
                return None
            position = match.end()
            literal, from_end, field, variable, number, comma = match.groups()
            if comma:
                groups.append([])
            elif literal is not None:
                groups[-1].append(("text", literal.replace('\\"', '"').replace("\\t", "\t").replace("\\n", "\n")))
            elif from_end is not None:
                groups[-1].append(("field_from_end", int(from_end[:4])))
            elif field is not None:
                groups[-1].append(("field", int(field[:6])))
            elif variable is not None:
                groups[-1].append((variable,))
            elif number is not None:
                groups[-1].append(("text", number))
            else:
                groups[-1].append(("field_from_end", 0))
        return groups

    def _fields(self, line: str) -> list[str]:
        if self.separator is None or self.separator == " ":
            return line.split()
        if self.separator == "\\t":
            return line.split("\t")
        return line.split(self.separator)

    def _render(self, action, line: str, fields: list[str], number: int) -> str:
        parts = []
        for group in action:
            piece = ""
            for item in group:
                kind = item[0]
                if kind == "line":
                    piece += line
                elif kind == "text":
                    piece += item[1]
                elif kind == "field":
                    index = item[1]
                    piece += line if index == 0 else (fields[index - 1] if index <= len(fields) else "")
                elif kind == "field_from_end":
                    index = len(fields) - item[1]
                    piece += fields[index - 1] if 1 <= index <= len(fields) else ""
                elif kind == "NR":
                    piece += str(number)
                elif kind == "NF":
                    piece += str(len(fields))
            parts.append(piece)
        return " ".join(parts)

    def run(self, lines: list[str]) -> Optional[list[str]]:
        """Output lines, or None when the program is not one this runs."""
        if not self.supported:
            return None
        out: list[str] = []
        size = 0

        def emit(text: str) -> bool:
            nonlocal size
            size += len(text) + 1
            if size > MAX_OUTPUT_CHARS:
                return False
            out.append(text)
            return True

        for condition, action in self.rules:
            if condition[0] == "BEGIN":
                emit(self._render(action, "", [], 0))
        for index, line in enumerate(lines):
            number = index + 1
            fields = self._fields(line)
            for condition, action in self.rules:
                kind = condition[0]
                if kind in ("BEGIN", "END"):
                    continue
                if kind == "match" and condition[1].search(line) is None:
                    continue
                if kind == "nr" and not {
                    "==": number == condition[2], "!=": number != condition[2],
                    "<": number < condition[2], ">": number > condition[2],
                    "<=": number <= condition[2], ">=": number >= condition[2],
                }[condition[1]]:
                    continue
                if not emit(self._render(action, line, fields, number)):
                    return out
        for condition, action in self.rules:
            if condition[0] == "END":
                last = lines[-1] if lines else ""
                emit(self._render(action, last, self._fields(last), len(lines)))
        return out


# --------------------------------------------------------------------------
# tr and cut
# --------------------------------------------------------------------------

_TR_CLASSES = {
    "[:lower:]": "abcdefghijklmnopqrstuvwxyz",
    "[:upper:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "[:digit:]": "0123456789",
    "[:alpha:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "[:alnum:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "[:space:]": " \t\n\r\x0b\x0c",
    "[:blank:]": " \t",
    "[:punct:]": "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}
_TR_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "0": "\x00", "a": "\a", "b": "\b", "f": "\f", "v": "\x0b"}


def tr_set(spec: str) -> str:
    """Expand a ``tr`` set: escapes, ``a-z`` ranges and ``[:class:]`` names."""
    out: list[str] = []
    i = 0
    while i < len(spec) and len(out) < 1024:
        matched_class = next((name for name in _TR_CLASSES if spec.startswith(name, i)), None)
        if matched_class:
            out.extend(_TR_CLASSES[matched_class])
            i += len(matched_class)
            continue
        ch = spec[i]
        if ch == "\\" and i + 1 < len(spec):
            octal = re.match(r"[0-7]{1,3}", spec[i + 1:i + 4])
            if octal and spec[i + 1] != "0":
                ch = chr(int(octal.group(0), 8) & 0xFF)
                i += len(octal.group(0))
            else:
                ch = _TR_ESCAPES.get(spec[i + 1], spec[i + 1])
                i += 1
        if i + 2 < len(spec) and spec[i + 1] == "-" and spec[i + 2] != "\\":
            low, high = ord(ch), ord(spec[i + 2])
            if low <= high and high - low < 256:
                out.extend(chr(c) for c in range(low, high + 1))
                i += 3
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def tr(args: list[str], text: str) -> str:
    """``tr`` with ``-d``, ``-s`` and plain translation.

    A second set shorter than the first is padded with its last character,
    as POSIX says; building the table from unequal sets is what used to
    raise and close the shell on ``tr '\\n' ' '``… any time the two happened
    to differ in length.
    """
    flags = "".join(a[1:] for a in args if a.startswith("-") and len(a) > 1 and not a[1:].isdigit())
    sets = [a for a in args if not (a.startswith("-") and len(a) > 1)]
    if not sets:
        return text
    first = tr_set(sets[0])
    if "d" in flags:
        text = text.translate({ord(c): None for c in first})
        squeeze = tr_set(sets[1]) if "s" in flags and len(sets) > 1 else ""
    elif len(sets) > 1:
        second = tr_set(sets[1])
        if not second:
            return text
        if len(second) < len(first):
            second += second[-1] * (len(first) - len(second))
        text = text.translate({ord(a): b for a, b in zip(first, second)})
        squeeze = second if "s" in flags else ""
    else:
        squeeze = first if "s" in flags else ""
    if squeeze:
        members = set(squeeze)
        out: list[str] = []
        for ch in text:
            if out and ch == out[-1] and ch in members:
                continue
            out.append(ch)
        text = "".join(out)
    return text


def _ranges(spec: str) -> list[tuple[int, int]]:
    """A ``cut`` list such as ``1,3-5,7-`` as inclusive 1-based ranges."""
    ranges = []
    for part in spec.split(",")[:64]:
        low, dash, high = part.partition("-")
        try:
            start = int(low[:6]) if low else 1
            end = (int(high[:6]) if high else 100_000) if dash else start
        except ValueError:
            continue
        if start >= 1 and end >= start:
            ranges.append((start, end))
    return ranges


def cut(args: list[str], lines: list[str]) -> Optional[list[str]]:
    """``cut -d X -f LIST`` and ``cut -c LIST``; None when neither is given."""
    delimiter = "\t"
    fields = characters = None
    only_delimited = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-d", "-f", "-c", "-b") and i + 1 < len(args):
            value = args[i + 1]
            i += 1
        elif arg[:2] in ("-d", "-f", "-c", "-b") and len(arg) > 2:
            value = arg[2:]
        elif arg == "-s":
            only_delimited = True
            i += 1
            continue
        else:
            i += 1
            continue
        if arg[:2] == "-d":
            delimiter = value[:1] or "\t"
        elif arg[:2] == "-f":
            fields = _ranges(value)
        else:
            characters = _ranges(value)
        i += 1
    if fields is None and characters is None:
        return None
    out = []
    for line in lines:
        if characters is not None:
            out.append("".join(line[start - 1:end] for start, end in characters))
            continue
        if delimiter not in line:
            if not only_delimited:
                out.append(line)
            continue
        columns = line.split(delimiter)
        chosen = []
        for start, end in fields:
            chosen.extend(columns[start - 1:end])
        out.append(delimiter.join(chosen))
    return out
