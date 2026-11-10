"""The part of a transcript a model is shown, for both model stages.

The language model used to read the first 6,000 characters of a session and
the decision model the first 2,000 and the last 1,000. Anything an attacker
did in the middle or late in a long session was never read, and padding was
enough to push it out of view: a page of harmless commands, then the dropper.

One builder now serves both models. Within a fixed budget it keeps

* every line the rule layer flagged, wherever it is;
* the start of the session;
* the end of the session;

and marks every gap, with how much was left out, so the model knows it is
reading an excerpt and the caller knows whether anything was omitted.

The budget is in UTF-8 bytes. A tokenizer never produces more tokens than
its input has bytes, so a byte budget is a token budget that cannot be
exceeded whatever the text is.

The transcript is attacker-controlled and is handed to the model strictly as
data. Text that imitates the prompt's own structure — the closing
``</transcript>`` tag, a chat template's role markers — is rewritten so it
cannot end the data block or open a new turn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

#: Markers left where lines or characters were removed. Square brackets and
#: dots, which no shell command or request line is likely to start with.
_GAP = "[... {lines} lines, {chars} characters omitted ...]"
_CUT = " [... {chars} characters omitted ...] "
#: Bytes set aside for each gap marker when planning what fits.
_GAP_COST = 64

#: Share of the budget each part may take when everything cannot fit. What
#: one part leaves unused goes to the next.
_FLAGGED_SHARE = 0.5
_HEAD_SHARE = 0.3

#: Smallest and largest budget one line may take. A single huge line keeps
#: its start and end.
_MIN_LINE_BYTES = 120

#: The tags this project's prompts wrap the transcript in, and the role and
#: control markers of the chat templates the models are served with.
_TAG_LOOKALIKE = re.compile(
    # The transcript tag itself, however it is spaced; and the short role
    # tags only when they are closed as tags, so "mysql < user.sql" is left
    # as the redirection it is.
    r"<(?=[ \t]{0,8}/?[ \t]{0,8}transcript\b"
    r"|/?(?:think|s|start_of_turn|end_of_turn|system|user|assistant)[ \t]{0,8}>)",
    re.IGNORECASE,
)
_INSTRUCTION_LOOKALIKE = re.compile(r"\[(?=/?INST\])", re.IGNORECASE)


def neutralise(text: str) -> str:
    """Rewrite text that imitates the prompt's delimiters or a chat turn.

    The characters stay readable (``&lt;/transcript>``), so the analysis of
    what the attacker typed is not harmed; they just stop being markup.
    """
    if "<" in text:
        text = _TAG_LOOKALIKE.sub("&lt;", text)
        text = text.replace("<|", "&lt;|").replace("<<SYS>>", "&lt;&lt;SYS>>")
    if "|>" in text:
        text = text.replace("|>", "|&gt;")
    if "[" in text:
        text = _INSTRUCTION_LOOKALIKE.sub("[ ", text)
    return text


@dataclass
class Window:
    #: What the model reads.
    text: str
    total_lines: int
    kept_lines: int
    omitted_lines: int
    omitted_chars: int
    #: Lines the rule layer flagged, and how many of them made it in.
    flagged_total: int
    flagged_kept: int

    @property
    def truncated(self) -> bool:
        """Whether the model saw less than the whole transcript."""
        return self.omitted_lines > 0 or self.omitted_chars > 0

    def describe(self) -> dict:
        return {
            "lines": self.total_lines,
            "kept_lines": self.kept_lines,
            "omitted_lines": self.omitted_lines,
            "omitted_chars": self.omitted_chars,
            "flagged_lines": self.flagged_total,
            "flagged_kept": self.flagged_kept,
            "truncated": self.truncated,
        }


def _size(text: str) -> int:
    return len(text.encode("utf-8", "replace"))


def _fit_line(text: str, limit: int) -> tuple[str, int]:
    """One line within ``limit`` bytes: (text, characters removed)."""
    if _size(text) <= limit:
        return text, 0
    # Characters, not bytes: slicing bytes could split a code point. A
    # character is at most four bytes, so a quarter of the limit always fits.
    keep = max(8, (limit - _GAP_COST) // 4)
    if len(text) <= keep:
        return text, 0
    head = keep * 2 // 3
    tail = keep - head
    removed = len(text) - head - tail
    return text[:head] + _CUT.format(chars=removed) + text[-tail:], removed


def build_window(
    lines: Sequence[str],
    max_bytes: int,
    flagged: Optional[Iterable[int]] = None,
) -> Window:
    """Choose what a model reads from a transcript, within ``max_bytes``."""
    max_bytes = max(int(max_bytes), 256)
    source = [neutralise(str(line)) for line in lines]
    total = len(source)
    flagged_set = {i for i in (flagged or []) if isinstance(i, int) and 0 <= i < total}

    # The whole transcript, when it fits, is the best window there is.
    whole = "\n".join(source)
    if _size(whole) <= max_bytes:
        return Window(whole, total, total, 0, 0, len(flagged_set), len(flagged_set))

    line_limit = max(_MIN_LINE_BYTES, max_bytes // 6)
    fitted: List[str] = []
    cut_chars = 0
    for text in source:
        short, removed = _fit_line(text, line_limit)
        fitted.append(short)
        cut_chars += removed
    costs = [_size(text) + 1 for text in fitted]

    chosen: set[int] = set()
    remaining = max_bytes

    def take(index: int, allowance: int) -> int:
        """Add a line if it fits the allowance; returns what is left of it."""
        nonlocal remaining
        if index in chosen:
            return allowance
        # A line that does not touch one already chosen opens a new gap.
        cost = costs[index] + (0 if (index - 1 in chosen or index + 1 in chosen or index == 0) else _GAP_COST)
        if cost > allowance or cost > remaining:
            return -1
        chosen.add(index)
        remaining -= cost
        return allowance - cost

    # Flagged lines first: they are why the session is being read at all.
    allowance = int(max_bytes * _FLAGGED_SHARE)
    for index in sorted(flagged_set):
        left = take(index, allowance)
        # One that does not fit is skipped, not the end of the search: a
        # later, shorter flagged line may still fit.
        if left >= 0:
            allowance = left
    unused = max(allowance, 0)

    allowance = int(max_bytes * _HEAD_SHARE) + unused
    for index in range(total):
        left = take(index, allowance)
        if left < 0:
            break
        allowance = left
    unused = max(allowance, 0)

    # The tail takes whatever is left, less one marker for the gap before it.
    allowance = remaining - _GAP_COST
    for index in range(total - 1, -1, -1):
        left = take(index, allowance)
        if left < 0:
            break
        allowance = left

    parts: List[str] = []
    previous = -1
    omitted_chars = cut_chars
    for index in sorted(chosen):
        if index > previous + 1:
            gap = range(previous + 1, index)
            gap_chars = sum(len(source[i]) for i in gap)
            parts.append(_GAP.format(lines=len(gap), chars=gap_chars))
            omitted_chars += gap_chars
        parts.append(fitted[index])
        previous = index
    if previous < total - 1:
        gap = range(previous + 1, total)
        gap_chars = sum(len(source[i]) for i in gap)
        parts.append(_GAP.format(lines=len(gap), chars=gap_chars))
        omitted_chars += gap_chars

    text = "\n".join(parts)
    # The plan above reserves space for every marker; this is the guarantee
    # rather than the plan, in case a marker's numbers ran longer than that.
    if _size(text) > max_bytes:
        text = text.encode("utf-8", "replace")[: max_bytes - 32].decode("utf-8", "ignore") + "\n[... cut ...]"

    return Window(
        text=text,
        total_lines=total,
        kept_lines=len(chosen),
        omitted_lines=total - len(chosen),
        omitted_chars=omitted_chars,
        flagged_total=len(flagged_set),
        flagged_kept=len(flagged_set & chosen),
    )


def window_for_session(commands: Sequence[str], protocol: str, max_bytes: int) -> Window:
    """The window for a stored session: its flagged lines come from the rules.

    The rule layer is run here rather than its result passed in, so both
    model stages build the same window from nothing but the commands.
    """
    from app.ai.nlp_engine import nlp_engine

    flagged = nlp_engine.flagged_lines(list(commands), protocol) if commands else []
    return build_window(commands, max_bytes, flagged)
