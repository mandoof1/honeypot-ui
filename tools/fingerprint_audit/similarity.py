"""Scores in [0, 1] for how alike two observations are.

A score never decides a match on its own. Two responses match when they are
equal after normalisation; the score says how far apart they are when they
are not, so that "one header out of order" and "a different server
altogether" do not look the same in the results.
"""

from __future__ import annotations

import difflib
import math
from typing import Hashable, Mapping, Optional, Sequence


def byte_cosine(a: bytes, b: bytes) -> float:
    """Cosine similarity of two responses as 256-bin byte-count vectors.

    Each response becomes a vector holding how many times each byte value
    occurs in it, and the score is the cosine of the angle between the two.
    It ignores the order of the bytes, which is why it is only ever a score:
    an anagram of a response scores 1.0 and is still a mismatch.

    Two empty responses are identical (1.0); an empty one against a non-empty
    one has nothing in common (0.0).
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    counts_a = [0] * 256
    counts_b = [0] * 256
    for byte in a:
        counts_a[byte] += 1
    for byte in b:
        counts_b[byte] += 1
    dot = sum(x * y for x, y in zip(counts_a, counts_b))
    norm_a = math.sqrt(sum(x * x for x in counts_a))
    norm_b = math.sqrt(sum(y * y for y in counts_b))
    # Rounding can push an exact match a hair over 1.
    return min(1.0, dot / (norm_a * norm_b))


def sequence_similarity(a: Sequence[Hashable], b: Sequence[Hashable]) -> float:
    """How alike two ordered lists are, order included.

    Twice the number of elements in the matching blocks over the total
    number of elements (difflib's ratio), so a list with one entry moved or
    missing scores high and a disjoint list scores 0.
    """
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, list(a), list(b), autojunk=False).ratio()


def set_similarity(a: Sequence[Hashable], b: Sequence[Hashable]) -> float:
    """Jaccard index: shared members over all members."""
    set_a, set_b = set(a), set(b)
    if not set_a and not set_b:
        return 1.0
    return len(set_a & set_b) / len(set_a | set_b)


def mapping_similarity(a: Mapping, b: Mapping) -> float:
    """Share of keys, over both mappings, that hold the same value in each."""
    keys = set(a) | set(b)
    if not keys:
        return 1.0
    same = sum(1 for key in keys if key in a and key in b and a[key] == b[key])
    return same / len(keys)


#: Two timings match when they are within this many seconds of each other, or
#: within this fraction of the larger one. Deliberately coarse: both targets
#: are on loopback, where scheduling noise is all that separates two servers
#: answering at once, and a timing row is meant to catch delays a daemon adds
#: on purpose (a failed-login pause, a login grace period), not microseconds.
TIMING_ABSOLUTE_TOLERANCE = 0.25
TIMING_RELATIVE_TOLERANCE = 0.25


def timings_match(a: Optional[float], b: Optional[float]) -> bool:
    if a is None or b is None:
        return a is None and b is None
    difference = abs(a - b)
    return (
        difference <= TIMING_ABSOLUTE_TOLERANCE
        or difference <= TIMING_RELATIVE_TOLERANCE * max(a, b)
    )


def timing_similarity(a: Optional[float], b: Optional[float]) -> float:
    """Smaller over larger; 1.0 when both are absent or both are zero."""
    if a is None or b is None:
        return 1.0 if a is None and b is None else 0.0
    largest = max(a, b)
    if largest <= 0:
        return 1.0
    return max(0.0, min(a, b)) / largest
