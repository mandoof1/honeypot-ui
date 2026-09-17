"""Entropy and printable strings — the two views that work on any file."""

from __future__ import annotations

import math
import re

import numpy as np

#: Strings shorter than this are mostly coincidental runs of printable bytes.
MIN_STRING = 6
MAX_STRINGS = 20_000
MAX_STRING_LENGTH = 1024

_ASCII = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING)


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: ~4.5 for code, ~7.9+ for encrypted."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0] / len(data)
    return float(-(probabilities * np.log2(probabilities)).sum())


def strings(data: bytes) -> list[str]:
    """ASCII and UTF-16LE strings, in file order of discovery, bounded."""
    found: list[str] = []
    seen: set[str] = set()
    for pattern, encoding in ((_ASCII, "ascii"), (_UTF16, "utf-16-le")):
        for match in pattern.finditer(data):
            text = match.group(0)[: MAX_STRING_LENGTH * (2 if encoding != "ascii" else 1)]
            value = text.decode(encoding, errors="ignore").strip()
            if len(value) >= MIN_STRING and value not in seen:
                seen.add(value)
                found.append(value)
                if len(found) >= MAX_STRINGS:
                    return found
    return found


def is_high_entropy(value: float) -> bool:
    return value >= 7.2


def rounded(value: float) -> float:
    return round(value, 3) if math.isfinite(value) else 0.0
