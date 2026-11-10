"""What a probe records about one target, and how two records are compared.

A probe run against one target yields a list of :class:`Check` objects: a
normalised value plus the raw evidence behind it. The same probe code runs
against the decoy and the reference, and :func:`compare` pairs the two lists
by check id. Keeping collection and comparison apart is what guarantees both
targets are measured the same way.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

from . import similarity

#: How a check's two values are compared.
#:
#: exact    equal or not; structured values (strings, flags, small mappings)
#: ordered  a list whose order is part of the answer (algorithm name-lists,
#:          header order, negotiation sequence)
#: set      a list whose order the measuring client does not preserve
#: bytes    a raw response, scored by byte-level cosine similarity
#: timing   seconds, compared within a coarse tolerance; informational
KINDS = ("exact", "ordered", "set", "bytes", "timing")

#: Longest raw capture stored in a result file, per value. The length and
#: SHA-256 of the whole capture are always stored.
MAX_STORED_BYTES = 4096


def escape_bytes(data: bytes) -> str:
    """Bytes as text a person can read and JSON can hold.

    Printable ASCII stays as it is; everything else, and the backslash,
    becomes a Python-style escape (``\\r``, ``\\n``, ``\\xff``).
    """
    out = []
    for byte in data:
        if byte == 0x5C:
            out.append("\\\\")
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        elif byte == 0x0D:
            out.append("\\r")
        elif byte == 0x0A:
            out.append("\\n")
        elif byte == 0x09:
            out.append("\\t")
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def describe_bytes(data: bytes, limit: int = MAX_STORED_BYTES) -> dict:
    """The stored form of a raw capture: size, hash and a readable prefix."""
    return {
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "text": escape_bytes(data[:limit]),
        "truncated": len(data) > limit,
    }


@dataclass
class Check:
    """One compared fact about one target."""

    id: str
    description: str
    kind: str
    #: The normalised value that is compared. ``bytes`` for kind "bytes",
    #: a list for "ordered" and "set", seconds or None for "timing", any
    #: JSON value for "exact".
    value: Any = None
    #: Supporting detail that is recorded but not compared: the raw capture
    #: before normalisation, timings, what was sent.
    evidence: dict = field(default_factory=dict)
    #: Set when the probe could not be carried out (connection refused, an
    #: exception). "The server said nothing" is a value, not an error.
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown check kind: {self.kind}")

    def stored(self) -> dict:
        value = describe_bytes(self.value) if isinstance(self.value, bytes) else self.value
        return {"value": value, "evidence": self.evidence, "error": self.error}


def _score(kind: str, a: Any, b: Any) -> tuple[bool, float]:
    """(match, similarity) for two values of one kind."""
    if kind == "timing":
        return similarity.timings_match(a, b), similarity.timing_similarity(a, b)

    match = a == b and type(a) is type(b)
    if match:
        return True, 1.0
    if kind == "bytes" and isinstance(a, bytes) and isinstance(b, bytes):
        return False, similarity.byte_cosine(a, b)
    if kind == "ordered" and isinstance(a, list) and isinstance(b, list):
        return False, similarity.sequence_similarity(_hashable(a), _hashable(b))
    if kind == "set" and isinstance(a, list) and isinstance(b, list):
        # Order was never observed, so equal membership is a match.
        score = similarity.set_similarity(_hashable(a), _hashable(b))
        return score == 1.0, score
    if isinstance(a, str) and isinstance(b, str):
        return False, similarity.byte_cosine(a.encode("utf-8"), b.encode("utf-8"))
    if isinstance(a, dict) and isinstance(b, dict):
        return False, similarity.mapping_similarity(a, b)
    return False, 0.0


def _hashable(items: list) -> list:
    """List members as something difflib and sets accept."""
    return [repr(item) if isinstance(item, (dict, list)) else item for item in items]


def compare_pair(decoy: Optional[Check], reference: Optional[Check]) -> dict:
    """The result row for one check id."""
    present = decoy or reference
    assert present is not None
    row = {
        "id": present.id,
        "description": present.description,
        "comparison": present.kind,
        # Timing rows are context for a reader, not a verdict: one sample
        # each, on loopback.
        "informational": present.kind == "timing",
        "match": False,
        "similarity": 0.0,
        "decoy": decoy.stored() if decoy else {"value": None, "evidence": {}, "error": "check not produced"},
        "reference": reference.stored() if reference else {"value": None, "evidence": {}, "error": "check not produced"},
    }
    if decoy is None or reference is None or decoy.error or reference.error:
        return row
    row["match"], score = _score(present.kind, decoy.value, reference.value)
    row["similarity"] = round(score, 4)
    return row


def compare(decoy: list[Check], reference: list[Check]) -> list[dict]:
    """Pair two targets' checks by id, in the order the decoy produced them."""
    by_id = {check.id: check for check in reference}
    rows = []
    seen = set()
    for check in decoy:
        seen.add(check.id)
        rows.append(compare_pair(check, by_id.get(check.id)))
    for check in reference:
        if check.id not in seen:
            rows.append(compare_pair(None, check))
    return rows


def summarise(rows: list[dict]) -> dict:
    """Counts for the head of a result file."""
    verdicts = [row for row in rows if not row["informational"]]
    errors = [
        row for row in rows if row["decoy"]["error"] or row["reference"]["error"]
    ]
    return {
        "checks": len(verdicts),
        "matches": sum(1 for row in verdicts if row["match"]),
        "mismatches": sum(1 for row in verdicts if not row["match"]),
        "informational_timing_rows": len(rows) - len(verdicts),
        "timing_rows_outside_tolerance": sum(
            1 for row in rows if row["informational"] and not row["match"]
        ),
        "rows_with_probe_errors": len(errors),
    }
