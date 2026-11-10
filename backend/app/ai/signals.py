"""Derived flags stored on a session (``honeypot_sessions.signals``).

Small facts worked out from what the engine sent, kept together so the
console and the exports read one place: whether an AI agent drove the
session, whether a planted honeytoken was used, and — added by the pipeline —
how far the anomaly score can be trusted and how the verdict was reached.

Also the client fingerprints, which are stored as received with their sizes
capped.
"""

from __future__ import annotations

import hashlib
import statistics
from typing import Dict, List, Optional, Tuple

#: Longest indicator value stored whole (the column is VARCHAR(500)).
MAX_INDICATOR_CHARS = 500


def fit_indicator_value(value: str) -> Tuple[str, bool]:
    """An indicator value that fits its column, and whether it was cut.

    A value longer than the column made the insert fail on PostgreSQL, the
    session with it, and the engine resend that session for ever. A long
    value keeps its start and gains the SHA-256 of the whole, so two long
    URLs that share a prefix stay two indicators.
    """
    value = str(value)
    if len(value) <= MAX_INDICATOR_CHARS:
        return value, False
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
    marker = f"...sha256:{digest}"
    return value[: MAX_INDICATOR_CHARS - len(marker)] + marker, True

# -- fingerprints -----------------------------------------------------------

_MAX_FINGERPRINT_KEYS = 32
_MAX_FINGERPRINT_KEY_CHARS = 64
_MAX_FINGERPRINT_VALUE_CHARS = 512
_MAX_FINGERPRINT_LIST_ITEMS = 64

#: The keys the engine contract names. Others are kept too (up to the cap):
#: an engine newer than this backend should not lose what it measured.
FINGERPRINT_KEYS = (
    "ssh_client_version", "hassh", "hassh_algorithms", "hassh_server",
    "ja3", "ja3_string", "ja4", "telnet_options", "http_header_order",
)


def _cap_value(value, depth: int = 0):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value[:_MAX_FINGERPRINT_VALUE_CHARS]
    if isinstance(value, list) and depth < 2:
        return [_cap_value(item, depth + 1) for item in value[:_MAX_FINGERPRINT_LIST_ITEMS]]
    if isinstance(value, dict) and depth < 2:
        return {
            str(key)[:_MAX_FINGERPRINT_KEY_CHARS]: _cap_value(item, depth + 1)
            for key, item in list(value.items())[:_MAX_FINGERPRINT_KEYS]
        }
    return str(value)[:_MAX_FINGERPRINT_VALUE_CHARS]


def cap_fingerprints(raw) -> Optional[Dict]:
    """The engine's fingerprint object, bounded. None when absent or empty.

    These values come from a client's handshake, so their length is the
    client's choice; the structure is kept and every string, list and object
    is cut to a fixed size.
    """
    if not isinstance(raw, dict) or not raw:
        return None
    capped = _cap_value(raw)
    return {key: value for key, value in capped.items() if value not in (None, "", [], {})} or None


# -- AI-agent detection -----------------------------------------------------

#: Inter-command gaps needed before timing is looked at at all.
MIN_GAPS = 4
#: The band a model-driven agent's think-then-act loop is assumed to fall in,
#: in seconds between commands. A script answers in well under a second; a
#: person's gaps are spread widely.
AGENT_GAP_MIN_SECONDS = 1.0
AGENT_GAP_MAX_SECONDS = 60.0
#: Coefficient of variation of the gaps below which they count as regular.
AGENT_REGULARITY_CV = 0.5
#: The most timing alone may contribute. Below one half on purpose.
TIMING_MAX_SCORE = 0.45


def _gaps(session_data: Dict) -> List[float]:
    stamps = []
    for entry in session_data.get("transcript") or []:
        if not isinstance(entry, dict):
            continue
        stamp = entry.get("timestamp")
        if isinstance(stamp, (int, float)) and not isinstance(stamp, bool):
            stamps.append(float(stamp))
    return [later - earlier for earlier, later in zip(stamps, stamps[1:]) if later >= earlier]


def ai_agent_signal(session_data: Dict) -> Optional[Dict]:
    """Whether an AI agent drove the session, and on what grounds.

    Two kinds of evidence, kept apart:

    * a canary trigger (the engine's ``ai_canary_triggered`` event: the
      client acted on text only a model reading the output would act on).
      This alone is decisive.
    * the timing of its commands. This alone is only suggestive. The band
      and the regularity cut-off above are assumptions about how an agent's
      loop behaves; they have not been validated against labelled sessions,
      and the reasons say so wherever they are shown.

    Returns None when there is neither a canary nor enough timing to look at.
    """
    session_data = session_data or {}
    canaries = [
        event for event in (session_data.get("events") or [])
        if isinstance(event, dict) and event.get("event_type") == "ai_canary_triggered"
    ]
    gaps = _gaps(session_data)
    if not canaries and len(gaps) < MIN_GAPS:
        return None

    reasons: List[str] = []
    timing_score = 0.0
    timing: Optional[Dict] = None

    if len(gaps) >= MIN_GAPS:
        median = statistics.median(gaps)
        mean = statistics.fmean(gaps)
        variation = (statistics.pstdev(gaps) / mean) if mean > 0 else 0.0
        timing = {"gaps": len(gaps), "median_gap_s": round(median, 3), "cv": round(variation, 3)}
        if AGENT_GAP_MIN_SECONDS <= median <= AGENT_GAP_MAX_SECONDS:
            timing_score += 0.25
            reasons.append(
                f"timing (suggestive only): median gap of {median:.1f} s between commands, "
                "in the range assumed for a model's think-then-act loop"
            )
            if variation <= AGENT_REGULARITY_CV:
                timing_score += 0.2
                reasons.append(
                    f"timing (suggestive only): gaps are regular (coefficient of variation {variation:.2f} "
                    f"over {len(gaps)} gaps)"
                )
        timing_score = min(timing_score, TIMING_MAX_SCORE)

    for event in canaries[:10]:
        name = str(event.get("canary") or "unnamed")[:80]
        channel = str(event.get("channel") or "unknown")[:40]
        reasons.insert(0, f"canary triggered: {name} via {channel}")

    signal = {
        "score": 1.0 if canaries else round(timing_score, 2),
        "canary": bool(canaries),
        # What the score rests on, so a reader never takes a timing guess
        # for a detection.
        "basis": "canary" if canaries else ("timing" if timing_score > 0 else "none"),
        "reasons": reasons,
    }
    if canaries:
        signal["canaries"] = sorted({str(e.get("canary") or "unnamed")[:80] for e in canaries})[:10]
    if timing is not None:
        signal["timing"] = timing
    return signal


# -- honeytokens ------------------------------------------------------------

def honeytoken_signal(session_data: Dict) -> Optional[Dict]:
    """The honeytokens a session used, from ``honeytoken_used`` events."""
    token_ids: List[str] = []
    kinds: List[str] = []
    paths: List[str] = []
    for event in (session_data or {}).get("events") or []:
        if not isinstance(event, dict) or event.get("event_type") != "honeytoken_used":
            continue
        token_id = str(event.get("token_id") or "")[:128]
        if token_id and token_id not in token_ids:
            token_ids.append(token_id)
        kind = str(event.get("kind") or "")[:40]
        if kind and kind not in kinds:
            kinds.append(kind)
        path = honeytoken_path(event)
        if path and path not in paths:
            paths.append(path)
    if not token_ids and not kinds:
        return None
    signal: Dict = {"token_ids": token_ids[:20], "kinds": kinds[:20]}
    if paths:
        signal["paths"] = paths[:20]
    return signal


def honeytoken_path(event: Dict) -> Optional[str]:
    """The file a token was planted in, when the event's detail names one."""
    detail = event.get("detail")
    candidates = []
    if isinstance(detail, dict):
        candidates = [detail.get("path"), detail.get("file"), detail.get("source")]
    elif isinstance(detail, str):
        candidates = [word for word in detail.split() if word.startswith("/")]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.startswith("/") and 3 < len(candidate) <= 255:
            return candidate.rstrip(".,;:")
    return None
