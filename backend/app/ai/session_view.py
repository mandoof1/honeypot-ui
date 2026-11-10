"""One view of a session for every stage that analyses it.

A session reaches the analysis code two ways: as the engine's payload at
ingest, and as a stored row when a model is fitted or a row is reanalysed.
Each caller used to rebuild the second into the first for itself, slightly
differently (one split web requests on newlines, one dropped the protocol),
so a model was fitted on one picture of a session and applied to another.

``rebuild_session_data`` is the single reconstruction, and ``run_rules`` the
single way the rule layer is called on either form.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

from app.ai.nlp_engine import nlp_engine

logger = logging.getLogger(__name__)

#: The decoy's own flags are stored as a per-type count; this many are
#: re-expanded per type, which is more than any rule counts.
_MAX_REBUILT_PACKETS = 500


def decrypt_json(blob) -> list:
    """A stored JSON list, or an empty one when absent or unreadable."""
    from app.core.encryption import decrypt_data

    if not blob:
        return []
    try:
        data = json.loads(decrypt_data(blob))
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []


def decrypt_lines(blob) -> List[str]:
    from app.core.encryption import decrypt_data

    if not blob:
        return []
    try:
        return [line for line in decrypt_data(blob).splitlines() if line.strip()]
    except (ValueError, TypeError):
        return []


def stored_commands(session) -> List[str]:
    """The commands of a stored session, each one whole.

    The transcript keeps a command with its newlines (a web request and its
    body are one entry); the raw column joins commands with newlines, which
    splits them. The transcript is used when it holds every command, and the
    raw column for sessions longer than the transcript's cap or older than
    transcripts.
    """
    transcript = decrypt_json(getattr(session, "transcript_encrypted", None))
    commands = [str(e["command"]) for e in transcript if isinstance(e, dict) and e.get("command")]
    if commands and len(commands) >= int(getattr(session, "command_count", 0) or 0):
        return commands
    return decrypt_lines(getattr(session, "raw_commands_encrypted", None)) or commands


def rebuild_session_data(session) -> Dict:
    """The ingest payload, as far as a stored row lets it be reconstructed."""
    credentials = [c for c in decrypt_json(session.credentials_encrypted) if isinstance(c, dict)]
    transcript = [e for e in decrypt_json(session.transcript_encrypted) if isinstance(e, dict)]

    packets = []
    summary = session.network_packets_summary or {}
    by_type = summary.get("by_type") if isinstance(summary, dict) else None
    for kind, entry in (by_type or {}).items():
        count = entry.get("count") if isinstance(entry, dict) else entry
        try:
            packets.extend({"type": kind} for _ in range(min(int(count or 0), _MAX_REBUILT_PACKETS)))
        except (TypeError, ValueError):
            continue

    started = getattr(session, "started_at", None)
    return {
        "attacker_ip": session.attacker_ip,
        "protocol": session.protocol,
        "commands": stored_commands(session),
        "transcript": transcript,
        "credentials": credentials,
        "failed_logins": sum(1 for c in credentials if not c.get("success")),
        "uploads": [{"filename": f} for f in (session.uploaded_files or [])],
        "events": session.network_events or [],
        "packets": packets,
        "duration_seconds": session.duration_seconds or 0,
        "keystroke_count": session.keystroke_count or 0,
        "fingerprints": getattr(session, "fingerprints", None),
        "started_at": started.isoformat() if started is not None else None,
    }


def request_headers(session_data: Dict) -> Optional[List[Optional[Dict]]]:
    """Headers of each web request, parallel to the commands, when recorded."""
    transcript = session_data.get("transcript") or []
    commands = session_data.get("commands") or []
    if not transcript or len(transcript) != len(commands):
        return None
    headers = [e.get("headers") if isinstance(e, dict) else None for e in transcript]
    return headers if any(isinstance(h, dict) for h in headers) else None


def run_rules(session_data: Dict) -> Dict:
    """Run the rule layer on a session, the same way everywhere."""
    commands = [str(c) for c in (session_data.get("commands") or [])]
    return nlp_engine.analyze_commands(
        commands, str(session_data.get("protocol") or ""), request_headers(session_data)
    )


def is_refusal(session_data: Dict) -> bool:
    """Whether this is a connection the engine turned away, not a session.

    A connection refused by the engine's rate limits arrives as a minimal
    record: source port 0, nothing typed, and a single ``connection_refused``
    event. Nothing happened in it to analyse.
    """
    events = [e for e in (session_data.get("events") or []) if isinstance(e, dict)]
    if not events or any(e.get("event_type") != "connection_refused" for e in events):
        return False
    return not session_data.get("commands") and not session_data.get("credentials") \
        and not session_data.get("uploads") and not int(session_data.get("attacker_port") or 0)
