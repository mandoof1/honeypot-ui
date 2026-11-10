"""Reading sessions and labels from files, for the evaluation tools.

The tools that measure the pipeline run on files, not on the database, so
the same set of sessions can be measured twice and the result compared. A
line of the sessions file may be any of the three shapes a session has
outside the database:

* the engine's stored session JSON (``SessionRecord.to_dict``: ``source_ip``,
  commands as objects, ``authentication_attempts``);
* the ingest payload the engine posts (``attacker_ip``, commands as strings);
* a line written by ``app.tools.label_sessions`` or ``export_dataset``.

``normalise`` turns each into the ingest payload shape the pipeline reads.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, Iterator, List, Optional

CATEGORIES = ("benign", "reconnaissance", "exploitation", "exfiltration")


def read_jsonl(path: str) -> Iterator[Dict]:
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: not JSON ({exc})") from exc
            if isinstance(record, dict):
                yield record


def write_jsonl(path: str, records) -> int:
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")
            count += 1
    return count


def _epoch(value) -> Optional[float]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def normalise(record: Dict) -> Dict:
    """One session in the ingest payload shape, whatever shape it came in."""
    commands_in = record.get("commands") or []
    transcript = record.get("transcript")
    if commands_in and isinstance(commands_in[0], dict):
        # The engine's own record: each command with its output and time.
        transcript = [
            {
                "command": str(c.get("command") or ""),
                "output": str(c.get("output") or ""),
                "exit_code": c.get("exit_code", 0),
                "timestamp": c.get("timestamp"),
            }
            for c in commands_in if isinstance(c, dict)
        ]
        commands = [entry["command"] for entry in transcript]
    else:
        commands = [str(c) for c in commands_in]

    attempts = record.get("credentials")
    if attempts is None:
        attempts = record.get("authentication_attempts") or []
    credentials = [
        {
            "username": str(a.get("username") or ""),
            "password": str(a.get("password") or ""),
            "success": bool(a.get("success")),
            "timestamp": a.get("timestamp"),
        }
        for a in attempts if isinstance(a, dict)
    ]

    events = record.get("events")
    if events is None:
        events = record.get("network_events") or []
    uploads = record.get("uploads")
    if uploads is None:
        uploads = record.get("files_uploaded") or []

    failed = record.get("failed_logins")
    if failed is None:
        failed = sum(1 for c in credentials if not c["success"])

    session_id = record.get("session_id") or record.get("session_uuid") or record.get("id")
    return {
        "session_id": str(session_id) if session_id is not None else None,
        "protocol": str(record.get("protocol") or "unknown").lower(),
        "attacker_ip": str(record.get("attacker_ip") or record.get("source_ip") or record.get("source") or ""),
        "attacker_port": record.get("attacker_port", record.get("source_port")),
        "started_at": record.get("started_at") or record.get("start_time"),
        "duration_seconds": float(record.get("duration_seconds") or 0.0),
        "commands": commands,
        "transcript": transcript or [],
        "credentials": credentials,
        "failed_logins": int(failed or 0),
        "uploads": [u for u in uploads if isinstance(u, dict)],
        "events": [e for e in events if isinstance(e, dict)],
        "packets": [p for p in (record.get("packets") or []) if isinstance(p, dict)],
        "flow": record.get("flow") if isinstance(record.get("flow"), dict) else None,
        "keystroke_count": int(record.get("keystroke_count") or 0),
        "fingerprints": record.get("fingerprints") if isinstance(record.get("fingerprints"), dict) else None,
        # Carried through when the line has one (label_sessions exports do).
        "label": record.get("label") if isinstance(record.get("label"), dict) else None,
    }


def load_sessions(path: str) -> List[Dict]:
    sessions = []
    for index, record in enumerate(read_jsonl(path)):
        session = normalise(record)
        if not session["session_id"]:
            session["session_id"] = f"line-{index + 1}"
        sessions.append(session)
    return sessions


def load_labels(path: str) -> Dict[str, Dict]:
    """``{session id: {"category": ..., ...}}`` from a labels JSONL file.

    A line without a category, or with one outside the four classes, is an
    unlabelled session and is left out: an evaluation must not count a blank
    as an answer.
    """
    labels: Dict[str, Dict] = {}
    for record in read_jsonl(path):
        session_id = record.get("session_id") or record.get("session_uuid")
        category = str(record.get("category") or "").strip().lower()
        if session_id is None or category not in CATEGORIES:
            continue
        labels[str(session_id)] = {**record, "category": category}
    return labels


def started_epoch(session: Dict) -> Optional[float]:
    return _epoch(session.get("started_at"))
