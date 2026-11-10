"""Compare this system's captures with a Cowrie honeypot's, over the same period.

Takes an export from this system (``app.tools.export_dataset`` or
``app.tools.label_sessions export``) and a Cowrie JSON log (one event per
line, ``cowrie.json``), restricts both to the period they share (or the one
given), and reports for each side:

* unique sources and sessions per day;
* login-to-command conversion: of the sessions that logged in, how many
  went on to run a command;
* commands per session and session duration, as distributions;
* distinct command sequences;
* download URLs and file hashes, and which of them both saw.

Where two distributions are compared, a two-sided Mann-Whitney U test says
whether they differ in location. It is implemented here (normal
approximation, corrected for ties and continuity): scipy is not one of this
project's requirements. It is a test of the two samples in front of it;
whether the two honeypots faced the same traffic is a question about the
deployment (same network, same ports, same days), and the report cannot
answer it. State the placement of both with ``--note``.

    python -m app.tools.compare_cowrie --honeysentinel sessions.jsonl --cowrie cowrie.json \\
        --note "both on 203.0.113.0/24, ports 22/23, 2026-11-01 to 2026-11-14" --out compare.json

Source addresses in an anonymised export are pseudonyms, so sources are
counted per side and never matched across sides.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.tools.session_io import read_jsonl

#: Samples below this on either side make the normal approximation poor; the
#: test is still reported, flagged.
MIN_SAMPLE_FOR_NORMAL_APPROXIMATION = 20


def _epoch(value) -> Optional[float]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return None


def honeysentinel_sessions(path: str) -> List[Dict]:
    """Sessions from one of this system's exports, in the comparison's shape."""
    sessions = []
    for record in read_jsonl(path):
        commands = []
        for item in record.get("commands") or []:
            commands.append(str(item.get("command") or "") if isinstance(item, dict) else str(item))
        credentials = [c for c in (record.get("credentials") or []) if isinstance(c, dict)]
        events = [e for e in (record.get("events") or []) if isinstance(e, dict)]
        sessions.append({
            "source": str(record.get("source") or record.get("attacker_ip") or record.get("source_ip") or ""),
            "start": _epoch(record.get("started_at") or record.get("start_time")),
            "duration": float(record.get("duration_seconds") or 0.0),
            "commands": [c for c in commands if c.strip()],
            "logged_in": any(c.get("success") for c in credentials),
            "urls": sorted({str(e["url"]) for e in events if e.get("event_type") == "file_download" and e.get("url")}),
            "hashes": sorted({str(h).lower() for h in (record.get("file_hashes") or [])}
                             | {str(u.get("sha256")).lower() for u in (record.get("uploads") or [])
                                if isinstance(u, dict) and u.get("sha256")}),
        })
    return sessions


def cowrie_sessions(path: str) -> List[Dict]:
    """Sessions rebuilt from a Cowrie JSON event log."""
    by_id: Dict[str, Dict] = {}
    for event in read_jsonl(path):
        session_id = event.get("session")
        if not session_id:
            continue
        session = by_id.setdefault(str(session_id), {
            "source": "", "start": None, "duration": 0.0, "commands": [],
            "logged_in": False, "urls": set(), "hashes": set(), "_last": None,
        })
        stamp = _epoch(event.get("timestamp"))
        if stamp is not None:
            session["start"] = stamp if session["start"] is None else min(session["start"], stamp)
            session["_last"] = stamp if session["_last"] is None else max(session["_last"], stamp)
        kind = str(event.get("eventid") or "")
        if kind == "cowrie.session.connect":
            session["source"] = str(event.get("src_ip") or "")
        elif kind == "cowrie.login.success":
            session["logged_in"] = True
        elif kind == "cowrie.command.input":
            command = str(event.get("input") or "")
            if command.strip():
                session["commands"].append(command)
        elif kind == "cowrie.session.closed":
            try:
                session["duration"] = float(event.get("duration") or 0.0)
            except (TypeError, ValueError):
                pass
        elif kind in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            if event.get("url"):
                session["urls"].add(str(event["url"]))
            if event.get("shasum"):
                session["hashes"].add(str(event["shasum"]).lower())
        if not session["source"] and event.get("src_ip"):
            session["source"] = str(event["src_ip"])

    sessions = []
    for session in by_id.values():
        # A log cut before the close event still has a first and last time.
        if not session["duration"] and session["start"] is not None and session["_last"] is not None:
            session["duration"] = session["_last"] - session["start"]
        session.pop("_last")
        session["urls"], session["hashes"] = sorted(session["urls"]), sorted(session["hashes"])
        sessions.append(session)
    return sessions


def mann_whitney_u(a: List[float], b: List[float]) -> Optional[Dict]:
    """Two-sided Mann-Whitney U test, normal approximation.

    Mid-ranks for ties, the variance corrected for them, and a continuity
    correction of one half. Returns None when either sample is empty or all
    values are equal (there is nothing to rank).
    """
    n1, n2 = len(a), len(b)
    if not n1 or not n2:
        return None
    combined = sorted([(value, 0) for value in a] + [(value, 1) for value in b])
    ranks = [0.0] * len(combined)
    tie_term = 0.0
    index = 0
    while index < len(combined):
        end = index
        while end + 1 < len(combined) and combined[end + 1][0] == combined[index][0]:
            end += 1
        size = end - index + 1
        for position in range(index, end + 1):
            ranks[position] = (index + end) / 2.0 + 1.0
        tie_term += size ** 3 - size
        index = end + 1

    rank_sum_a = sum(rank for rank, (_, side) in zip(ranks, combined) if side == 0)
    u_a = rank_sum_a - n1 * (n1 + 1) / 2.0
    u = min(u_a, n1 * n2 - u_a)
    total = n1 + n2
    variance = n1 * n2 / 12.0 * ((total + 1) - tie_term / (total * (total - 1)))
    if variance <= 0:
        return None
    z = (abs(u_a - n1 * n2 / 2.0) - 0.5) / math.sqrt(variance)
    z = max(z, 0.0)
    p_value = math.erfc(z / math.sqrt(2.0))
    return {
        "test": "Mann-Whitney U, two-sided, normal approximation with tie and continuity correction",
        "u": round(u, 2),
        "z": round(z, 4),
        "p_value": round(min(p_value, 1.0), 6),
        "n": [n1, n2],
        # P(a value from the first sample exceeds one from the second),
        # ties counted half: the size of the difference, which p is not.
        "common_language_effect": round(u_a / (n1 * n2), 4),
        "small_sample": min(n1, n2) < MIN_SAMPLE_FOR_NORMAL_APPROXIMATION,
    }


def _distribution(values: List[float]) -> Dict:
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "mean": round(statistics.fmean(ordered), 3),
        "median": round(statistics.median(ordered), 3),
        "p95": round(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))], 3),
        "max": round(ordered[-1], 3),
    }


def _sequence_id(commands: List[str]) -> str:
    return hashlib.sha256("\n".join(commands).encode("utf-8", "replace")).hexdigest()


def summarise(sessions: List[Dict]) -> Dict:
    days = Counter(
        datetime.fromtimestamp(s["start"], tz=timezone.utc).date().isoformat()
        for s in sessions if s["start"] is not None
    )
    logged_in = [s for s in sessions if s["logged_in"]]
    converted = [s for s in logged_in if s["commands"]]
    with_commands = [s for s in sessions if s["commands"]]
    return {
        "sessions": len(sessions),
        "unique_sources": len({s["source"] for s in sessions if s["source"]}),
        "days_with_sessions": len(days),
        "sessions_per_day": _distribution([float(n) for n in days.values()]),
        "sessions_by_day": dict(sorted(days.items())),
        "logged_in": len(logged_in),
        "logged_in_and_ran_a_command": len(converted),
        "login_to_command_conversion": round(len(converted) / len(logged_in), 4) if logged_in else None,
        "commands_per_session": _distribution([float(len(s["commands"])) for s in sessions]),
        "session_duration_seconds": _distribution([s["duration"] for s in sessions]),
        "distinct_command_sequences": len({_sequence_id(s["commands"]) for s in with_commands}),
        "download_urls": len({u for s in sessions for u in s["urls"]}),
        "file_hashes": len({h for s in sessions for h in s["hashes"]}),
    }


def _period(sessions: List[Dict]) -> Tuple[Optional[float], Optional[float]]:
    starts = [s["start"] for s in sessions if s["start"] is not None]
    return (min(starts), max(starts)) if starts else (None, None)


def compare(ours: List[Dict], theirs: List[Dict], since: Optional[float] = None,
            until: Optional[float] = None, note: str = "") -> Dict:
    from app.ai.provenance import run_metadata

    our_first, our_last = _period(ours)
    their_first, their_last = _period(theirs)
    # The period both logs cover, unless one was given.
    if since is None and our_first is not None and their_first is not None:
        since = max(our_first, their_first)
    if until is None and our_last is not None and their_last is not None:
        until = min(our_last, their_last)

    def within(session: Dict) -> bool:
        if session["start"] is None:
            return False
        return (since is None or session["start"] >= since) and (until is None or session["start"] <= until)

    ours_in, theirs_in = [s for s in ours if within(s)], [s for s in theirs if within(s)]
    our_urls, their_urls = ({u for s in side for u in s["urls"]} for side in (ours_in, theirs_in))
    our_hashes, their_hashes = ({h for s in side for h in s["hashes"]} for side in (ours_in, theirs_in))
    our_sequences = {_sequence_id(s["commands"]) for s in ours_in if s["commands"]}
    their_sequences = {_sequence_id(s["commands"]) for s in theirs_in if s["commands"]}

    def iso(value: Optional[float]) -> Optional[str]:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat() if value is not None else None

    warnings = []
    if not ours_in or not theirs_in:
        warnings.append("One side has no sessions in the compared period; nothing here is a comparison.")
    elif min(len(ours_in), len(theirs_in)) < MIN_SAMPLE_FOR_NORMAL_APPROXIMATION:
        warnings.append(
            f"Fewer than {MIN_SAMPLE_FOR_NORMAL_APPROXIMATION} sessions on one side: the tests are indicative at best."
        )
    return {
        **run_metadata("app.tools.compare_cowrie"),
        "what": "This system's captured sessions against a Cowrie log over a shared period.",
        "note": note or "placement of the two honeypots not stated",
        "period": {"since": iso(since), "until": iso(until)},
        "excluded_outside_period": {
            "honeysentinel": len(ours) - len(ours_in), "cowrie": len(theirs) - len(theirs_in),
        },
        "warning": " ".join(warnings) if warnings else None,
        "honeysentinel": summarise(ours_in),
        "cowrie": summarise(theirs_in),
        "tests": {
            "commands_per_session": mann_whitney_u(
                [float(len(s["commands"])) for s in ours_in], [float(len(s["commands"])) for s in theirs_in]),
            "session_duration_seconds": mann_whitney_u(
                [s["duration"] for s in ours_in], [s["duration"] for s in theirs_in]),
        },
        "overlap": {
            "download_urls_seen_by_both": sorted(our_urls & their_urls)[:200],
            "download_urls_only_honeysentinel": len(our_urls - their_urls),
            "download_urls_only_cowrie": len(their_urls - our_urls),
            "file_hashes_seen_by_both": sorted(our_hashes & their_hashes)[:200],
            "file_hashes_only_honeysentinel": len(our_hashes - their_hashes),
            "file_hashes_only_cowrie": len(their_hashes - our_hashes),
            "command_sequences_seen_by_both": len(our_sequences & their_sequences),
        },
    }


def table(report: Dict) -> str:
    """The comparison as a short text table."""
    ours, theirs = report["honeysentinel"], report["cowrie"]

    def cell(value) -> str:
        return "-" if value is None else str(value)

    rows = [
        ("sessions", ours["sessions"], theirs["sessions"]),
        ("unique sources", ours["unique_sources"], theirs["unique_sources"]),
        ("sessions/day (mean)", ours["sessions_per_day"].get("mean"), theirs["sessions_per_day"].get("mean")),
        ("logged in", ours["logged_in"], theirs["logged_in"]),
        ("login -> command", ours["login_to_command_conversion"], theirs["login_to_command_conversion"]),
        ("commands/session (median)", ours["commands_per_session"].get("median"), theirs["commands_per_session"].get("median")),
        ("commands/session (mean)", ours["commands_per_session"].get("mean"), theirs["commands_per_session"].get("mean")),
        ("duration s (median)", ours["session_duration_seconds"].get("median"), theirs["session_duration_seconds"].get("median")),
        ("distinct command sequences", ours["distinct_command_sequences"], theirs["distinct_command_sequences"]),
        ("download URLs", ours["download_urls"], theirs["download_urls"]),
        ("file hashes", ours["file_hashes"], theirs["file_hashes"]),
    ]
    lines = [
        f"Period: {report['period']['since']} to {report['period']['until']}",
        f"{'':30}{'HoneySentinel':>16}{'Cowrie':>16}",
    ]
    lines += [f"{name:30}{cell(a):>16}{cell(b):>16}" for name, a, b in rows]
    for name, test in report["tests"].items():
        if test:
            lines.append(
                f"{name}: U={test['u']}, z={test['z']}, p={test['p_value']}"
                + (" (small sample)" if test["small_sample"] else "")
            )
    overlap = report["overlap"]
    lines.append(
        f"Seen by both: {len(overlap['download_urls_seen_by_both'])} URL(s), "
        f"{len(overlap['file_hashes_seen_by_both'])} file hash(es), "
        f"{overlap['command_sequences_seen_by_both']} command sequence(s)"
    )
    if report["warning"]:
        lines.append(f"WARNING: {report['warning']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--honeysentinel", required=True, help="JSONL export from this system")
    parser.add_argument("--cowrie", required=True, help="Cowrie JSON log (one event per line)")
    parser.add_argument("--since", help="ISO date/time; start of the period (default: where both logs begin)")
    parser.add_argument("--until", help="ISO date/time; end of the period (default: where either log ends)")
    parser.add_argument("--note", default="", help="where and how the two honeypots were deployed")
    parser.add_argument("--out", help="write the report here as JSON")
    args = parser.parse_args(argv)

    report = compare(
        honeysentinel_sessions(args.honeysentinel), cowrie_sessions(args.cowrie),
        since=_epoch(args.since), until=_epoch(args.until), note=args.note,
    )
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    else:
        print(json.dumps(report, indent=2))
    print(table(report), file=sys.stderr if not args.out else sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
