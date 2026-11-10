"""Export stored sessions for labelling, and import the labels.

The pipeline's models have only ever been scored against other people's data
(CIC-IDS2017 flows, a synthetic held-out set). Measuring them on this
deployment's sessions needs those sessions labelled by a person, and this is
the round trip for that.

    # 1. Write the sessions and an empty labels file to fill in.
    python -m app.tools.label_sessions export --out sessions.jsonl --labels labels.jsonl
    python -m app.tools.label_sessions export --since 2026-11-01 --limit 200 ...

    # 2. Edit labels.jsonl: set "category" on each line to one of
    #    benign, reconnaissance, exploitation, exfiltration. Leave a line's
    #    category empty to leave the session unlabelled.

    # 3. Store the labels on the sessions (in signals.label).
    python -m app.tools.label_sessions import --labels labels.jsonl --labelled-by "analyst initials"

    # Later: export only what has been labelled, labels included.
    python -m app.tools.label_sessions export --only-labelled --out labelled.jsonl

The export holds the commands as they were captured, decrypted: it is for the
operator's own analysts and stays on the operator's machine. Passwords tried
are not written (the usernames and whether a login succeeded are); for a file
that can leave the deployment use ``app.tools.export_dataset``.

The pipeline's own verdict is left out of the export unless asked for
(``--with-verdict``): a labeller who is shown the rule layer's answer tends
to agree with it, and then the evaluation measures agreement with itself.

Run inside the backend container, where the encryption key is available.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select

from app.tools.session_io import CATEGORIES, read_jsonl, write_jsonl


def export_record(session, with_verdict: bool = False) -> Dict:
    """One stored session as a labelling record."""
    from app.ai.session_view import rebuild_session_data

    data = rebuild_session_data(session)
    record = {
        "session_id": session.session_uuid,
        "protocol": data["protocol"],
        "attacker_ip": data["attacker_ip"],
        "started_at": data["started_at"],
        "duration_seconds": data["duration_seconds"],
        "commands": data["commands"],
        "transcript": data["transcript"],
        # Who tried to log in and whether it worked; not what they typed.
        "credentials": [
            {"username": c.get("username"), "success": bool(c.get("success")), "timestamp": c.get("timestamp")}
            for c in data["credentials"]
        ],
        "failed_logins": data["failed_logins"],
        "uploads": data["uploads"],
        "events": data["events"],
        "packets": data["packets"],
        "keystroke_count": data["keystroke_count"],
        "fingerprints": data["fingerprints"],
    }
    signals = session.signals if isinstance(session.signals, dict) else {}
    if isinstance(signals.get("label"), dict):
        record["label"] = signals["label"]
    if with_verdict:
        record["pipeline_verdict"] = {
            "category": session.attack_category.value if session.attack_category else None,
            "rule_reason": session.rule_reason,
        }
    return record


async def export(args) -> int:
    from app.core.database import async_session_factory
    from app.models import HoneypotSession

    query = select(HoneypotSession).order_by(HoneypotSession.id)
    if args.since:
        since = datetime.fromisoformat(args.since)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        query = query.where(HoneypotSession.started_at >= since)
    if args.protocol:
        query = query.where(HoneypotSession.protocol == args.protocol.lower())
    if args.limit:
        query = query.limit(args.limit)

    async with async_session_factory() as db:
        rows = (await db.execute(query)).scalars().all()

    records = []
    for row in rows:
        labelled = isinstance(row.signals, dict) and isinstance(row.signals.get("label"), dict)
        if args.only_labelled and not labelled:
            continue
        # A refused connection holds nothing to label.
        if isinstance(row.signals, dict) and row.signals.get("refusal"):
            continue
        records.append(export_record(row, args.with_verdict))

    written = write_jsonl(args.out, records)
    print(f"{written} session(s) -> {args.out}", file=sys.stderr)
    if args.labels:
        template = [
            {
                "session_id": r["session_id"],
                "category": (r.get("label") or {}).get("category", ""),
                "notes": (r.get("label") or {}).get("notes", ""),
            }
            for r in records
        ]
        write_jsonl(args.labels, template)
        print(f"labels template -> {args.labels} (categories: {', '.join(CATEGORIES)})", file=sys.stderr)
    return 0


def read_labels(path: str) -> tuple:
    """(valid labels by session id, problems) from a labels file."""
    valid: Dict[str, Dict] = {}
    problems: List[str] = []
    for number, record in enumerate(read_jsonl(path), 1):
        session_id = record.get("session_id")
        category = str(record.get("category") or "").strip().lower()
        if not category:
            continue
        if not session_id:
            problems.append(f"line {number}: no session_id")
        elif category not in CATEGORIES:
            problems.append(f"line {number}: {category!r} is not one of {', '.join(CATEGORIES)}")
        else:
            valid[str(session_id)] = {"category": category, "notes": str(record.get("notes") or "")[:500]}
    return valid, problems


async def import_labels(args) -> int:
    from app.core.database import async_session_factory
    from app.models import HoneypotSession

    labels, problems = read_labels(args.labels)
    for problem in problems:
        print(f"skipped {problem}", file=sys.stderr)
    if not labels:
        print("No labels to import.", file=sys.stderr)
        return 1

    stored = 0
    now = datetime.now(timezone.utc).isoformat()
    async with async_session_factory() as db:
        rows = (
            await db.execute(select(HoneypotSession).where(HoneypotSession.session_uuid.in_(list(labels))))
        ).scalars().all()
        for row in rows:
            signals = dict(row.signals) if isinstance(row.signals, dict) else {}
            signals["label"] = {
                **labels[row.session_uuid],
                "labelled_by": args.labelled_by,
                "labelled_at": now,
            }
            row.signals = signals
            stored += 1
        if args.dry_run:
            await db.rollback()
        else:
            await db.commit()
    unknown = len(labels) - stored
    print(
        f"{'Would store' if args.dry_run else 'Stored'} {stored} label(s)"
        + (f"; {unknown} name a session that is not in the database" if unknown else ""),
        file=sys.stderr,
    )
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    out = commands.add_parser("export", help="write sessions (and a labels template) to files")
    out.add_argument("--out", required=True, help="JSONL of sessions to write")
    out.add_argument("--labels", help="also write a labels file to fill in")
    out.add_argument("--since", help="ISO date/time; sessions started at or after")
    out.add_argument("--protocol", help="only this protocol")
    out.add_argument("--limit", type=int, help="at most this many sessions")
    out.add_argument("--only-labelled", action="store_true", help="only sessions that carry a label")
    out.add_argument("--with-verdict", action="store_true",
                     help="include the pipeline's own category (biases labelling; off by default)")

    into = commands.add_parser("import", help="store labels from a file on the sessions")
    into.add_argument("--labels", required=True, help="JSONL of {session_id, category, notes}")
    into.add_argument("--labelled-by", required=True, help="who labelled them, for the record")
    into.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    return asyncio.run(export(args) if args.command == "export" else import_labels(args))


if __name__ == "__main__":
    raise SystemExit(main())
