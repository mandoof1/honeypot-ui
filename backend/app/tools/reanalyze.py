"""Re-run the rule layer over stored sessions.

The verdict a session carries was fixed at ingest. When the signatures
change (as they did when the substring intent rules were replaced), every
existing row keeps the old answer, so the dashboard shows two different
rule sets side by side with no way to tell which is which.

This rebuilds the stage-1 inputs from what the row stores (commands,
credentials, events, packet summary, uploads, the flow model's class
distribution) and recomputes: NLP tools/intents, the rule-based category and
its reason, severity-independent fields (MITRE mapping, anomaly score on the
corrected scale), and the transcript hash. It never raises alerts, never
sends notifications, and never touches the encrypted evidence.

    python -m app.tools.reanalyze --dry-run            # report what would change
    python -m app.tools.reanalyze --all                # rewrite every session
    python -m app.tools.reanalyze --since 2026-10-01   # a window
    python -m app.tools.reanalyze --ids 2256 2262      # specific rows
    python -m app.tools.reanalyze --all --queue-llm    # also queue stage 2

Run inside the backend container, where the encryption key is available.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.database import async_session_factory
from app.core.encryption import decrypt_data
from app.models import AttackCategory, HoneypotSession
from app.services.analysis import _CATEGORY_RANK, analysis_pipeline

logger = logging.getLogger("reanalyze")


def _decrypt_json(blob):
    if not blob:
        return []
    try:
        return json.loads(decrypt_data(blob))
    except (ValueError, json.JSONDecodeError):
        return []


def _decrypt_lines(blob):
    if not blob:
        return []
    try:
        return [l for l in decrypt_data(blob).splitlines() if l.strip()]
    except ValueError:
        return []


def rebuild_session_data(session: HoneypotSession) -> dict:
    """The ingest payload, as far as the row lets it be reconstructed."""
    credentials = _decrypt_json(session.credentials_encrypted)
    failed = sum(1 for c in credentials if isinstance(c, dict) and not c.get("success"))
    packets = []
    summary = session.network_packets_summary or {}
    by_type = summary.get("by_type") if isinstance(summary, dict) else None
    for kind, entry in (by_type or {}).items():
        count = entry.get("count") if isinstance(entry, dict) else entry
        try:
            packets.extend({"type": kind} for _ in range(min(int(count or 0), 500)))
        except (TypeError, ValueError):
            continue
    return {
        "attacker_ip": session.attacker_ip,
        "protocol": session.protocol,
        "commands": _decrypt_lines(session.raw_commands_encrypted),
        "credentials": credentials,
        "failed_logins": failed,
        "uploads": [{"filename": f} for f in (session.uploaded_files or [])],
        "events": session.network_events or [],
        "packets": packets,
        "duration_seconds": session.duration_seconds or 0,
        "keystroke_count": session.keystroke_count or 0,
    }


def reanalyze_row(session: HoneypotSession) -> dict:
    """Recompute the rule-derived fields in place. Returns a change summary."""
    from app.ai.anomaly_detector import anomaly_detector
    from app.ai.mitre_mapper import mitre_mapper
    from app.ai.nlp_engine import nlp_engine
    import hashlib

    data = rebuild_session_data(session)
    commands = data["commands"]
    nlp_result = nlp_engine.analyze_commands(commands, data["protocol"] or "")

    # The flow model's verdict is recoverable from the stored distribution.
    probs = session.class_probabilities if isinstance(session.class_probabilities, dict) else {}
    if probs:
        flow_label = max(probs.items(), key=lambda kv: kv[1])[0]
        flow_conf = float(probs[flow_label])
    else:
        flow_label, flow_conf = "benign", float(session.attack_confidence or 0.0)
    try:
        flow_category = AttackCategory(flow_label)
    except ValueError:
        flow_category = AttackCategory.BENIGN

    rule_category, rule_confidence, rule_reason = analysis_pipeline._rule_based_category(
        nlp_result, data
    )
    if _CATEGORY_RANK[rule_category] > _CATEGORY_RANK[flow_category]:
        category, confidence, source = rule_category, rule_confidence, "rules"
    else:
        category, confidence = flow_category, flow_conf
        source = session.model_source if session.model_source and session.model_source != "rules" else "cicids2017"

    ai_result = {"category": category.value, "confidence": confidence}
    mitre_result = mitre_mapper.map_analysis(nlp_result, ai_result, data)

    before = {
        "category": session.attack_category.value if session.attack_category else None,
        "intents": sorted(session.detected_intents or []),
        "tools": sorted(session.detected_tools or []),
    }

    # Keep model-sourced techniques from stage 2; replace the rule-derived ones.
    kept = [t for t in (session.mitre_techniques or []) if isinstance(t, dict) and t.get("source") == "chimera"]
    techniques = list(mitre_result.get("techniques", []))
    known = {t.get("id") for t in techniques}
    techniques += [t for t in kept if t.get("id") not in known]
    tactics = list(mitre_result.get("tactic_ids", []))
    for t in kept:
        tactic = mitre_mapper.tactic_for_technique(t.get("id", ""))
        if tactic and tactic not in tactics:
            tactics.append(tactic)

    session.attack_category = category
    session.attack_confidence = confidence
    session.model_source = source
    session.rule_reason = (rule_reason or None) and rule_reason[:300]
    session.detected_tools = nlp_result.get("tool_names", [])
    session.detected_intents = nlp_result.get("detected_intents", [])
    session.mitre_tactics = tactics
    session.mitre_techniques = techniques
    if commands and not session.transcript_sha256:
        session.transcript_sha256 = hashlib.sha256(
            "\n".join(commands).encode("utf-8", "replace")
        ).hexdigest()

    # Anomaly scores stored before the scale fix were divided by 1.5.
    if session.anomaly_score is not None and session.anomaly_score <= 0.6667:
        rescored = round(min(session.anomaly_score * 1.5, 1.0), 4)
        session.anomaly_score = rescored

    after = {
        "category": category.value,
        "intents": sorted(session.detected_intents),
        "tools": sorted(session.detected_tools),
    }
    return {"id": session.id, "before": before, "after": after, "changed": before != after}


async def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--all", action="store_true")
    scope.add_argument("--since", type=str, help="ISO date/time; sessions started at or after")
    scope.add_argument("--ids", type=int, nargs="+")
    parser.add_argument("--dry-run", action="store_true", help="compute, report, do not write")
    parser.add_argument("--queue-llm", action="store_true",
                        help="also mark eligible sessions pending for the language model")
    parser.add_argument("--batch", type=int, default=200)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    query = select(HoneypotSession).order_by(HoneypotSession.id)
    if args.since:
        since = datetime.fromisoformat(args.since)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        query = query.where(HoneypotSession.started_at >= since)
    if args.ids:
        query = query.where(HoneypotSession.id.in_(args.ids))

    from app.services import enrichment

    changed = 0
    total = 0
    categories = Counter()
    queued = 0
    async with async_session_factory() as db:
        rows = (await db.execute(query)).scalars().all()
        for i, session in enumerate(rows, 1):
            total += 1
            report = reanalyze_row(session)
            categories[f"{report['before']['category']}→{report['after']['category']}"] += 1
            if report["changed"]:
                changed += 1
                print(json.dumps(report, default=str))
            if args.queue_llm and session.enrichment_status in ("none", "skipped", "failed"):
                data = rebuild_session_data(session)
                from app.ai.nlp_engine import nlp_engine

                nlp = nlp_engine.analyze_commands(data["commands"], data["protocol"] or "")
                status = enrichment.initial_status(session, nlp, data)
                if status == "pending":
                    session.enrichment_status = "pending"
                    queued += 1
            if not args.dry_run and i % args.batch == 0:
                await db.commit()
        if args.dry_run:
            await db.rollback()
        else:
            await db.commit()

    print(
        f"{'Would change' if args.dry_run else 'Changed'} {changed} of {total} session(s); "
        f"queued {queued} for the model.",
        file=sys.stderr,
    )
    for transition, count in categories.most_common():
        print(f"  {transition}: {count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
