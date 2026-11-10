"""Re-run the rule layer over stored sessions.

The verdict a session carries was fixed at ingest. When the signatures
change (as they did when the substring intent rules were replaced), every
existing row keeps the old answer, so the dashboard shows two different
rule sets side by side with no way to tell which is which.

This rebuilds the stage-1 inputs from what the row stores (commands,
credentials, events, packet summary, uploads) and recomputes: tools and
intents, the rule category, its confidence and reason, the ATT&CK mapping
(validated against the catalog), the derived signals and the transcript
hash. It never raises alerts, never sends notifications, and never touches
the encrypted evidence.

    python -m app.tools.reanalyze --dry-run --all      # report what would change
    python -m app.tools.reanalyze --all                # rewrite every session
    python -m app.tools.reanalyze --since 2026-10-01   # a window
    python -m app.tools.reanalyze --ids 2256 2262      # specific rows
    python -m app.tools.reanalyze --all --queue-llm    # also queue stage 2
    python -m app.tools.reanalyze --all --queue-triage # also queue triage
    python -m app.tools.reanalyze --all --queue-triage --retriage  # and redo it
    python -m app.tools.reanalyze --all --summary-only # rebuild only the plain summary
    python -m app.tools.reanalyze --all --attack-catalog
                                       # only clean stored techniques against the catalog
    python -m app.tools.reanalyze --all --backfill-referenced-ip
                                       # only retype indicators stored as "ip" + tag referenced_ip
    python -m app.tools.reanalyze --all --clusters     # only re-assign clusters with the fitted model
    python -m app.tools.reanalyze --all --anomaly      # only re-score (or clear uncalibrated flags)
    python -m app.tools.reanalyze --all --rescale-anomaly-before 2026-10-07T12:00
                                       # also fix scores stored before the scale fix

Every run ends with a JSON line on stdout counting, per protocol, how many
stored technique ids were valid, revoked-and-followed, matched by name,
deprecated or unverified against the ATT&CK catalog.

Run inside the backend container, where the encryption key is available.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import re
import sys
from collections import Counter
from typing import Dict, Optional
from datetime import datetime, timezone

from sqlalchemy import select

from app.ai import verdict as verdicts
from app.ai.attack_catalog import STATUSES, catalog
from app.ai.mitre_mapper import mitre_mapper, tactics_of, validate_techniques
from app.ai.session_view import decrypt_json, decrypt_lines, rebuild_session_data, run_rules
from app.ai.signals import ai_agent_signal, honeytoken_signal
from app.core.database import async_session_factory
from app.models import Alert, AttackCategory, HoneypotSession, IndicatorOfCompromise
from app.services.analysis import summarise_commands

logger = logging.getLogger("reanalyze")

_REQUEST_LINE = re.compile(r"^[A-Z]{3,7} \S")


def rebuild_summary(session: HoneypotSession) -> bool:
    """Recompute the plain command summary. Returns whether it changed.

    Built from the transcript, where each web request is one entry with its
    body attached. The stored command list is newline-joined, so a request's
    body lines come back from it as separate commands; when there is no
    transcript, only lines that look like request lines are kept for web
    sessions, so a body never reaches the summary.
    """
    protocol = (session.protocol or "").lower()
    transcript = decrypt_json(session.transcript_encrypted)
    commands = [
        str(t["command"]) for t in transcript if isinstance(t, dict) and t.get("command")
    ]
    if not commands:
        commands = decrypt_lines(session.raw_commands_encrypted)
        if protocol in ("http", "https"):
            commands = [c for c in commands if _REQUEST_LINE.match(c)]
    summary = summarise_commands(commands, protocol)
    if summary == session.command_summary:
        return False
    session.command_summary = summary
    return True


def count_id_validity(techniques, counts: Counter) -> None:
    """Tally how stored technique ids fare against the catalog."""
    for technique in techniques or []:
        if isinstance(technique, dict) and technique.get("id"):
            resolution = catalog.resolve(str(technique["id"]), str(technique.get("name") or ""))
            counts[resolution.status] += 1


def clean_attack(session: HoneypotSession) -> bool:
    """Validate a row's stored techniques against the catalog, in place.

    Rule-derived entries are checked as stored. Model-derived ones are
    rebuilt from the language model's own answer (kept in ``enrichment``)
    where there is one, so a name the old code overwrote with a parent's can
    still be matched. Unknown ids are removed from the session and listed
    under ``enrichment.unverified_techniques``. Returns whether it changed.
    """
    before = json.dumps([session.mitre_techniques, session.mitre_tactics], sort_keys=True, default=str)
    stored = [t for t in (session.mitre_techniques or []) if isinstance(t, dict)]
    rule_entries = validate_techniques([t for t in stored if t.get("source") != "chimera"])
    techniques = list(rule_entries["verified"])
    known = {t["id"] for t in techniques}

    enrichment = dict(session.enrichment) if isinstance(session.enrichment, dict) else None
    model_claims = (enrichment or {}).get("mitre_techniques") or [t for t in stored if t.get("source") == "chimera"]
    model_entries = validate_techniques(model_claims, source="chimera")
    for entry in model_entries["verified"]:
        if entry["id"] in known:
            continue
        entry["confidence"] = entry.get("support")
        if entry.get("support") is not None:
            entry["unconfirmed"] = bool(entry.get("unconfirmed"))
        techniques.append(entry)
        known.add(entry["id"])

    session.mitre_techniques = techniques
    session.mitre_tactics = tactics_of(techniques)
    if enrichment is not None:
        enrichment["mitre_techniques"] = model_entries["verified"]
        enrichment["unverified_techniques"] = model_entries["unverified"]
        session.enrichment = enrichment
    after = json.dumps([session.mitre_techniques, session.mitre_tactics], sort_keys=True, default=str)
    return before != after


def clean_alert_attack(alert: Alert) -> bool:
    before = json.dumps([alert.mitre_techniques, alert.mitre_tactics], sort_keys=True, default=str)
    verified = validate_techniques([t for t in (alert.mitre_techniques or []) if isinstance(t, dict)])["verified"]
    alert.mitre_techniques = verified
    alert.mitre_tactics = tactics_of(verified)
    return before != json.dumps([alert.mitre_techniques, alert.mitre_tactics], sort_keys=True, default=str)


def reanalyze_row(session: HoneypotSession, rescale_anomaly_before: Optional[datetime] = None) -> dict:
    """Recompute the rule-derived fields in place. Returns a change summary."""
    data = rebuild_session_data(session)
    commands = data["commands"]
    nlp_result = run_rules(data)
    rules = verdicts.rule_verdict(nlp_result, data)

    # The flow model's verdict is recoverable from the stored distribution.
    # It is advisory, exactly as at ingest.
    probs = session.class_probabilities if isinstance(session.class_probabilities, dict) else {}
    flow = {"category": "benign", "confidence": 0.0, "model_source": None}
    if probs:
        label = max(probs.items(), key=lambda kv: kv[1])[0]
        flow = {"category": label, "confidence": float(probs[label]), "model_source": "stored distribution"}
    final = verdicts.reconcile(flow, rules)
    mitre_result = mitre_mapper.map_evidence(rules.evidence)

    before = {
        "category": session.attack_category.value if session.attack_category else None,
        "intents": sorted(session.detected_intents or []),
        "tools": sorted(session.detected_tools or []),
    }

    # Keep model-sourced techniques from stage 2 (validated); replace the
    # rule-derived ones.
    kept = validate_techniques(
        [t for t in (session.mitre_techniques or []) if isinstance(t, dict) and t.get("source") == "chimera"],
        source="chimera",
    )["verified"]
    techniques = list(mitre_result.get("techniques", []))
    known = {t.get("id") for t in techniques}
    techniques += [t for t in kept if t.get("id") not in known]

    session.attack_category = AttackCategory(final["category"])
    session.attack_confidence = final["confidence"]
    session.model_source = final["source"]
    session.rule_reason = (rules.reason or None) and rules.reason[:300]
    session.detected_tools = nlp_result.get("tool_names", [])
    session.detected_intents = nlp_result.get("detected_intents", [])
    session.mitre_techniques = techniques
    session.mitre_tactics = tactics_of(techniques)
    if commands and not session.transcript_sha256:
        session.transcript_sha256 = hashlib.sha256(
            "\n".join(commands).encode("utf-8", "replace")
        ).hexdigest()

    # The derived signals, recomputed; what later stages added is kept.
    score = verdicts.severity_score(
        final["category"], final["confidence"],
        nlp_result.get("detected_intents"), nlp_result.get("critical_tools"),
        anomalous=False,
    )
    honeytoken = honeytoken_signal(data)
    agent = ai_agent_signal(data)
    signals = dict(session.signals) if isinstance(session.signals, dict) else {}
    signals["severity"] = verdicts.severity_level(score, floor="high" if honeytoken else "low")
    signals["severity_score"] = score
    signals["verdict"] = {
        "source": final["source"],
        "evidence": list(dict.fromkeys(item["key"] for item in rules.evidence))[:40],
        "independent_findings": len(rules.supporting),
        "flow": final["flow"],
        "rules_truncated": bool(nlp_result.get("truncated")),
    }
    for key, value in (("honeytoken", honeytoken), ("ai_agent", agent)):
        if value is not None:
            signals[key] = value
        else:
            signals.pop(key, None)
    signals.setdefault("anomaly", {"calibrated": False, "model_source": "synthetic"})
    session.signals = signals

    summary_changed = rebuild_summary(session)

    # Anomaly scores stored before the scale fix were divided by 1.5. Only
    # rows older than an explicit cutoff are corrected: the score itself
    # cannot say whether it was already fixed, so rescaling every score up
    # to 0.6667 multiplied correct ones by 1.5 again on each run.
    created = session.created_at
    if created is not None and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if (
        rescale_anomaly_before is not None
        and created is not None
        and created < rescale_anomaly_before
        and session.anomaly_score is not None
        and session.anomaly_score <= 0.6667
    ):
        session.anomaly_score = round(min(session.anomaly_score * 1.5, 1.0), 4)

    after = {
        "category": final["category"],
        "intents": sorted(session.detected_intents),
        "tools": sorted(session.detected_tools),
    }
    return {
        "id": session.id, "before": before, "after": after,
        "summary_changed": summary_changed,
        "changed": before != after or summary_changed,
    }


async def backfill_referenced_ip(db, session_ids=None) -> int:
    """Retype indicators that were stored as ``ip`` with a ``referenced_ip`` tag.

    An address that only appears in typed text used to share the type of the
    session's own source, so a blocklist built from ``ip`` blocked whatever
    an attacker had mentioned. Addresses the language model pointed at are
    of the same kind.
    """
    query = select(IndicatorOfCompromise).where(IndicatorOfCompromise.ioc_type == "ip")
    if session_ids is not None:
        query = query.where(IndicatorOfCompromise.session_id.in_(session_ids))
    changed = 0
    for row in (await db.execute(query)).scalars():
        tags = row.tags if isinstance(row.tags, list) else []
        if "referenced_ip" in tags or ("chimera" in tags and "attacker_ip" not in tags):
            row.ioc_type = "referenced_ip"
            changed += 1
    return changed


async def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--all", action="store_true")
    scope.add_argument("--since", type=str, help="ISO date/time; sessions started at or after")
    scope.add_argument("--ids", type=int, nargs="+")
    parser.add_argument("--dry-run", action="store_true", help="compute, report, do not write")
    parser.add_argument("--queue-llm", action="store_true",
                        help="also mark eligible sessions pending for the language model")
    parser.add_argument("--queue-triage", action="store_true",
                        help="queue untriaged sessions with commands for the decision model; "
                             "their language-model state is left as it is")
    parser.add_argument("--retriage", action="store_true",
                        help="with --queue-triage, also queue sessions already triaged")
    parser.add_argument("--rescale-anomaly-before", type=str, default=None,
                        help="ISO date/time; multiply anomaly scores of rows stored before it by 1.5 "
                             "(the pre-fix scale). Off by default; run it once, never twice")
    parser.add_argument("--summary-only", action="store_true",
                        help="rebuild only the plain command summary; leave verdicts and scores alone")
    parser.add_argument("--attack-catalog", action="store_true",
                        help="only validate stored techniques (sessions and their alerts) against the "
                             "ATT&CK catalog: drop unknown ids, follow revocations, take names and "
                             "tactics from the catalog")
    parser.add_argument("--backfill-referenced-ip", action="store_true",
                        help="only retype indicators stored as type ip with the referenced_ip tag")
    parser.add_argument("--clusters", action="store_true",
                        help="only re-assign clusters with the fitted model")
    parser.add_argument("--anomaly", action="store_true",
                        help="only re-score with a detector fitted on sessions, or clear the flags "
                             "the synthetic bootstrap set")
    parser.add_argument("--batch", type=int, default=200)
    args = parser.parse_args(argv)
    rescale_before = None
    if args.rescale_anomaly_before:
        rescale_before = datetime.fromisoformat(args.rescale_anomaly_before)
        if rescale_before.tzinfo is None:
            rescale_before = rescale_before.replace(tzinfo=timezone.utc)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    query = select(HoneypotSession).order_by(HoneypotSession.id)
    if args.since:
        since = datetime.fromisoformat(args.since)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        query = query.where(HoneypotSession.started_at >= since)
    if args.ids:
        query = query.where(HoneypotSession.id.in_(args.ids))

    from app.ai import maintenance
    from app.services import enrichment

    changed = 0
    total = 0
    categories = Counter()
    queued = 0
    triage_queued = 0
    extra: Dict = {}
    #: protocol -> status -> count, over technique ids as they were stored.
    validity: Dict[str, Counter] = {}
    only_one_thing = args.summary_only or args.attack_catalog or args.backfill_referenced_ip \
        or args.clusters or args.anomaly

    async with async_session_factory() as db:
        if args.clusters and not args.dry_run:
            extra["clusters_reassigned"] = await maintenance.backfill_clusters(db, args.batch)
        if args.anomaly and not args.dry_run:
            rescored = await maintenance.backfill_anomaly(db, args.batch)
            extra["anomaly_rescored"] = rescored
            if not rescored:
                extra["anomaly_flags_cleared"] = await maintenance.mark_anomaly_uncalibrated(db, args.batch)

        rows = (await db.execute(query)).scalars().all()
        for i, session in enumerate(rows, 1):
            total += 1
            count_id_validity(
                session.mitre_techniques,
                validity.setdefault((session.protocol or "unknown").lower(), Counter()),
            )
            if args.summary_only:
                if rebuild_summary(session):
                    changed += 1
                    print(json.dumps({"id": session.id, "summary_changed": True}))
            elif args.attack_catalog:
                if clean_attack(session):
                    changed += 1
                    print(json.dumps({"id": session.id, "attack_cleaned": True}))
            if only_one_thing:
                if not args.dry_run and i % args.batch == 0:
                    await db.commit()
                continue

            report = reanalyze_row(session, rescale_before)
            categories[f"{report['before']['category']}→{report['after']['category']}"] += 1
            if report["changed"]:
                changed += 1
                print(json.dumps(report, default=str))
            if args.queue_llm and session.enrichment_status in ("none", "skipped", "failed"):
                data = rebuild_session_data(session)
                status = enrichment.initial_status(session, run_rules(data), data)
                if status == "pending":
                    session.enrichment_status = "pending"
                    queued += 1
            if (
                args.queue_triage
                and (session.triage_status in ("none", "failed") or args.retriage)
                and session.raw_commands_encrypted
                and not session.scanner_operator
            ):
                # Triage of a row that already has a language-model state is
                # a second opinion only: routing applies to rows waiting on it.
                session.triage_status = "pending"
                session.triage = {"rules_verdict": session.enrichment_status}
                triage_queued += 1
            if not args.dry_run and i % args.batch == 0:
                await db.commit()

        if args.attack_catalog:
            alert_query = select(Alert).where(Alert.mitre_techniques.isnot(None))
            if not args.all:
                alert_query = alert_query.where(Alert.session_id.in_([s.id for s in rows]))
            extra["alerts_cleaned"] = sum(
                1 for alert in (await db.execute(alert_query)).scalars() if clean_alert_attack(alert)
            )
        if args.backfill_referenced_ip:
            extra["indicators_retyped"] = await backfill_referenced_ip(
                db, None if args.all else [s.id for s in rows]
            )

        if args.dry_run:
            await db.rollback()
        else:
            await db.commit()

    print(
        f"{'Would change' if args.dry_run else 'Changed'} {changed} of {total} session(s); "
        f"queued {queued} for the model and {triage_queued} for triage.",
        file=sys.stderr,
    )
    for transition, count in categories.most_common():
        print(f"  {transition}: {count}", file=sys.stderr)
    print(json.dumps({
        "sessions": total,
        "changed": changed,
        "dry_run": bool(args.dry_run),
        **extra,
        "attack_catalog": catalog.describe(),
        # Over the technique ids as stored before this run touched them.
        "attack_id_validity": {
            protocol: {status: counts.get(status, 0) for status in STATUSES}
            for protocol, counts in sorted(validity.items())
        },
    }))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
