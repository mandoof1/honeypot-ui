"""Evaluate the decision model against labelled transcripts.

Runs the production client (app.ai.decider) against a live /v1/systemone
endpoint, so the questions measured are the questions the pipeline asks.

Two measurements over a JSONL file in the Wolfram fine-tune's chat format
(system / user "Protocol: ...\\nCommands captured, in order: ..." / assistant
JSON with "mitre_techniques"), such as the held-out split of the Kaggle
dataset hadiabdulrahman/wolfram-bench-data (chimera-heldout.jsonl):

* Technique checks. Every technique that occurs anywhere in the file is
  asked about for every transcript. The labelled techniques are positives;
  the rest are hard negatives from the same domain. Reports ROC AUC and,
  per threshold, how many real techniques survive and how many wrong ones
  get through.
* Triage. The file has no triage labels, so they are derived from the
  labelled techniques by a fixed rule (below) and compared with both the
  decision model and the rule layer on the same transcripts.

    DECIDER_URL=http://127.0.0.1:18090 python -m app.tools.eval_decider \\
        --data chimera-heldout.jsonl --out ../docs/evaluation/decider-heldout.json

``--db-summary`` instead reports what triage did to the sessions stored in
the deployment's database (no labels exist for those): its category against
the rules', its routes, and its latency. Aggregates only; no address or
command leaves the database.

    docker compose exec backend python -m app.tools.eval_decider --db-summary

The transcripts in that file are synthetic: written by the generator that
produced the fine-tune's in-domain data, held out from training. Numbers on
them say how the model behaves on clean, typical sessions; they are not a
measurement on captured traffic.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from collections import Counter

#: Labels are derived from ATT&CK itself, by technique id, not through the
#: project's rule map (which files a wget download under Exfiltration).
#: Discovery and Reconnaissance: on their own, the session only looked.
_DISCOVERY = {"T1007", "T1016", "T1018", "T1033", "T1046", "T1049", "T1057", "T1069",
              "T1082", "T1083", "T1087", "T1135", "T1518", "T1595"}
#: Credential Access and Impact: the top severity level.
_HIGH = {"T1003", "T1110", "T1552", "T1555", "T1485", "T1486", "T1489", "T1490",
         "T1496", "T1498", "T1499"}
#: Exfiltration.
_EXFIL = {"T1020", "T1030", "T1041", "T1048", "T1567"}


def load(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            user = record["messages"][1]["content"]
            answer = json.loads(record["messages"][2]["content"])
            protocol = user.split("\n", 1)[0].split(":", 1)[1].strip().lower()
            body = user.split("in order", 1)[1].split("\n", 1)[1]
            commands = [c for c in body.strip().splitlines() if c.strip()]
            rows.append({
                "protocol": protocol,
                "commands": commands,
                "techniques": sorted({t["id"] for t in answer.get("mitre_techniques") or []}),
            })
    return rows


def derived_labels(techniques: list[str]) -> dict:
    """Category and severity implied by the labelled techniques.

    benign / level 0 with no technique; reconnaissance / level 1 when every
    technique is Discovery; exfiltration when any is Exfiltration; otherwise
    exploitation (the rule layer files credential access under it too).
    Level 3 when any technique is Credential Access, Impact or Exfiltration,
    else level 2.
    """
    parents = {t.split(".")[0] for t in techniques}
    if not parents:
        return {"category": "benign", "severity": 0}
    if parents <= _DISCOVERY:
        return {"category": "reconnaissance", "severity": 1}
    category = "exfiltration" if parents & _EXFIL else "exploitation"
    return {"category": category, "severity": 3 if parents & (_HIGH | _EXFIL) else 2}


def rules_category(row: dict) -> str:
    from app.ai.nlp_engine import nlp_engine
    from app.services.analysis import analysis_pipeline

    nlp = nlp_engine.analyze_commands(row["commands"], row["protocol"])
    category, _, _ = analysis_pipeline._rule_based_category(nlp, {"commands": row["commands"]})
    return category.value


def auc(pos: list[float], neg: list[float]) -> float:
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def ece(pairs: list[tuple[float, bool]], bins: int = 10) -> float:
    total = len(pairs)
    error = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        bucket = [(p, y) for p, y in pairs if lo <= p < hi or (b == bins - 1 and p == 1.0)]
        if bucket:
            confidence = sum(p for p, _ in bucket) / len(bucket)
            accuracy = sum(y for _, y in bucket) / len(bucket)
            error += len(bucket) / total * abs(confidence - accuracy)
    return error


async def run(args) -> dict:
    from app.ai.decider import decider
    from app.ai.mitre_mapper import mitre_mapper

    if not decider.enabled:
        sys.exit("DECIDER_URL is not set")
    rows = load(args.data)
    vocabulary = sorted({t for row in rows for t in row["techniques"]})

    scores: list[tuple[float, bool]] = []
    per_technique: dict[str, dict] = {}
    triage_rows = []
    check_ms, triage_ms = [], []
    for i, row in enumerate(rows, 1):
        started = time.perf_counter()
        support = await decider.check_techniques(
            row["commands"], row["protocol"],
            [{"id": t, "name": mitre_mapper.technique_name(t) or ""} for t in vocabulary],
        )
        check_ms.append((time.perf_counter() - started) * 1000.0)
        for tid, value in (support or {}).items():
            label = tid in row["techniques"]
            scores.append((value, label))
            stats = per_technique.setdefault(tid, {"pos": [], "neg": []})
            stats["pos" if label else "neg"].append(value)

        triage = await decider.triage(row["commands"], protocol=row["protocol"])
        triage_ms.append(triage["ms"] if triage else None)
        labels = derived_labels(row["techniques"])
        triage_rows.append({
            "label": labels,
            "rules": rules_category(row),
            "model": triage["category"] if triage else None,
            "severity": triage["severity"] if triage else None,
            "p_low": triage["p_low"] if triage else None,
            "p_compromise": triage["p_compromise"] if triage else None,
            "operator": triage["operator"] if triage else None,
        })
        print(f"[{i}/{len(rows)}] check {check_ms[-1]:.0f} ms, triage {triage_ms[-1] or 0:.0f} ms", file=sys.stderr)

    pos = [p for p, y in scores if y]
    neg = [p for p, y in scores if not y]
    thresholds = {}
    for threshold in (0.1, 0.2, 0.3, 0.4, 0.5):
        thresholds[str(threshold)] = {
            "real_kept": sum(p >= threshold for p in pos),
            "real_total": len(pos),
            "wrong_accepted": sum(p >= threshold for p in neg),
            "wrong_total": len(neg),
        }

    answered = [r for r in triage_rows if r["model"]]
    sev_pairs = [(r["severity"], r["label"]["severity"]) for r in answered]
    by_label = Counter(r["label"]["category"] for r in triage_rows)
    confusion = Counter(f'{r["label"]["category"]}->{r["model"]}' for r in answered)
    rules_confusion = Counter(f'{r["label"]["category"]}->{r["rules"]}' for r in triage_rows)
    from app.core.config import get_settings

    settings = get_settings()
    from app.services.enrichment import route_after_triage

    routes = Counter()
    for r in answered:
        status, _ = route_after_triage("pending", r["rules"], {"p_low": r["p_low"], "p_compromise": r["p_compromise"]})
        worth = r["label"]["severity"] >= 2
        routes[f'{"worth" if worth else "low"}->{status}'] += 1
    skip_wrongly = sum(
        1 for r in answered
        if r["label"]["severity"] >= 2 and r["p_low"] >= settings.DECIDER_SKIP_THRESHOLD
    )
    return {
        "model": decider.model_name,
        "data": args.data,
        "transcripts": len(rows),
        "synthetic": True,
        "technique_check": {
            "questions": len(scores),
            "positives": len(pos),
            "negatives": len(neg),
            "auc": round(auc(pos, neg), 4),
            "accuracy_at_0.5": round(sum((p >= 0.5) == y for p, y in scores) / len(scores), 4),
            "ece": round(ece(scores), 4),
            "mean_support_real": round(statistics.mean(pos), 4),
            "mean_support_wrong": round(statistics.mean(neg), 4),
            "thresholds": thresholds,
            "per_technique_auc": {
                tid: round(auc(s["pos"], s["neg"]), 3)
                for tid, s in sorted(per_technique.items()) if s["pos"] and s["neg"]
            },
            "ms_per_transcript": {
                "p50": round(statistics.median(check_ms)),
                "max": round(max(check_ms)),
                "questions_each": len(vocabulary),
            },
        },
        "triage": {
            "labels": dict(by_label),
            "label_rule": derived_labels.__doc__.strip(),
            "model_category_accuracy": round(
                sum(r["model"] == r["label"]["category"] for r in answered) / max(1, len(answered)), 4),
            "rules_category_accuracy": round(
                sum(r["rules"] == r["label"]["category"] for r in triage_rows) / len(triage_rows), 4),
            "model_confusion": dict(confusion),
            "rules_confusion": dict(rules_confusion),
            "severity_mae": round(statistics.mean(abs(s - y) for s, y in sev_pairs), 3) if sev_pairs else None,
            "severity_by_label": {
                str(level): round(statistics.mean(s for s, y in sev_pairs if y == level), 3)
                for level in sorted({y for _, y in sev_pairs})
            },
            "skip_threshold": settings.DECIDER_SKIP_THRESHOLD,
            "would_skip": sum(1 for r in answered if r["p_low"] >= settings.DECIDER_SKIP_THRESHOLD),
            "would_skip_wrongly": skip_wrongly,
            # What routing does with the rules' category as well, for shell
            # sessions (which the rules alone always send on): "worth" means
            # the labels put the session at level 2 or above.
            "routing": dict(routes),
            "operator": dict(Counter(r["operator"] for r in answered)),
            "ms_per_transcript": {
                "p50": round(statistics.median(m for m in triage_ms if m)),
                "max": round(max(m for m in triage_ms if m)),
            },
        },
    }


async def db_summary() -> dict:
    from sqlalchemy import select

    from app.core.database import async_session_factory
    from app.models import HoneypotSession

    async with async_session_factory() as db:
        rows = (
            await db.execute(select(HoneypotSession).where(HoneypotSession.triage_status != "none"))
        ).scalars().all()
    done = [r for r in rows if r.triage_status == "complete" and isinstance(r.triage, dict)]
    fresh = [r for r in done if not r.triage.get("reused_from_session")]
    latency = sorted(r.triage["ms"] for r in fresh if isinstance(r.triage.get("ms"), (int, float)))
    tokens = sorted(r.triage["input_tokens"] for r in fresh if isinstance(r.triage.get("input_tokens"), int))

    def rule(r):
        return r.attack_category.value if r.attack_category else "benign"

    def quantile(values, q):
        return round(values[min(len(values) - 1, int(q * len(values)))]) if values else None

    return {
        "sessions": len(rows),
        "by_status": dict(Counter(r.triage_status for r in rows)),
        "by_protocol": dict(Counter((r.protocol or "unknown") for r in done)),
        "triage_vs_rules": dict(Counter(f"{rule(r)}->{r.triage.get('category')}" for r in done)),
        "agreement_with_rules": round(sum(r.triage.get("category") == rule(r) for r in done) / max(1, len(done)), 4),
        "routes_applied": dict(Counter(r.triage["route"] for r in done if r.triage.get("route"))),
        "routes_suggested": dict(Counter(r.triage["suggested_route"] for r in done if r.triage.get("suggested_route"))),
        "operator": dict(Counter(r.triage.get("operator") for r in done)),
        "reused_identical_transcript": len(done) - len(fresh),
        "ms": {"p50": quantile(latency, 0.5), "p95": quantile(latency, 0.95), "max": quantile(latency, 1.0)},
        "input_tokens": {"p50": quantile(tokens, 0.5), "max": quantile(tokens, 1.0)},
    }


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--data", help="JSONL in the Wolfram chat format")
    mode.add_argument("--db-summary", action="store_true", help="summarise triage of the stored sessions")
    parser.add_argument("--out", help="write the report here as JSON")
    args = parser.parse_args(argv)
    report = asyncio.run(db_summary() if args.db_summary else run(args))
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")


if __name__ == "__main__":
    main()
