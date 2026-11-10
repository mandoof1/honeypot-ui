"""Measure the analysis pipeline, layer by layer, against labelled sessions.

Runs on files, with no database: a JSONL of sessions (the engine's stored
session JSON, the ingest payload, or an export from ``label_sessions``) and a
labels file (``{"session_id": ..., "category": ...}`` per line).

    python -m app.tools.eval_pipeline --sessions sessions.jsonl --labels labels.jsonl \\
        --dataset-description "controlled test traffic, 2026-11, node edge-1" \\
        --out ../docs/evaluation/pipeline-<date>.json

Measured in-process for every session: the rule layer, the flow classifier,
and the stored verdict (what ingest would write). With ``--models`` and the
endpoints configured (DECIDER_URL, CHIMERA_URL), triage and the language
model are measured too; nothing is called otherwise.

Reported per layer: the confusion matrix, per-class precision, recall and
F1, accuracy and macro F1 with bootstrap confidence intervals. Also: how
many technique ids each source produced that the ATT&CK catalog accepts, by
protocol; and the rule layer's time by transcript size.

The numbers describe the labelled set and nothing else. The report carries
the set's description, its size per class and protocol, and the code
revision. A set smaller than ``--min-sessions`` gets its matrices but no
headline figures, and says why: accuracy on a dozen sessions is an anecdote.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from collections import Counter
from typing import Dict, List, Optional, Sequence

from app.tools.session_io import CATEGORIES, load_labels, load_sessions

#: Below this many labelled sessions no headline figure is printed.
MIN_HEADLINE_SESSIONS = 30
#: A class with fewer labelled sessions than this is called out.
MIN_CLASS_SUPPORT = 5

SIZE_BUCKETS = ((0, 1_000, "under 1 kB"), (1_000, 10_000, "1-10 kB"),
                (10_000, 65_536, "10-64 kB"), (65_536, None, "over 64 kB"))


def confusion(pairs: Sequence[tuple]) -> Dict:
    """Rows are the labels, columns the predictions, over the four classes."""
    matrix = [[0] * len(CATEGORIES) for _ in CATEGORIES]
    other = 0
    for truth, predicted in pairs:
        if predicted not in CATEGORIES:
            other += 1
            continue
        matrix[CATEGORIES.index(truth)][CATEGORIES.index(predicted)] += 1
    return {"labels": list(CATEGORIES), "matrix": matrix, "no_prediction": other}


def per_class(pairs: Sequence[tuple]) -> Dict:
    out = {}
    for name in CATEGORIES:
        true_positive = sum(1 for t, p in pairs if t == name and p == name)
        predicted = sum(1 for _, p in pairs if p == name)
        actual = sum(1 for t, _ in pairs if t == name)
        precision = true_positive / predicted if predicted else None
        recall = true_positive / actual if actual else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision and recall else (0.0 if actual and predicted else None)
        )
        out[name] = {
            "precision": _round(precision), "recall": _round(recall), "f1": _round(f1), "support": actual,
        }
    return out


def _round(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, 4)


def accuracy(pairs: Sequence[tuple]) -> float:
    return sum(1 for t, p in pairs if t == p) / len(pairs)


def macro_f1(pairs: Sequence[tuple]) -> float:
    """Mean F1 over the classes that occur in the labels."""
    scores = [
        metrics["f1"] or 0.0
        for metrics in per_class(pairs).values() if metrics["support"]
    ]
    return sum(scores) / len(scores) if scores else 0.0


def bootstrap_interval(pairs: Sequence[tuple], metric, resamples: int, seed: int = 1) -> List[float]:
    """A 95% percentile interval for a metric, resampling sessions."""
    rng = random.Random(seed)
    n = len(pairs)
    values = sorted(metric([pairs[rng.randrange(n)] for _ in range(n)]) for _ in range(resamples))
    return [round(values[int(0.025 * resamples)], 4), round(values[min(resamples - 1, int(0.975 * resamples))], 4)]


def layer_report(pairs: Sequence[tuple], headline: bool, resamples: int, min_answered: int = 0) -> Dict:
    answered = [(t, p) for t, p in pairs if p is not None]
    report = {
        "sessions": len(pairs),
        "answered": len(answered),
        # A layer that answers a fraction of the sessions is scored on that
        # fraction only; the share is part of the result.
        "coverage": round(len(answered) / len(pairs), 4) if pairs else None,
        "confusion_matrix": confusion(answered),
        "per_class": per_class(answered) if answered else {},
    }
    if headline and answered and len(answered) < min_answered:
        report["headline_withheld"] = (
            f"answered {len(answered)} of {len(pairs)} sessions, fewer than {min_answered}"
        )
    elif headline and answered:
        report["accuracy"] = round(accuracy(answered), 4)
        report["accuracy_ci95"] = bootstrap_interval(answered, accuracy, resamples)
        report["macro_f1"] = round(macro_f1(answered), 4)
        report["macro_f1_ci95"] = bootstrap_interval(answered, macro_f1, resamples)
    return report


def _quantile(values: List[float], q: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 2)


def timing_by_size(samples: List[tuple]) -> List[Dict]:
    """Rule-layer milliseconds, grouped by the transcript's size in characters."""
    rows = []
    for low, high, name in SIZE_BUCKETS:
        times = [ms for size, ms in samples if size >= low and (high is None or size < high)]
        if times:
            rows.append({
                "transcript": name, "sessions": len(times),
                "p50_ms": _quantile(times, 0.5), "p95_ms": _quantile(times, 0.95), "max_ms": round(max(times), 2),
            })
    return rows


async def evaluate(
    sessions: List[Dict],
    labels: Dict[str, Dict],
    use_models: bool = False,
    resamples: int = 1000,
    min_sessions: int = MIN_HEADLINE_SESSIONS,
    allow_small: bool = False,
    dataset_description: str = "",
) -> Dict:
    from app.ai import verdict as verdicts
    from app.ai.attack_catalog import STATUSES, catalog
    from app.ai.classifier import classifier
    from app.ai.decider import decider
    from app.ai.llm import chimera
    from app.ai.mitre_mapper import mitre_mapper, validate_techniques
    from app.ai.provenance import run_metadata
    from app.ai.session_view import run_rules
    from app.services.enrichment import llm_category

    labelled = [s for s in sessions if s["session_id"] in labels]
    pairs: Dict[str, List[tuple]] = {"rules": [], "flow_classifier": [], "pipeline": []}
    timing: List[tuple] = []
    validity: Dict[str, Dict[str, Counter]] = {"rules": {}, "llm": {}}
    triage_enabled = use_models and decider.enabled
    llm_enabled = use_models and chimera.enabled
    if triage_enabled:
        pairs["triage"] = []
    if llm_enabled:
        pairs["llm"] = []

    # Models loaded before anything is timed.
    classifier.preload()
    run_rules({"commands": ["true"], "protocol": "ssh"})

    for session in labelled:
        truth = labels[session["session_id"]]["category"]
        protocol = session["protocol"]

        started = time.perf_counter()
        nlp_result = run_rules(session)
        rules = verdicts.rule_verdict(nlp_result, session)
        timing.append((sum(len(c) for c in session["commands"]), (time.perf_counter() - started) * 1000.0))

        flow = classifier.classify_flow(session.get("flow"), protocol)
        final = verdicts.reconcile(flow, rules)
        pairs["rules"].append((truth, rules.category))
        # A session without flow statistics has no flow verdict to score.
        pairs["flow_classifier"].append((truth, flow["category"] if flow["model_source"] != "no_flow" else None))
        pairs["pipeline"].append((truth, final["category"]))

        rule_counts = validity["rules"].setdefault(protocol, Counter())
        for technique in mitre_mapper.map_evidence(rules.evidence)["techniques"]:
            rule_counts[catalog.resolve(technique["id"]).status] += 1

        if triage_enabled and session["commands"]:
            triage = await decider.triage(
                session["commands"], protocol=protocol,
                duration_seconds=session["duration_seconds"], keystrokes=session["keystroke_count"],
            )
            pairs["triage"].append((truth, triage["category"] if triage else None))
        if llm_enabled and session["commands"]:
            analysis = await chimera.analyse(session["commands"], protocol=protocol)
            if analysis is None:
                pairs["llm"].append((truth, None))
            else:
                checked = validate_techniques(analysis.get("mitre_techniques") or [], source="chimera")
                llm_counts = validity["llm"].setdefault(protocol, Counter())
                llm_counts.update(checked["counts"])
                pairs["llm"].append((truth, llm_category(checked["verified"])[0]))

    by_label = Counter(labels[s["session_id"]]["category"] for s in labelled)
    warnings = []
    small = len(labelled) < min_sessions
    if small:
        warnings.append(
            f"Only {len(labelled)} labelled session(s); fewer than {min_sessions}. "
            "Headline figures are withheld: on a set this small they describe these sessions, not the system."
            if not allow_small else
            f"Only {len(labelled)} labelled session(s); the figures below describe these sessions, not the system."
        )
    thin = [name for name in CATEGORIES if 0 < by_label[name] < MIN_CLASS_SUPPORT]
    if thin:
        warnings.append(f"Fewer than {MIN_CLASS_SUPPORT} labelled sessions in: {', '.join(thin)}.")
    missing = [name for name in CATEGORIES if by_label[name] == 0]
    if missing:
        warnings.append(f"No labelled sessions in: {', '.join(missing)}. Nothing here measures those classes.")
    headline = bool(labelled) and (not small or allow_small)

    return {
        **run_metadata("app.tools.eval_pipeline"),
        "what": "Per-layer and end-to-end classification of labelled sessions by the analysis pipeline.",
        "dataset": {
            "description": dataset_description or "not described",
            "sessions_in_file": len(sessions),
            "labelled": len(labelled),
            "unlabelled": len(sessions) - len(labelled),
            "by_label": {name: by_label[name] for name in CATEGORIES},
            "by_protocol": dict(Counter(s["protocol"] for s in labelled)),
        },
        "warning": " ".join(warnings) if warnings else None,
        "headline_figures": headline,
        "models": {
            "flow_classifier": classifier.model_source,
            "triage": decider.model_name if triage_enabled else None,
            "llm": chimera.model_name if llm_enabled else None,
        },
        "attack_catalog": catalog.describe(),
        "layers": {
            name: layer_report(values, headline, resamples, 0 if allow_small else min_sessions)
            for name, values in pairs.items()
        },
        "technique_id_validity": {
            source: {
                protocol: {status: counts.get(status, 0) for status in STATUSES}
                for protocol, counts in sorted(by_protocol.items())
            }
            for source, by_protocol in validity.items() if by_protocol
        },
        "rule_layer_timing": timing_by_size(timing),
        "bootstrap_resamples": resamples if headline else 0,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", required=True, help="JSONL of sessions")
    parser.add_argument("--labels", required=True, help="JSONL of {session_id, category}")
    parser.add_argument("--dataset-description", default="",
                        help="what the sessions are, where and when they were captured, and who labelled them")
    parser.add_argument("--models", action="store_true",
                        help="also run triage and the language model, where their endpoints are configured")
    parser.add_argument("--bootstrap", type=int, default=1000, help="bootstrap resamples for the intervals")
    parser.add_argument("--min-sessions", type=int, default=MIN_HEADLINE_SESSIONS,
                        help="labelled sessions below which headline figures are withheld")
    parser.add_argument("--allow-small", action="store_true",
                        help="print headline figures for a small set anyway; the warning stays")
    parser.add_argument("--out", help="write the report here as JSON")
    args = parser.parse_args(argv)

    report = asyncio.run(evaluate(
        load_sessions(args.sessions), load_labels(args.labels),
        use_models=args.models, resamples=args.bootstrap, min_sessions=args.min_sessions,
        allow_small=args.allow_small, dataset_description=args.dataset_description,
    ))
    text = json.dumps(report, indent=2)
    print(text)
    if report["warning"]:
        print(f"WARNING: {report['warning']}", file=sys.stderr)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
