"""Attach the generator's labels to the sessions the engine stored.

    python -m tools.controlled_traffic.collect --manifest run/manifest.jsonl \
        --captures run/data/sessions --out run

Writes ``sessions.jsonl`` and ``labels.jsonl`` for
``python -m app.tools.eval_pipeline``, and ``dataset.json`` describing the set:
how many sessions each scenario and label produced, and how many stored
sessions were left out and why. A session gets a scenario's label when it
started inside that scenario's time window on one of its protocols; the
generator runs scenarios one at a time so the windows do not overlap.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

#: The engine timestamps a session when the connection is accepted, a moment
#: after the generator noted the scenario's start, and tools such as nmap may
#: hold a connection open slightly past their own exit.
SLACK_SECONDS = 1.0


def _epoch(value) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--captures", required=True, type=Path, help="the engine's session capture directory")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    header, footer, windows = {}, {}, []
    for line in args.manifest.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("header"):
            header = row
        elif row.get("footer"):
            footer = row
        else:
            windows.append(row)

    labelled, left_out = [], Counter()
    for path in sorted(args.captures.glob("*.json")):
        try:
            session = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            left_out["unreadable file"] += 1
            continue
        if not isinstance(session, dict) or "session_id" not in session:
            left_out["not a session record"] += 1
            continue
        if session.get("source_port") == 0:
            left_out["refused connection, not a session"] += 1
            continue
        started = _epoch(session.get("start_time"))
        if started is None:
            left_out["no start time"] += 1
            continue
        matches = [
            w for w in windows
            if w["started"] - SLACK_SECONDS <= started <= w["ended"] + SLACK_SECONDS
            and session.get("protocol") in w["protocols"]
        ]
        if len(matches) != 1:
            left_out["outside every scenario window" if not matches else "inside two windows"] += 1
            continue
        labelled.append((session, matches[0]))

    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "sessions.jsonl").open("w", encoding="utf-8") as sessions, \
            (args.out / "labels.jsonl").open("w", encoding="utf-8") as labels:
        for session, window in labelled:
            sessions.write(json.dumps(session) + "\n")
            labels.write(json.dumps({
                "session_id": session["session_id"],
                "category": window["label"],
                "scenario": window["scenario"],
            }) + "\n")

    by_label = Counter(w["label"] for _, w in labelled)
    by_scenario = Counter(w["scenario"] for _, w in labelled)
    by_protocol = Counter(s.get("protocol") for s, _ in labelled)
    dataset = {
        "kind": "controlled test traffic",
        "what": (
            "Sessions produced by tools/controlled_traffic/generate.py against a throwaway engine on "
            "loopback. Labels were assigned by construction: each session carries the label of the "
            "scripted scenario that produced it. None of this is traffic from real attackers."
        ),
        "label_definitions": header.get("labels"),
        "generator": {k: header.get(k) for k in ("seed", "rounds", "gap", "target")},
        "scenarios_run": len(windows),
        "sessions_labelled": len(labelled),
        "by_label": dict(sorted(by_label.items())),
        "by_scenario": dict(sorted(by_scenario.items())),
        "by_protocol": dict(sorted(by_protocol.items())),
        "left_out": dict(left_out),
        "generator_notes": footer.get("notes", []),
        "limits": [
            "The scripted shell and web scenarios were written by the team that wrote the rules, so the rule layer is being scored on traffic resembling what it was built for.",
            "Every session comes from one source address on loopback.",
            "A scenario's label is applied to every session inside its window; a scanner's individual probe connections all carry the scan's label.",
        ],
    }
    (args.out / "dataset.json").write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: dataset[k] for k in ("sessions_labelled", "by_label", "by_protocol", "left_out")}, indent=2))


if __name__ == "__main__":
    main()
