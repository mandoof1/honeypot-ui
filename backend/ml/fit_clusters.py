"""Fit the behavioural cluster model on captured sessions.

Section VI.B claims the system "performs behavioural clustering for attacker
profiling". The rule-based scorecard it actually had is kept — it is
interpretable and works from the first session — but clustering is now real,
and this is what fits it.

Unlike the classifier, this needs no external dataset: it trains on the
honeypot's own captured sessions, which is the right corpus for grouping
behaviour and avoids the CIC-IDS2017 domain shift entirely.

    python -m ml.fit_clusters

Until it is run, the API reports ``behavioural_cluster: {"fitted": false}``
rather than inventing a cluster for every session.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

import numpy as np
from sqlalchemy import select

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ai.clustering import MIN_SESSIONS_TO_FIT, clusterer, extract  # noqa: E402
from app.ai.nlp_engine import nlp_engine  # noqa: E402
from app.core.database import async_session_factory  # noqa: E402
from app.core.encryption import decrypt_data  # noqa: E402
from app.models import HoneypotSession  # noqa: E402


def _decrypt_json(blob):
    if not blob:
        return []
    try:
        return json.loads(decrypt_data(blob))
    except (ValueError, TypeError):
        return []


def _rebuild(s: HoneypotSession) -> tuple[dict, dict]:
    """The ingest-time inputs to ``extract``, recovered from a stored session.

    Clusters are fitted here and assigned at ingest, so both must see the
    same vector. This used to zero the complexity and obfuscation features
    and never count failed logins, while ingest computed all three: the model
    was fitted on one picture of behaviour and applied to another. The NLP
    stage is re-run on the stored commands instead, which is exactly what
    ingest ran.
    """
    # The transcript keeps each command whole; the raw column joins them
    # with newlines, which splits any command that contains one.
    commands = [str(e.get("command", "")) for e in _decrypt_json(s.transcript_encrypted)]
    if not commands and s.raw_commands_encrypted:
        try:
            commands = decrypt_data(s.raw_commands_encrypted).splitlines()
        except ValueError:
            commands = []
    credentials = _decrypt_json(s.credentials_encrypted)
    session_data = {
        "duration_seconds": s.duration_seconds,
        "commands": commands,
        "failed_logins": sum(1 for c in credentials if not c.get("success")),
        "uploads": s.uploaded_files or [],
    }
    return session_data, nlp_engine.analyze_commands(commands)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


async def main() -> int:
    async with async_session_factory() as db:
        sessions = (await db.execute(select(HoneypotSession))).scalars().all()

    if len(sessions) < MIN_SESSIONS_TO_FIT:
        print(
            f"Only {len(sessions)} session(s) captured; {MIN_SESSIONS_TO_FIT} "
            f"are needed.\nRun the honeypot engine first — fitting on fewer "
            f"would produce assignments that look like findings but are noise."
        )
        return 1

    vectors = [extract(*_rebuild(s)) for s in sessions]

    stats = clusterer.fit(np.vstack(vectors))
    print(f"\n  Fitted {stats['n_clusters']} clusters over {stats['n_sessions']} sessions")
    for cluster, size in sorted(stats["sizes"].items()):
        print(f"    cluster {cluster}: {size:,} session(s)")
    print(f"  inertia {stats['inertia']:.2f}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
