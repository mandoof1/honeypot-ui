"""Fit the behavioural cluster model on captured sessions.

Section VI.B claims the system "performs behavioural clustering for attacker
profiling". The rule-based scorecard it actually had is kept — it is
interpretable and works from the first session — but clustering is now real,
and this is what fits it.

Unlike the classifier, this needs no external dataset: it trains on the
honeypot's own captured sessions, which is the right corpus for grouping
behaviour and avoids the CIC-IDS2017 domain shift entirely.

    python -m ml.fit_clusters                 # fit, then re-assign every stored row
    python -m ml.fit_clusters --no-backfill   # fit only

The backend's scheduler does the same on its own once enough sessions exist
(services/scheduler.py), so this is for fitting on demand. Fit and
assignment build their vectors with the same function from the same
reconstruction of a session (app/ai/session_view.py, app/ai/clustering.py);
the fit used to re-run the rules without the protocol, which skewed every
web session.

Until a model exists, the API reports ``behavioural_cluster: {"fitted": false}``
rather than inventing a cluster for every session.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ai import maintenance  # noqa: E402
from app.core.database import async_session_factory  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


async def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-backfill", action="store_true",
                        help="do not re-assign the stored sessions after fitting")
    args = parser.parse_args(argv)

    async with async_session_factory() as db:
        try:
            stats = await maintenance.fit_clusters(db)
        except ValueError as exc:
            print(f"{exc}\nRun the honeypot engine first.")
            return 1
        if not args.no_backfill:
            stats["backfilled"] = await maintenance.backfill_clusters(db)

    print(f"\n  Fitted {stats['k']} clusters over {stats['n']} sessions "
          f"(silhouette {stats['silhouette']})")
    for cluster, size in sorted(stats["sizes"].items()):
        print(f"    cluster {cluster}: {size:,} session(s)")
    print(f"  inertia {stats['inertia']:.2f}")
    if "backfilled" in stats:
        print(f"  re-assigned {stats['backfilled']:,} stored session(s)")
    print()
    print(json.dumps({k: v for k, v in stats.items() if k != "sizes"}, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
