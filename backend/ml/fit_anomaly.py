"""Fit the anomaly detector on the deployment's stored sessions.

The detector the system starts with is fitted on invented data, and until
this has run (or the scheduler has run it, once enough sessions exist) the
pipeline treats its output as uncalibrated: a score is shown, nothing is
flagged anomalous, and the score reaches neither severity nor alerts.

    python -m ml.fit_anomaly                       # fit, then re-score stored rows
    python -m ml.fit_anomaly --contamination 0.02
    python -m ml.fit_anomaly --min-sessions 500 --no-backfill

What a fit means, and does not:

* It is fitted on every stored session, attacks included. "Anomalous" then
  means unusual among the sessions this deployment has seen, not malicious:
  on a honeypot nearly every session is hostile, and the unusual one may be
  the benign one.
* ``contamination`` (ANOMALY_CONTAMINATION, 0.05 by default) is the share of
  the fitted sessions the model is told to call anomalous. It is an
  assumption, not something measured: with 0.05, the most isolated five per
  cent are flagged by construction. Report the value with any count of
  anomalous sessions.
* The minimum (ANOMALY_MIN_SESSIONS, 200) is a floor against fitting on a
  handful, not a claim that 200 is enough to characterise a deployment.

The model file records when it was fitted, on how many sessions, with what
contamination and at which code revision; the API reads it back labelled
"sessions", never "pretrained".
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
    parser.add_argument("--contamination", type=float, default=None,
                        help="share of fitted sessions to treat as anomalous (default: ANOMALY_CONTAMINATION)")
    parser.add_argument("--min-sessions", type=int, default=None,
                        help="refuse to fit on fewer (default: ANOMALY_MIN_SESSIONS)")
    parser.add_argument("--no-backfill", action="store_true",
                        help="do not re-score the stored sessions after fitting")
    args = parser.parse_args(argv)

    async with async_session_factory() as db:
        try:
            record = await maintenance.fit_anomaly(db, args.contamination, args.min_sessions)
        except ValueError as exc:
            print(exc)
            return 1
        if not args.no_backfill:
            record["backfilled"] = await maintenance.backfill_anomaly(db)

    print(json.dumps(record, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
