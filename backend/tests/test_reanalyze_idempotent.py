"""Re-running the reanalysis tool must not change anomaly scores again.

It multiplied every score up to 0.6667 by 1.5 (the correction for rows stored
before the scale fix), so each run inflated scores that were already right.
"""

import json
from datetime import datetime, timezone

from app.core.encryption import encrypt_data
from app.models import HoneypotSession
from app.tools.reanalyze import reanalyze_row


def _row(score, created):
    return HoneypotSession(
        id=1,
        protocol="ssh",
        attacker_ip="203.0.113.9",
        anomaly_score=score,
        created_at=created,
        class_probabilities={"benign": 0.9, "exploitation": 0.1},
        raw_commands_encrypted=encrypt_data("uname -a\ncat /etc/passwd"),
        transcript_encrypted=encrypt_data(json.dumps([{"command": "uname -a"}])),
        network_events=[],
        uploaded_files=[],
    )


NEW = datetime(2026, 10, 11, tzinfo=timezone.utc)
OLD = datetime(2026, 10, 5, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)


def test_default_run_leaves_anomaly_scores_alone():
    row = _row(0.5, NEW)
    reanalyze_row(row)
    reanalyze_row(row)
    assert row.anomaly_score == 0.5


def test_rescale_applies_only_to_rows_stored_before_the_cutoff():
    old, new = _row(0.4, OLD), _row(0.4, NEW)
    reanalyze_row(old, CUTOFF)
    reanalyze_row(new, CUTOFF)
    assert old.anomaly_score == 0.6
    assert new.anomaly_score == 0.4
