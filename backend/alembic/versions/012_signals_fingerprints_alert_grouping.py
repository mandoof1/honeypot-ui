"""Session fingerprints and derived signals; alerts that group across workers.

Sessions gain two JSONB columns:

* ``fingerprints`` holds what the engine measured of the client's handshake
  (SSH client version, HASSH, JA3/JA4, Telnet options, HTTP header order),
  as received with every value length-capped.
* ``signals`` holds flags the analysis derives: whether an AI agent drove the
  session and on what grounds, honeytokens used, whether the anomaly score
  is calibrated, what set the category, the severity, and any disagreement
  between the rules and the model stages.

Alerts gain two columns:

* ``session_ids`` lists every session folded into the alert. The alert used
  to keep only the first one, so an early brute-force alert absorbed a later
  compromise from the same address without a trace.
* ``group_key`` is the source and its fixed time window, unique, so the four
  ingest workers raising the same alert at once produce one row. The old
  ``dedup_key`` cannot carry the constraint: it repeats across the alerts
  already stored. Rows from before this revision keep a null ``group_key``
  (nulls do not collide).

Revision ID: 012
Revises: 011
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "honeypot_sessions",
        sa.Column("fingerprints", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("signals", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column("session_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("alerts", sa.Column("group_key", sa.String(200), nullable=True))
    op.create_index("uq_alerts_group_key", "alerts", ["group_key"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_alerts_group_key", table_name="alerts")
    op.drop_column("alerts", "group_key")
    op.drop_column("alerts", "session_ids")
    op.drop_column("honeypot_sessions", "signals")
    op.drop_column("honeypot_sessions", "fingerprints")
