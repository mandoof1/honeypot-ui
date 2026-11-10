"""Hardening round: retry counter, authenticator replay guard, indexes.

Two columns:

* ``payload_samples.analysis_attempts`` counts how often a sample's analysis
  has been started. A sample whose report could not be stored stayed
  ``pending`` and was picked up again every hour without end; with a counter
  it is marked ``failed`` after a few attempts.
* ``users.totp_last_step`` is the time step of the last authenticator code
  accepted for the account, so the same code cannot be used twice inside the
  ninety seconds it stays valid.

Indexes for queries that were scanning:

* ``honeypot_sessions.status``: the dashboard counts active sessions on every
  poll and the session list filters on it.
* ``honeypot_sessions (started_at, attack_category)``: the per-day trend
  series is a count by day and category over a date range, which this
  answers from the index alone.
* ``alerts.last_seen_at``: the alert list sorts on it first.
* ``audit_logs (user_id, created_at)``: the audit log view filters by user
  and sorts by time, and the sign-in path counts a user's recent
  second-factor failures.
* ``otp_verifications.user_id``: every code request counts the account's
  codes in the last hour.

Both this revision and 012 follow 010; a merge revision joins them.

Revision ID: 011
Revises: 010
"""

from alembic import op
import sqlalchemy as sa

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "payload_samples",
        sa.Column("analysis_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "users",
        sa.Column("totp_last_step", sa.BigInteger(), nullable=True),
    )

    op.create_index("ix_honeypot_sessions_status", "honeypot_sessions", ["status"])
    op.create_index(
        "ix_honeypot_sessions_started_category",
        "honeypot_sessions",
        ["started_at", "attack_category"],
    )
    op.create_index("ix_alerts_last_seen_at", "alerts", ["last_seen_at"])
    op.create_index(
        "ix_audit_logs_user_created", "audit_logs", ["user_id", "created_at"]
    )
    op.create_index(
        "ix_otp_verifications_user_id", "otp_verifications", ["user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_otp_verifications_user_id", table_name="otp_verifications")
    op.drop_index("ix_audit_logs_user_created", table_name="audit_logs")
    op.drop_index("ix_alerts_last_seen_at", table_name="alerts")
    op.drop_index(
        "ix_honeypot_sessions_started_category", table_name="honeypot_sessions"
    )
    op.drop_index("ix_honeypot_sessions_status", table_name="honeypot_sessions")
    op.drop_column("users", "totp_last_step")
    op.drop_column("payload_samples", "analysis_attempts")
