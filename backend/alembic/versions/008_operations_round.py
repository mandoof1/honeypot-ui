"""Durable enrichment, alert handling and engine liveness.

Three things the first production weeks showed were missing:

* The LLM stage ran as a fire-and-forget task inside the ingest workers, so a
  restart dropped the queue and nothing recorded whether a session had been
  analysed. Sessions now carry an enrichment status and the result itself,
  and a single worker drains them in order.
* Alerts could not say why they fired, could not be grouped, carried no notes,
  and their notifications were sent inline from the ingest request. They gain
  a kind (session or system), a dedup key with an occurrence count, notes, and
  an outbox table that a background dispatcher retries.
* Nodes only had a heartbeat timestamp written at registration. They now keep
  the engine's last status report so the dashboard can show liveness, spool
  depth and disk space.

Also: account lockout counters, the indexes the hot queries were missing, and
ON DELETE CASCADE on the alert and indicator foreign keys so retention can
delete sessions without loading their children.

Revision ID: 008
Revises: 007
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- sessions: enrichment state and the rule layer's reasoning ----------
    op.add_column(
        "honeypot_sessions",
        sa.Column("enrichment_status", sa.String(16), nullable=False, server_default="none"),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("enrichment", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("enrichment_error", sa.String(500), nullable=True),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("enrichment_priority", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("rule_reason", sa.String(300), nullable=True),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("transcript_sha256", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_honeypot_sessions_transcript_sha256", "honeypot_sessions", ["transcript_sha256"]
    )
    op.create_index(
        "ix_honeypot_sessions_enrichment_pending",
        "honeypot_sessions",
        ["enrichment_priority", "id"],
        postgresql_where=sa.text("enrichment_status = 'pending'"),
    )
    op.create_index("ix_honeypot_sessions_node_id", "honeypot_sessions", ["node_id"])
    op.create_index("ix_honeypot_sessions_protocol", "honeypot_sessions", ["protocol"])
    op.create_index("ix_honeypot_sessions_geo_country", "honeypot_sessions", ["geo_country"])
    # The partial index could never serve the dashboard's `scanner_operator IS
    # NULL` filter; a plain btree indexes nulls too.
    op.drop_index("ix_honeypot_sessions_scanner_operator", table_name="honeypot_sessions")
    op.create_index(
        "ix_honeypot_sessions_scanner_operator", "honeypot_sessions", ["scanner_operator"]
    )

    # --- alerts: kind, grouping, notes, cascade ------------------------------
    op.alter_column("alerts", "session_id", existing_type=sa.Integer(), nullable=True)
    op.add_column(
        "alerts", sa.Column("kind", sa.String(16), nullable=False, server_default="session")
    )
    op.add_column("alerts", sa.Column("attacker_ip", sa.String(45), nullable=True))
    op.add_column("alerts", sa.Column("node_id", sa.Integer(), nullable=True))
    op.add_column("alerts", sa.Column("notes", sa.Text(), nullable=True))
    op.add_column(
        "alerts", sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1")
    )
    op.add_column("alerts", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("alerts", sa.Column("dedup_key", sa.String(160), nullable=True))
    op.create_foreign_key(
        "alerts_node_id_fkey", "alerts", "honeypot_nodes", ["node_id"], ["id"], ondelete="SET NULL"
    )
    op.drop_constraint("alerts_session_id_fkey", "alerts", type_="foreignkey")
    op.create_foreign_key(
        "alerts_session_id_fkey",
        "alerts",
        "honeypot_sessions",
        ["session_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_alerts_session_id", "alerts", ["session_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_attacker_ip", "alerts", ["attacker_ip"])
    op.create_index("ix_alerts_dedup_key", "alerts", ["dedup_key"])
    op.create_index("ix_alerts_kind", "alerts", ["kind"])
    op.execute("UPDATE alerts SET last_seen_at = created_at WHERE last_seen_at IS NULL")
    op.execute(
        "UPDATE alerts a SET attacker_ip = s.attacker_ip "
        "FROM honeypot_sessions s WHERE a.session_id = s.id AND a.attacker_ip IS NULL"
    )

    # --- indicators: cascade and the indexes the feed relies on --------------
    op.drop_constraint(
        "indicators_of_compromise_session_id_fkey",
        "indicators_of_compromise",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "indicators_of_compromise_session_id_fkey",
        "indicators_of_compromise",
        "honeypot_sessions",
        ["session_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_indicators_of_compromise_session_id", "indicators_of_compromise", ["session_id"]
    )
    op.create_index(
        "ix_indicators_of_compromise_type_value",
        "indicators_of_compromise",
        ["ioc_type", "value"],
    )

    # --- audit log -------------------------------------------------------------
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])

    # --- users: lockout ----------------------------------------------------------
    op.add_column(
        "users",
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))

    # --- nodes: liveness ---------------------------------------------------------
    op.add_column("honeypot_nodes", sa.Column("version", sa.String(32), nullable=True))
    op.add_column(
        "honeypot_nodes",
        sa.Column("last_status", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "honeypot_nodes",
        sa.Column("offline_alerted", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    # --- notification outbox -------------------------------------------------------
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.Integer(), nullable=True),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_notification_outbox_due",
        "notification_outbox",
        ["status", "next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_notification_outbox_due", table_name="notification_outbox")
    op.drop_table("notification_outbox")

    op.drop_column("honeypot_nodes", "offline_alerted")
    op.drop_column("honeypot_nodes", "last_status")
    op.drop_column("honeypot_nodes", "version")

    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_count")

    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")

    op.drop_index("ix_indicators_of_compromise_type_value", table_name="indicators_of_compromise")
    op.drop_index("ix_indicators_of_compromise_session_id", table_name="indicators_of_compromise")
    op.drop_constraint(
        "indicators_of_compromise_session_id_fkey",
        "indicators_of_compromise",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "indicators_of_compromise_session_id_fkey",
        "indicators_of_compromise",
        "honeypot_sessions",
        ["session_id"],
        ["id"],
    )

    op.drop_index("ix_alerts_kind", table_name="alerts")
    op.drop_index("ix_alerts_dedup_key", table_name="alerts")
    op.drop_index("ix_alerts_attacker_ip", table_name="alerts")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_session_id", table_name="alerts")
    op.drop_constraint("alerts_session_id_fkey", "alerts", type_="foreignkey")
    op.execute("DELETE FROM alerts WHERE session_id IS NULL")
    op.create_foreign_key(
        "alerts_session_id_fkey", "alerts", "honeypot_sessions", ["session_id"], ["id"]
    )
    op.drop_constraint("alerts_node_id_fkey", "alerts", type_="foreignkey")
    op.drop_column("alerts", "dedup_key")
    op.drop_column("alerts", "last_seen_at")
    op.drop_column("alerts", "occurrences")
    op.drop_column("alerts", "notes")
    op.drop_column("alerts", "node_id")
    op.drop_column("alerts", "attacker_ip")
    op.drop_column("alerts", "kind")
    op.alter_column("alerts", "session_id", existing_type=sa.Integer(), nullable=False)

    op.drop_index("ix_honeypot_sessions_scanner_operator", table_name="honeypot_sessions")
    op.create_index(
        "ix_honeypot_sessions_scanner_operator",
        "honeypot_sessions",
        ["scanner_operator"],
        postgresql_where=sa.text("scanner_operator IS NOT NULL"),
    )
    op.drop_index("ix_honeypot_sessions_geo_country", table_name="honeypot_sessions")
    op.drop_index("ix_honeypot_sessions_protocol", table_name="honeypot_sessions")
    op.drop_index("ix_honeypot_sessions_node_id", table_name="honeypot_sessions")
    op.drop_index("ix_honeypot_sessions_enrichment_pending", table_name="honeypot_sessions")
    op.drop_index("ix_honeypot_sessions_transcript_sha256", table_name="honeypot_sessions")
    op.drop_column("honeypot_sessions", "transcript_sha256")
    op.drop_column("honeypot_sessions", "rule_reason")
    op.drop_column("honeypot_sessions", "enrichment_priority")
    op.drop_column("honeypot_sessions", "enrichment_error")
    op.drop_column("honeypot_sessions", "enriched_at")
    op.drop_column("honeypot_sessions", "enrichment")
    op.drop_column("honeypot_sessions", "enrichment_status")
