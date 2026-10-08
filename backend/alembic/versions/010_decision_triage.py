"""Decision-model triage ahead of the language model.

Sessions gain a second stage-2 state: a decision model (Kev, served by
llama.cpp's /v1/systemone) triages each session in seconds before the
language model spends minutes on it. ``triage_status`` is its queue, and
``triage`` holds the answer next to the rules' verdict it was weighed
against.

Revision ID: 010
Revises: 009
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "honeypot_sessions",
        sa.Column("triage_status", sa.String(16), nullable=False, server_default="none"),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("triage", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "honeypot_sessions",
        sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_honeypot_sessions_triage_pending",
        "honeypot_sessions",
        ["id"],
        postgresql_where=sa.text("triage_status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_index("ix_honeypot_sessions_triage_pending", table_name="honeypot_sessions")
    op.drop_column("honeypot_sessions", "triaged_at")
    op.drop_column("honeypot_sessions", "triage")
    op.drop_column("honeypot_sessions", "triage_status")
