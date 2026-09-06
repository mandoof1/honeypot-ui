"""Persist capture identity checks and evidence truncation metadata.

Revision ID: 007
Revises: 006
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("honeypot_sessions", sa.Column("ingest_digest", sa.String(64), nullable=True))
    op.add_column("honeypot_sessions", sa.Column("capture_dropped", postgresql.JSONB(), nullable=True))
    op.create_index("ix_ioc_session_type_value", "indicators_of_compromise", ["session_id", "ioc_type", "value"])
    op.create_index("ix_sessions_started_id", "honeypot_sessions", ["started_at", "id"])


def downgrade():
    op.drop_index("ix_sessions_started_id", table_name="honeypot_sessions")
    op.drop_index("ix_ioc_session_type_value", table_name="indicators_of_compromise")
    op.drop_column("honeypot_sessions", "capture_dropped")
    op.drop_column("honeypot_sessions", "ingest_digest")
