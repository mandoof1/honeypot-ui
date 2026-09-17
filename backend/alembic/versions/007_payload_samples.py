"""Keep and analyse the files attackers upload.

The engine had a file-upload recorder that nothing called, and the ingest
path turned whatever uploads it received into a bare hash indicator: no
content, no type, nothing to say what the file was. Captured files now arrive
with their bytes, and are stored here encrypted and analysed statically.

Samples are unique by SHA-256 and linked to every session they appeared in,
because the same loader dropped by forty addresses is one sample seen forty
times — and that recurrence is what makes it worth reporting.

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


def upgrade() -> None:
    op.create_table(
        "payload_samples",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=False),
        sa.Column("md5", sa.String(32), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("content_encrypted", sa.Text(), nullable=True),
        sa.Column("file_kind", sa.String(32), nullable=True),
        sa.Column("file_type", sa.String(128), nullable=True),
        sa.Column("family", sa.String(64), nullable=True),
        sa.Column("analysis_status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("analysis_error", sa.String(500), nullable=True),
        sa.Column("analysis", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("analyser_version", sa.String(16), nullable=True),
        sa.Column("analysed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_payload_samples_sha256", "payload_samples", ["sha256"], unique=True)
    op.create_index("ix_payload_samples_file_kind", "payload_samples", ["file_kind"])
    op.create_index("ix_payload_samples_family", "payload_samples", ["family"])

    op.create_table(
        "session_artifacts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.Integer(), nullable=False),
        sa.Column("sample_id", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("remote_path", sa.String(500), nullable=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("methods", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("iocs_recorded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(["session_id"], ["honeypot_sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["sample_id"], ["payload_samples.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_session_artifacts_session_id", "session_artifacts", ["session_id"])
    op.create_index("ix_session_artifacts_sample_id", "session_artifacts", ["sample_id"])


def downgrade() -> None:
    op.drop_index("ix_session_artifacts_sample_id", table_name="session_artifacts")
    op.drop_index("ix_session_artifacts_session_id", table_name="session_artifacts")
    op.drop_table("session_artifacts")
    op.drop_index("ix_payload_samples_family", table_name="payload_samples")
    op.drop_index("ix_payload_samples_file_kind", table_name="payload_samples")
    op.drop_index("ix_payload_samples_sha256", table_name="payload_samples")
    op.drop_table("payload_samples")
