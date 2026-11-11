"""GIN index on audit_log.token_ids for subject-export history lookups.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-10
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_audit_log_token_ids", "audit_log", ["token_ids"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("ix_audit_log_token_ids", table_name="audit_log")
