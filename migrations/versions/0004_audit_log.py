"""Per-tenant hash-chained audit log; the app role may only append and read.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_MATCH = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), primary_key=True),
        sa.Column("seq", sa.BigInteger(), primary_key=True, autoincrement=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("token_ids", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("outcome", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column("prev_hash", sa.LargeBinary(), nullable=False),
        sa.Column("hash", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(
            "actor_type IN ('api_key', 'console_user', 'system')", name="ck_audit_log_actor_type"
        ),
    )
    op.execute("ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_log FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON audit_log "
        "USING (" + TENANT_MATCH + ") WITH CHECK (" + TENANT_MATCH + ")"
    )
    # Append-only for the application: no UPDATE, no DELETE.
    op.execute("GRANT SELECT, INSERT ON audit_log TO securedb_app")


def downgrade() -> None:
    op.drop_table("audit_log")
