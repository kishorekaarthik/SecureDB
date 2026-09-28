"""Tenant data keys with row-level security; tenant lookup keys.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Fails closed: with no tenant context the predicate is NULL, so no rows match.
TENANT_MATCH = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.add_column("tenants", sa.Column("wrapped_lookup_key", sa.LargeBinary(), nullable=True))
    op.create_table(
        "tenant_keys",
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("provider_key_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'retiring', 'retired')", name="ck_tenant_keys_status"
        ),
    )
    op.create_index(
        "uq_tenant_keys_one_active",
        "tenant_keys",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.execute("ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON tenant_keys "
        "USING (" + TENANT_MATCH + ") WITH CHECK (" + TENANT_MATCH + ")"
    )
    op.execute("GRANT SELECT, INSERT ON tenant_keys TO securedb_app")


def downgrade() -> None:
    op.drop_table("tenant_keys")
    op.drop_column("tenants", "wrapped_lookup_key")
