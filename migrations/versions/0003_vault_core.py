"""API keys, access policies and tokens, all behind row-level security.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Fails closed: with no tenant context the predicate is NULL, so no rows match.
TENANT_MATCH = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"
# Authentication runs before the tenant is known: it may read only the presented key.
PREFIX_MATCH = "prefix = NULLIF(current_setting('app.api_key_prefix', true), '')"


def _created_at() -> sa.Column[object]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
    )


def _isolate(table: str) -> None:
    op.execute("ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON " + table + " "
        "USING (" + TENANT_MATCH + ") WITH CHECK (" + TENANT_MATCH + ")"
    )


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("prefix", sa.Text(), nullable=False, unique=True),
        sa.Column("secret_hash", sa.LargeBinary(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.Text()), nullable=False),
        _created_at(),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    _isolate("api_keys")
    op.execute(
        "CREATE POLICY api_key_auth_lookup ON api_keys FOR SELECT USING (" + PREFIX_MATCH + ")"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON api_keys TO securedb_app")

    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("api_key_id", sa.Uuid(), sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("field_type", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("effect", sa.Text(), nullable=False),
        sa.UniqueConstraint(
            "api_key_id", "field_type", "action", name="uq_policies_key_type_action"
        ),
        sa.CheckConstraint("action IN ('tokenize', 'detokenize')", name="ck_policies_action"),
        sa.CheckConstraint("effect IN ('allow', 'mask')", name="ck_policies_effect"),
        sa.CheckConstraint(
            "action = 'detokenize' OR effect = 'allow'", name="ck_policies_tokenize_allow"
        ),
    )
    _isolate("policies")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON policies TO securedb_app")

    op.create_table(
        "tokens",
        sa.Column("token", sa.Text(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.Text(), nullable=True),
        sa.Column("lookup_hmac", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        _created_at(),
        sa.UniqueConstraint("tenant_id", "type", "lookup_hmac", name="uq_tokens_dedup"),
    )
    op.create_index("ix_tokens_tenant_subject", "tokens", ["tenant_id", "subject_id"])
    _isolate("tokens")
    op.execute("GRANT SELECT, INSERT, DELETE ON tokens TO securedb_app")


def downgrade() -> None:
    op.drop_table("tokens")
    op.drop_table("policies")
    op.drop_table("api_keys")
