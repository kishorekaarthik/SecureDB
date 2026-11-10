"""Console users and sessions, behind row-level security.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_MATCH = "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid"
# The session cookie is checked before the tenant is known: only the row whose hash
# was presented is visible.
SESSION_MATCH = "id_hash = decode(NULLIF(current_setting('app.session_hash', true), ''), 'hex')"


def _now(name: str) -> sa.Column[object]:
    return sa.Column(
        name, sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
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
        "console_users",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=False),
        sa.Column("totp_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("totp_key_version", sa.Integer(), nullable=False),
        sa.Column("last_totp_step", sa.BigInteger(), nullable=True),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("failed_logins", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        _now("created_at"),
        sa.UniqueConstraint("tenant_id", "email", name="uq_console_users_tenant_email"),
        sa.CheckConstraint("role IN ('owner', 'viewer')", name="ck_console_users_role"),
    )
    _isolate("console_users")
    op.execute("GRANT SELECT, INSERT, UPDATE ON console_users TO securedb_app")

    op.create_table(
        "console_sessions",
        sa.Column("id_hash", sa.LargeBinary(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("console_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("csrf_token", sa.Text(), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        _now("created_at"),
        _now("last_seen_at"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    _isolate("console_sessions")
    op.execute(
        "CREATE POLICY session_lookup ON console_sessions FOR SELECT USING (" + SESSION_MATCH + ")"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON console_sessions TO securedb_app")


def downgrade() -> None:
    op.drop_table("console_sessions")
    op.drop_table("console_users")
