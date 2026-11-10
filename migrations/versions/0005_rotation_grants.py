"""Column-level UPDATE grants needed for key rotation and re-encryption.

The app may change a key's status and wrapping, and a token's ciphertext, nonce and
key version - never a token's ID, type, lookup hash or tenant.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-10
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "GRANT UPDATE (status, wrapped_dek, provider, provider_key_id) "
        "ON tenant_keys TO securedb_app"
    )
    op.execute("GRANT UPDATE (ciphertext, nonce, key_version) ON tokens TO securedb_app")


def downgrade() -> None:
    op.execute("REVOKE UPDATE ON tokens FROM securedb_app")
    op.execute("REVOKE UPDATE ON tenant_keys FROM securedb_app")
