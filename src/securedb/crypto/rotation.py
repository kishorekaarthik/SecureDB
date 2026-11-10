"""Data-key rotation and re-encryption (spec §2.5)."""

import uuid
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from securedb.audit.log import Actor, append
from securedb.crypto.tenant_keys import KeyRing
from securedb.crypto.values import EncryptedValue, ValueCipher
from securedb.db.models import TenantKey, Token
from securedb.db.session import Database


@dataclass(frozen=True)
class ReencryptResult:
    reencrypted: int
    retired_versions: list[int]


def rotate_dek(session: Session, keyring: KeyRing, tenant_id: uuid.UUID, *, actor: Actor) -> int:
    """New writes use a fresh DEK from now on. Existing values keep working (their old
    version is 'retiring') until `reencrypt` moves them. Returns the new version."""
    previous, new = keyring.add_dek_version(session, tenant_id)
    append(
        session,
        tenant_id,
        actor,
        "key.rotate_dek",
        outcome={"from_version": previous, "to_version": new},
    )
    return new


def reencrypt(
    db: Database,
    keyring: KeyRing,
    tenant_id: uuid.UUID,
    *,
    actor: Actor,
    batch_size: int = 500,
) -> ReencryptResult:
    """Re-encrypt every value not on the active DEK, one audited transaction per batch.

    Batches lock rows with SKIP LOCKED, so this can run beside live traffic and can be
    re-run after an interruption. Retiring versions no row uses any more become 'retired'.
    """
    cipher = ValueCipher(keyring)
    total = 0
    while True:
        with db.tenant_session(tenant_id) as session:
            active = keyring.active_dek(session, tenant_id)
            rows = session.scalars(
                select(Token)
                .where(Token.tenant_id == tenant_id, Token.key_version != active.version)
                .order_by(Token.token)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            ).all()
            if not rows:
                break
            for row in rows:
                value = cipher.decrypt(
                    session,
                    tenant_id,
                    row.token,
                    row.type,
                    EncryptedValue(row.ciphertext, row.nonce, row.key_version),
                )
                fresh = cipher.encrypt(session, tenant_id, row.token, row.type, value)
                row.ciphertext, row.nonce, row.key_version = (
                    fresh.ciphertext,
                    fresh.nonce,
                    fresh.key_version,
                )
            session.flush()
            append(
                session,
                tenant_id,
                actor,
                "key.reencrypt",
                token_ids=[row.token for row in rows],
                outcome={"count": len(rows), "to_version": active.version},
            )
            total += len(rows)

    with db.tenant_session(tenant_id) as session:
        retiring = session.scalars(
            select(TenantKey.version).where(
                TenantKey.tenant_id == tenant_id, TenantKey.status == "retiring"
            )
        ).all()
        in_use = set(session.scalars(select(Token.key_version).distinct()).all())
        retired = sorted(v for v in retiring if v not in in_use)
        if retired:
            session.execute(
                update(TenantKey)
                .where(TenantKey.tenant_id == tenant_id, TenantKey.version.in_(retired))
                .values(status="retired")
            )
            append(session, tenant_id, actor, "key.retire", outcome={"versions": retired})
    return ReencryptResult(reencrypted=total, retired_versions=retired)
