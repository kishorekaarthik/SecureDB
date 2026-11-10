"""Data-key rotation and re-encryption (spec §2.5)."""

import uuid
from dataclasses import dataclass

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from securedb.audit.log import Actor, append
from securedb.crypto.provider import KeyProvider
from securedb.crypto.tenant_keys import (
    KeyRing,
    dek_context,
    lock_key_management,
    lookup_context,
)
from securedb.crypto.values import EncryptedValue, ValueCipher
from securedb.db.models import Tenant, TenantKey, Token
from securedb.db.session import Database
from securedb.errors import CryptoError


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


def rotate_master(db: Database, old: KeyProvider, new: KeyProvider, *, actor: Actor) -> int:
    """Re-wrap every tenant's DEKs and lookup key from `old` to `new` in ONE transaction.

    Idempotent per key: keys already wrapped by `new` are left alone, so a rotation can be
    re-run to finish a mixed state. Holds the key-management lock exclusively, so no keys
    can be created under the old master key meanwhile. Token rows are untouched. Any
    failure rolls everything back. Running servers hold the old master key and must be
    restarted. Returns the number of tenants whose keys changed.
    """
    changed_tenants = 0
    with db.session() as session:
        lock_key_management(session, exclusive=True)
        tenants = session.scalars(
            select(Tenant).where(Tenant.wrapped_lookup_key.is_not(None)).order_by(Tenant.id)
        ).all()
        for tenant in tenants:
            session.execute(
                text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant.id)},
            )
            changed = False
            for key in session.scalars(select(TenantKey).where(TenantKey.tenant_id == tenant.id)):
                if key.provider_key_id == new.key_id:
                    continue
                context = dek_context(tenant.id, key.version)
                key.wrapped_dek = new.wrap(old.unwrap(key.wrapped_dek, context), context)
                key.provider, key.provider_key_id = new.name, new.key_id
                changed = True
            wrapped_lookup = tenant.wrapped_lookup_key or b""  # non-null by the query above
            context = lookup_context(tenant.id)
            try:
                new.unwrap(wrapped_lookup, context)  # already re-wrapped
            except CryptoError:
                tenant.wrapped_lookup_key = new.wrap(old.unwrap(wrapped_lookup, context), context)
                changed = True
            if not changed:
                continue
            session.flush()
            append(
                session,
                tenant.id,
                actor,
                "key.rotate_master",
                outcome={"from_key_id": old.key_id, "to_key_id": new.key_id},
            )
            changed_tenants += 1
    return changed_tenants
