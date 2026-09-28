import secrets
import uuid
from collections.abc import Mapping

import pytest
from sqlalchemy import Engine, text

from securedb.crypto.local import LocalKeyProvider, LockedKeyProvider
from securedb.crypto.tenant_keys import DataKey, KeyRing
from securedb.db.models import Tenant, TenantKey
from securedb.db.session import Database
from securedb.errors import CryptoError, KeyProviderLocked, NotFound
from tests.helpers import create_tenant_with_keys, set_tenant


class CountingProvider:
    """Wraps a real provider and counts unwrap calls (to observe caching)."""

    def __init__(self, inner: LocalKeyProvider) -> None:
        self.inner = inner
        self.name = inner.name
        self.key_id = inner.key_id
        self.unwraps = 0

    def is_unlocked(self) -> bool:
        return True

    def wrap(self, key: bytes, context: Mapping[str, str]) -> bytes:
        return self.inner.wrap(key, context)

    def unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        self.unwraps += 1
        return self.inner.unwrap(wrapped, context)


def test_creates_active_dek_and_lookup_key_stored_only_wrapped(
    db: Database, key_provider: LocalKeyProvider
) -> None:
    keyring = KeyRing(key_provider)
    tenant_id = create_tenant_with_keys(db, keyring, "acme")
    with db.tenant_session(tenant_id) as session:
        row = session.get(TenantKey, (tenant_id, 1))
        tenant = session.get(Tenant, tenant_id)
        data_key = keyring.active_dek(session, tenant_id)
        lookup_key = keyring.lookup_key(session, tenant_id)
    assert row is not None and tenant is not None and tenant.wrapped_lookup_key is not None
    assert (row.status, row.provider, row.provider_key_id) == ("active", "local", "mk_test")
    assert data_key.version == 1
    assert len(data_key.key) == 32
    assert len(lookup_key) == 32
    assert data_key.key not in row.wrapped_dek
    assert lookup_key not in tenant.wrapped_lookup_key


def test_every_tenant_gets_distinct_keys(db: Database, key_provider: LocalKeyProvider) -> None:
    keyring = KeyRing(key_provider)
    first = create_tenant_with_keys(db, keyring, "acme")
    second = create_tenant_with_keys(db, keyring, "globex")
    with db.tenant_session(first) as session:
        first_dek = keyring.active_dek(session, first).key
        first_lookup = keyring.lookup_key(session, first)
    with db.tenant_session(second) as session:
        second_dek = keyring.active_dek(session, second).key
        second_lookup = keyring.lookup_key(session, second)
    assert len({first_dek, first_lookup, second_dek, second_lookup}) == 4


def test_keys_are_stable_across_keyring_instances(
    db: Database, key_provider: LocalKeyProvider
) -> None:
    tenant_id = create_tenant_with_keys(db, KeyRing(key_provider), "acme")
    with db.tenant_session(tenant_id) as session:
        assert (
            KeyRing(key_provider).active_dek(session, tenant_id).key
            == KeyRing(key_provider).active_dek(session, tenant_id).key
        )


def test_a_different_master_key_cannot_unwrap(db: Database, key_provider: LocalKeyProvider) -> None:
    tenant_id = create_tenant_with_keys(db, KeyRing(key_provider), "acme")
    impostor = KeyRing(LocalKeyProvider(secrets.token_bytes(32), key_id="mk_test"))
    with db.tenant_session(tenant_id) as session, pytest.raises(CryptoError):
        impostor.active_dek(session, tenant_id)


def test_wrapped_dek_copied_to_another_tenant_fails_to_unwrap(
    db: Database, key_provider: LocalKeyProvider, owner_engine: Engine
) -> None:
    keyring = KeyRing(key_provider)
    first = create_tenant_with_keys(db, keyring, "acme")
    second = create_tenant_with_keys(db, keyring, "globex")
    with owner_engine.begin() as conn:
        set_tenant(conn, first)
        stolen = conn.execute(text("SELECT wrapped_dek FROM tenant_keys")).scalar_one()
        set_tenant(conn, second)
        conn.execute(text("UPDATE tenant_keys SET wrapped_dek = :w"), {"w": stolen})
    with db.tenant_session(second) as session, pytest.raises(CryptoError):
        KeyRing(key_provider).active_dek(session, second)


def test_without_tenant_context_no_key_is_visible(
    db: Database, key_provider: LocalKeyProvider
) -> None:
    keyring = KeyRing(key_provider)
    tenant_id = create_tenant_with_keys(db, keyring, "acme")
    with db.session() as session, pytest.raises(NotFound):
        KeyRing(key_provider).active_dek(session, tenant_id)


def test_another_tenants_context_cannot_see_the_key(
    db: Database, key_provider: LocalKeyProvider
) -> None:
    keyring = KeyRing(key_provider)
    first = create_tenant_with_keys(db, keyring, "acme")
    second = create_tenant_with_keys(db, keyring, "globex")
    with db.tenant_session(second) as session, pytest.raises(NotFound):
        KeyRing(key_provider).dek(session, first, 1)


def test_unknown_version_is_not_found(db: Database, key_provider: LocalKeyProvider) -> None:
    keyring = KeyRing(key_provider)
    tenant_id = create_tenant_with_keys(db, keyring, "acme")
    with db.tenant_session(tenant_id) as session, pytest.raises(NotFound):
        keyring.dek(session, tenant_id, 99)


def test_unknown_tenant_cannot_get_keys(db: Database, key_provider: LocalKeyProvider) -> None:
    ghost = uuid.uuid4()
    with db.tenant_session(ghost) as session, pytest.raises(NotFound):
        KeyRing(key_provider).create_tenant_keys(session, ghost)


def test_keys_cannot_be_created_twice(db: Database, key_provider: LocalKeyProvider) -> None:
    keyring = KeyRing(key_provider)
    tenant_id = create_tenant_with_keys(db, keyring, "acme")
    with db.tenant_session(tenant_id) as session, pytest.raises(ValueError, match="already"):
        keyring.create_tenant_keys(session, tenant_id)


def test_unwrapped_keys_are_cached(db: Database, key_provider: LocalKeyProvider) -> None:
    counting = CountingProvider(key_provider)
    keyring = KeyRing(counting)
    tenant_id = create_tenant_with_keys(db, keyring, "acme")
    with db.tenant_session(tenant_id) as session:
        for _ in range(3):
            keyring.active_dek(session, tenant_id)
            keyring.lookup_key(session, tenant_id)
    assert counting.unwraps == 2  # one DEK + one lookup key


def test_locked_provider_cannot_create_keys(db: Database) -> None:
    tenant_id = uuid.uuid4()
    with db.session() as session:
        session.add(Tenant(id=tenant_id, name="acme"))
    keyring = KeyRing(LockedKeyProvider("locked for test"))
    with db.tenant_session(tenant_id) as session, pytest.raises(KeyProviderLocked):
        keyring.create_tenant_keys(session, tenant_id)


def test_data_key_repr_hides_the_key() -> None:
    key = bytes(range(32))
    text_repr = repr(DataKey(version=3, key=key))
    assert text_repr == "DataKey(version=3)"
    assert key.hex() not in text_repr
