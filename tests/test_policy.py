import uuid

import pytest
from sqlalchemy import select

from securedb.audit.log import Actor
from securedb.crypto.local import LocalKeyProvider, LockedKeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import Tenant
from securedb.db.session import Database
from securedb.errors import Conflict, KeyProviderLocked, NotFound
from securedb.policy.engine import Action, Effect, decide, effects_for, set_policy
from securedb.tenants.api_keys import Scope, issue_api_key
from securedb.tenants.service import create_tenant, find_tenant_id
from securedb.vault.fields import FieldType


@pytest.fixture
def keyring(key_provider: LocalKeyProvider) -> KeyRing:
    return KeyRing(key_provider)


@pytest.fixture
def tenant(db: Database, keyring: KeyRing) -> uuid.UUID:
    return create_tenant(db, keyring, "acme", actor=Actor.system("test"))


@pytest.fixture
def key_id(db: Database, tenant: uuid.UUID) -> uuid.UUID:
    with db.tenant_session(tenant) as session:
        return issue_api_key(
            session, tenant, "svc", [Scope.tokenize], actor=Actor.system("test")
        ).id


def _decide(db: Database, tenant: uuid.UUID, key_id: uuid.UUID, action: Action) -> Effect:
    with db.tenant_session(tenant) as session:
        return decide(session, key_id, FieldType.pan, action)


# --- Tenants -----------------------------------------------------------------


def test_create_tenant_creates_keys(db: Database, keyring: KeyRing, tenant: uuid.UUID) -> None:
    with db.tenant_session(tenant) as session:
        assert keyring.active_dek(session, tenant).version == 1
    assert find_tenant_id(db, "acme") == tenant


def test_duplicate_tenant_names_conflict(db: Database, keyring: KeyRing, tenant: uuid.UUID) -> None:
    with pytest.raises(Conflict):
        create_tenant(db, keyring, "acme", actor=Actor.system("test"))


def test_unknown_tenant_name_is_not_found(db: Database) -> None:
    with pytest.raises(NotFound):
        find_tenant_id(db, "nobody")


def test_tenant_is_not_created_when_vault_is_locked(db: Database) -> None:
    with pytest.raises(KeyProviderLocked):
        create_tenant(db, KeyRing(LockedKeyProvider("locked")), "ghost", actor=Actor.system("test"))
    with db.session() as session:
        assert session.scalars(select(Tenant.name)).all() == []


@pytest.mark.parametrize("name", ["", "   "])
def test_blank_tenant_names_are_rejected(db: Database, keyring: KeyRing, name: str) -> None:
    with pytest.raises(ValueError, match="name"):
        create_tenant(db, keyring, name, actor=Actor.system("test"))


# --- Policies ----------------------------------------------------------------


def test_default_is_deny(db: Database, tenant: uuid.UUID, key_id: uuid.UUID) -> None:
    assert _decide(db, tenant, key_id, Action.detokenize) is Effect.deny
    assert _decide(db, tenant, key_id, Action.tokenize) is Effect.deny


def test_set_and_overwrite_policy(db: Database, tenant: uuid.UUID, key_id: uuid.UUID) -> None:
    with db.tenant_session(tenant) as session:
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.pan,
            Action.detokenize,
            Effect.mask,
            actor=Actor.system("test"),
        )
    assert _decide(db, tenant, key_id, Action.detokenize) is Effect.mask
    with db.tenant_session(tenant) as session:
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.pan,
            Action.detokenize,
            Effect.allow,
            actor=Actor.system("test"),
        )
    assert _decide(db, tenant, key_id, Action.detokenize) is Effect.allow
    with db.tenant_session(tenant) as session:
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.pan,
            Action.detokenize,
            Effect.deny,
            actor=Actor.system("test"),
        )
    assert _decide(db, tenant, key_id, Action.detokenize) is Effect.deny


def test_tokenize_can_only_be_allowed(db: Database, tenant: uuid.UUID, key_id: uuid.UUID) -> None:
    with db.tenant_session(tenant) as session, pytest.raises(ValueError, match="allow"):
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.pan,
            Action.tokenize,
            Effect.mask,
            actor=Actor.system("test"),
        )


def test_effects_for_returns_every_configured_type(
    db: Database, tenant: uuid.UUID, key_id: uuid.UUID
) -> None:
    with db.tenant_session(tenant) as session:
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.pan,
            Action.detokenize,
            Effect.mask,
            actor=Actor.system("test"),
        )
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.email,
            Action.detokenize,
            Effect.allow,
            actor=Actor.system("test"),
        )
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.pan,
            Action.tokenize,
            Effect.allow,
            actor=Actor.system("test"),
        )
        effects = effects_for(session, key_id, Action.detokenize)
    assert effects == {FieldType.pan: Effect.mask, FieldType.email: Effect.allow}


def test_policies_cannot_target_another_tenants_key(
    db: Database, keyring: KeyRing, tenant: uuid.UUID, key_id: uuid.UUID
) -> None:
    other = create_tenant(db, keyring, "globex", actor=Actor.system("test"))
    with db.tenant_session(other) as session, pytest.raises(NotFound):
        set_policy(
            session,
            other,
            key_id,
            FieldType.pan,
            Action.detokenize,
            Effect.allow,
            actor=Actor.system("test"),
        )


def test_policies_are_invisible_to_other_tenants(
    db: Database, keyring: KeyRing, tenant: uuid.UUID, key_id: uuid.UUID
) -> None:
    with db.tenant_session(tenant) as session:
        set_policy(
            session,
            tenant,
            key_id,
            FieldType.pan,
            Action.detokenize,
            Effect.allow,
            actor=Actor.system("test"),
        )
    other = create_tenant(db, keyring, "globex", actor=Actor.system("test"))
    assert _decide(db, other, key_id, Action.detokenize) is Effect.deny


def test_audited_operations_require_an_explicit_actor(
    db: Database, keyring: KeyRing, tenant: uuid.UUID, key_id: uuid.UUID
) -> None:
    with db.tenant_session(tenant) as session:
        with pytest.raises(TypeError, match="actor"):
            set_policy(session, tenant, key_id, FieldType.pan, Action.tokenize, Effect.allow)  # type: ignore[call-arg]
        with pytest.raises(TypeError, match="actor"):
            issue_api_key(session, tenant, "svc", [Scope.tokenize])  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="actor"):
        create_tenant(db, keyring, "globex")  # type: ignore[call-arg]
