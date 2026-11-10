import secrets
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import ProgrammingError

from securedb.audit.log import Actor, list_entries
from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.rotation import reencrypt, rotate_dek
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import TenantKey, Token
from securedb.db.session import Database
from securedb.errors import CryptoError, NotFound
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import AuthenticatedKey, Scope, issue_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType
from securedb.vault.service import TokenizeItem, TokenService
from tests.helpers import set_tenant

TEST = Actor.system("test")


@dataclass
class World:
    db: Database
    keyring: KeyRing
    service: TokenService
    tenant: uuid.UUID
    key: AuthenticatedKey


@pytest.fixture
def world(db: Database, key_provider: LocalKeyProvider) -> World:
    keyring = KeyRing(key_provider)
    tenant = create_tenant(db, keyring, "acme", actor=TEST)
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", [Scope.tokenize], actor=TEST)
        for action in (Action.tokenize, Action.detokenize):
            set_policy(
                session, tenant, issued.id, FieldType.email, action, Effect.allow, actor=TEST
            )
    key = AuthenticatedKey(issued.id, tenant, frozenset({"tokenize", "detokenize"}))
    return World(db, keyring, TokenService(keyring), tenant, key)


def _tokenize(w: World, *values: str) -> list[str]:
    with w.db.tenant_session(w.tenant) as session:
        items = [TokenizeItem(FieldType.email, v) for v in values]
        return [r.token for r in w.service.tokenize(session, w.key, items)]


def _values(w: World, tokens: list[str]) -> list[object]:
    with w.db.tenant_session(w.tenant) as session:
        return [r.value for r in w.service.detokenize(session, w.key, tokens)]


def _versions(w: World) -> dict[int, str]:
    with w.db.tenant_session(w.tenant) as session:
        rows = session.execute(select(TenantKey.version, TenantKey.status)).all()
    return {row.version: row.status for row in rows}


def _token_versions(w: World) -> list[int]:
    with w.db.tenant_session(w.tenant) as session:
        return sorted(session.scalars(select(Token.key_version)).all())


def test_rotate_makes_a_new_active_version(world: World) -> None:
    [old] = _tokenize(world, "old@example.com")
    with world.db.tenant_session(world.tenant) as session:
        assert rotate_dek(session, world.keyring, world.tenant, actor=TEST) == 2
    assert _versions(world) == {1: "retiring", 2: "active"}
    [new] = _tokenize(world, "new@example.com")
    assert _token_versions(world) == [1, 2]
    assert _values(world, [old, new]) == ["old@example.com", "new@example.com"]


def test_reencrypt_moves_everything_and_retires_old_versions(world: World) -> None:
    tokens = _tokenize(world, *(f"user{i}@example.com" for i in range(5)))
    with world.db.tenant_session(world.tenant) as session:
        rotate_dek(session, world.keyring, world.tenant, actor=TEST)
    with world.db.tenant_session(world.tenant) as session:
        rotate_dek(session, world.keyring, world.tenant, actor=TEST)
    result = reencrypt(world.db, world.keyring, world.tenant, actor=TEST, batch_size=2)
    assert result.reencrypted == 5
    assert result.retired_versions == [1, 2]
    assert _versions(world) == {1: "retired", 2: "retired", 3: "active"}
    assert _token_versions(world) == [3] * 5
    assert _values(world, tokens) == [f"user{i}@example.com" for i in range(5)]
    again = reencrypt(world.db, world.keyring, world.tenant, actor=TEST)
    assert (again.reencrypted, again.retired_versions) == (0, [])


def test_rotation_and_reencryption_are_audited(world: World) -> None:
    _tokenize(world, *(f"user{i}@example.com" for i in range(3)))
    with world.db.tenant_session(world.tenant) as session:
        rotate_dek(session, world.keyring, world.tenant, actor=TEST)
    reencrypt(world.db, world.keyring, world.tenant, actor=TEST, batch_size=2)
    with world.db.tenant_session(world.tenant) as session:
        entries = [
            e for e in list_entries(session, world.tenant, limit=200) if e.action.startswith("key.")
        ]
    assert [(e.action, e.outcome) for e in entries] == [
        ("key.rotate_dek", {"from_version": 1, "to_version": 2}),
        ("key.reencrypt", {"count": 2, "to_version": 2}),
        ("key.reencrypt", {"count": 1, "to_version": 2}),
        ("key.retire", {"versions": [1]}),
    ]


def test_reencrypt_needs_the_vault_key(world: World) -> None:
    _tokenize(world, "a@example.com")
    with world.db.tenant_session(world.tenant) as session:
        rotate_dek(session, world.keyring, world.tenant, actor=TEST)
    impostor = KeyRing(LocalKeyProvider(secrets.token_bytes(32), key_id="mk_test"))
    with pytest.raises(CryptoError):
        reencrypt(world.db, impostor, world.tenant, actor=TEST)
    assert _token_versions(world) == [1]  # nothing half-done


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE tokens SET token = 'tok_email_forged'",
        "UPDATE tokens SET type = 'pan'",
        "UPDATE tokens SET lookup_hmac = 'x'",
        "UPDATE tenant_keys SET tenant_id = gen_random_uuid()",
        "UPDATE tenant_keys SET version = 99",
    ],
)
def test_app_role_can_only_update_rotation_columns(
    world: World, app_engine: Engine, statement: str
) -> None:
    _tokenize(world, "a@example.com")
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        set_tenant(conn, world.tenant)
        conn.execute(text(statement))


def test_rotation_requires_the_tenants_context(world: World) -> None:
    with world.db.session() as session, pytest.raises(NotFound):
        rotate_dek(session, world.keyring, world.tenant, actor=TEST)
    with world.db.tenant_session(world.tenant) as session:
        assert session.scalar(select(func.count()).select_from(TenantKey)) == 1
