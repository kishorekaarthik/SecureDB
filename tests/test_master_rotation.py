import secrets
import uuid
from collections.abc import Mapping

import pytest
from sqlalchemy import select

from securedb.audit.log import Actor, list_entries
from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.rotation import rotate_master
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import TenantKey, Token
from securedb.db.session import Database
from securedb.errors import CryptoError
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import AuthenticatedKey, Scope, issue_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType
from securedb.vault.service import TokenizeItem, TokenService

TEST = Actor.system("test")


def _tenant_with_token(db: Database, keyring: KeyRing, name: str) -> tuple[uuid.UUID, str]:
    tenant = create_tenant(db, keyring, name, actor=TEST)
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", [Scope.tokenize], actor=TEST)
        for action in (Action.tokenize, Action.detokenize):
            set_policy(
                session, tenant, issued.id, FieldType.email, action, Effect.allow, actor=TEST
            )
    key = AuthenticatedKey(issued.id, tenant, frozenset({"tokenize", "detokenize"}))
    with db.tenant_session(tenant) as session:
        [result] = TokenService(keyring).tokenize(
            session, key, [TokenizeItem(FieldType.email, f"{name}@example.com")]
        )
    return tenant, result.token


def _read(db: Database, keyring: KeyRing, tenant: uuid.UUID, token: str) -> object:
    from securedb.crypto.values import EncryptedValue, ValueCipher

    with db.tenant_session(tenant) as session:
        row = session.get(Token, token)
        assert row is not None
        return ValueCipher(keyring).decrypt(
            session, tenant, token, row.type,
            EncryptedValue(row.ciphertext, row.nonce, row.key_version),
        )  # fmt: skip


@pytest.fixture
def old() -> LocalKeyProvider:
    return LocalKeyProvider(secrets.token_bytes(32), key_id="mk_old")


@pytest.fixture
def new() -> LocalKeyProvider:
    return LocalKeyProvider(secrets.token_bytes(32), key_id="mk_new")


def test_rotate_master_rewraps_every_tenant(
    db: Database, old: LocalKeyProvider, new: LocalKeyProvider
) -> None:
    tenants = [_tenant_with_token(db, KeyRing(old), name) for name in ("acme", "globex")]

    def ciphertexts() -> dict[str, bytes]:
        found: dict[str, bytes] = {}
        for tenant, token in tenants:
            with db.tenant_session(tenant) as session:
                row = session.get(Token, token)
                assert row is not None
                found[token] = row.ciphertext
        return found

    before = ciphertexts()
    assert rotate_master(db, old, new, actor=TEST) == 2

    for tenant, token in tenants:
        name = "acme" if tenant == tenants[0][0] else "globex"
        assert _read(db, KeyRing(new), tenant, token) == f"{name}@example.com"
        with pytest.raises(CryptoError):
            _read(db, KeyRing(old), tenant, token)
        with db.tenant_session(tenant) as session:
            assert session.scalars(select(TenantKey.provider_key_id)).all() == ["mk_new"]
            last = list_entries(session, tenant, limit=200)[-1]
        assert (last.action, last.outcome) == (
            "key.rotate_master",
            {"from_key_id": "mk_old", "to_key_id": "mk_new"},
        )
    assert ciphertexts() == before  # token rows are not rewritten


def test_rotate_master_is_all_or_nothing(
    db: Database, old: LocalKeyProvider, new: LocalKeyProvider
) -> None:
    first, first_token = _tenant_with_token(db, KeyRing(old), "acme")
    second, second_token = _tenant_with_token(db, KeyRing(old), "globex")

    class FailsOnSecondTenant:
        name, key_id = new.name, new.key_id

        def __init__(self) -> None:
            self.tenants_seen: set[str] = set()

        def is_unlocked(self) -> bool:
            return True

        def unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
            return new.unwrap(wrapped, context)

        def wrap(self, key: bytes, context: Mapping[str, str]) -> bytes:
            self.tenants_seen.add(context["tenant_id"])
            if len(self.tenants_seen) > 1:
                raise RuntimeError("provider outage")
            return new.wrap(key, context)

    with pytest.raises(RuntimeError, match="outage"):
        rotate_master(db, old, FailsOnSecondTenant(), actor=TEST)
    assert _read(db, KeyRing(old), first, first_token) == "acme@example.com"
    assert _read(db, KeyRing(old), second, second_token) == "globex@example.com"


def test_rotate_master_with_the_wrong_old_key_changes_nothing(
    db: Database, old: LocalKeyProvider, new: LocalKeyProvider
) -> None:
    tenant, token = _tenant_with_token(db, KeyRing(old), "acme")
    wrong = LocalKeyProvider(secrets.token_bytes(32), key_id="mk_old")
    with pytest.raises(CryptoError):
        rotate_master(db, wrong, new, actor=TEST)
    assert _read(db, KeyRing(old), tenant, token) == "acme@example.com"
