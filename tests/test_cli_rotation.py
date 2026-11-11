import json
from collections.abc import Iterator

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from securedb import cli
from securedb.audit.log import Actor
from securedb.config import Settings
from securedb.crypto import master_key as mk
from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.provider import KeyProvider
from securedb.crypto.rotation import rotate_master
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import TenantKey, Token
from securedb.db.session import Database
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import AuthenticatedKey, Scope, issue_api_key
from securedb.tenants.service import create_tenant, find_tenant_id
from securedb.vault.fields import FieldType
from securedb.vault.service import TokenizeItem, TokenService
from tests.helpers import MemoryKeyring

runner = CliRunner()
TEST = Actor.system("test")


@pytest.fixture
def database(settings: Settings, clean_db: None) -> Iterator[Database]:
    database = Database(settings.database_url)
    yield database
    database.dispose()


@pytest.fixture
def keychain_provider(monkeypatch: pytest.MonkeyPatch, database: Database) -> LocalKeyProvider:
    """A real master key in the (in-memory) OS keychain; the CLI loads it like production."""
    mk.init_keychain_master_key()

    def fake_open() -> tuple[Database, KeyProvider]:
        return database, mk.load_keychain_master_key()

    monkeypatch.setattr(cli, "_open", fake_open)
    monkeypatch.setattr(cli, "_master_key_store", lambda: "keychain")
    return mk.load_keychain_master_key()


def _run(*args: str) -> tuple[int, str]:
    result = runner.invoke(cli.app, list(args))
    return result.exit_code, result.output


def _seed(database: Database, provider: KeyProvider) -> tuple[str, str]:
    """Tenant 'acme' with one tokenized email; returns (token, value)."""
    keyring = KeyRing(provider)
    tenant = create_tenant(database, keyring, "acme", actor=TEST)
    with database.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", [Scope.tokenize], actor=TEST)
        for action in (Action.tokenize, Action.detokenize):
            set_policy(
                session, tenant, issued.id, FieldType.email, action, Effect.allow, actor=TEST
            )
    key = AuthenticatedKey(issued.id, tenant, frozenset({"tokenize", "detokenize"}))
    with database.tenant_session(tenant) as session:
        [result] = TokenService(keyring).tokenize(
            session, key, [TokenizeItem(FieldType.email, "a@example.com")]
        )
    return result.token, "a@example.com"


def _decrypts(database: Database, provider: KeyProvider, token: str) -> bool:
    from securedb.crypto.values import EncryptedValue, ValueCipher
    from securedb.errors import CryptoError

    tenant = find_tenant_id(database, "acme")
    with database.tenant_session(tenant) as session:
        row = session.get(Token, token)
        assert row is not None
        try:
            ValueCipher(KeyRing(provider)).decrypt(
                session, tenant, token, row.type,
                EncryptedValue(row.ciphertext, row.nonce, row.key_version),
            )  # fmt: skip
        except CryptoError:
            return False
    return True


def test_rotate_dek_then_reencrypt(database: Database, keychain_provider: LocalKeyProvider) -> None:
    token, _ = _seed(database, keychain_provider)
    code, output = _run("rotate-dek", "--tenant", "acme")
    assert code == 0, output
    assert "v2" in output and "reencrypt" in output
    code, output = _run("reencrypt", "--tenant", "acme", "--batch-size", "10")
    assert code == 0, output
    assert "Re-encrypted 1" in output and "retired versions: 1" in output
    tenant = find_tenant_id(database, "acme")
    with database.tenant_session(tenant) as session:
        assert session.scalars(select(Token.key_version)).all() == [2]
    assert _decrypts(database, keychain_provider, token)


def test_rotate_master_swaps_the_keychain_key(
    database: Database, keychain_provider: LocalKeyProvider, memory_keyring: MemoryKeyring
) -> None:
    token, _ = _seed(database, keychain_provider)
    code, output = _run("rotate-master")
    assert code == 0, output
    new = mk.load_keychain_master_key()
    assert new.key_id != keychain_provider.key_id
    assert keychain_provider.key_id in output and new.key_id in output
    assert "Restart" in output
    assert _decrypts(database, new, token)
    assert not _decrypts(database, keychain_provider, token)
    previous = json.loads(memory_keyring.entries[(mk.KEYCHAIN_SERVICE, mk.PREVIOUS_USERNAME)])
    assert previous["key_id"] == keychain_provider.key_id
    assert (mk.KEYCHAIN_SERVICE, mk.PENDING_USERNAME) not in memory_keyring.entries
    tenant = find_tenant_id(database, "acme")
    with database.tenant_session(tenant) as session:
        assert session.scalars(select(TenantKey.provider_key_id)).all() == [new.key_id]


def test_rotate_master_resumes_after_a_crash_before_promotion(
    database: Database, keychain_provider: LocalKeyProvider
) -> None:
    token, _ = _seed(database, keychain_provider)
    pending = mk.stage_keychain_master_key()
    rotate_master(database, keychain_provider, pending, actor=TEST)  # ...then the process died
    code, output = _run("rotate-master")
    assert code == 0, output
    assert mk.load_keychain_master_key().key_id == pending.key_id
    assert _decrypts(database, pending, token)


def test_rotate_master_without_a_keychain_key_fails_cleanly(
    monkeypatch: pytest.MonkeyPatch, database: Database
) -> None:
    from securedb.crypto.local import LockedKeyProvider

    monkeypatch.setattr(cli, "_open", lambda: (database, LockedKeyProvider("No master key.")))
    code, output = _run("rotate-master")
    assert code == 1
    assert "Error" in output


def test_rotation_commands_need_an_unlocked_vault(
    monkeypatch: pytest.MonkeyPatch, database: Database, keychain_provider: LocalKeyProvider
) -> None:
    from securedb.crypto.local import LockedKeyProvider

    _seed(database, keychain_provider)
    monkeypatch.setattr(cli, "_open", lambda: (database, LockedKeyProvider("locked")))
    for command in (["rotate-dek", "--tenant", "acme"], ["reencrypt", "--tenant", "acme"]):
        code, output = _run(*command)
        assert code == 1 and "locked" in output


def test_rotate_master_refuses_the_file_store(
    monkeypatch: pytest.MonkeyPatch,
    database: Database,
    keychain_provider: LocalKeyProvider,
    memory_keyring: MemoryKeyring,
) -> None:
    _seed(database, keychain_provider)
    monkeypatch.setattr(cli, "_master_key_store", lambda: "file")
    code, output = _run("rotate-master")
    assert code == 1
    assert "file" in output
    assert (mk.KEYCHAIN_SERVICE, mk.PENDING_USERNAME) not in memory_keyring.entries
    assert mk.load_keychain_master_key().key_id == keychain_provider.key_id


def test_rotate_master_after_a_crash_mid_promotion_still_rotates(
    database: Database, keychain_provider: LocalKeyProvider, memory_keyring: MemoryKeyring
) -> None:
    token, _ = _seed(database, keychain_provider)
    # A -> B rotation died after promotion's second write: current == pending == B.
    b = mk.stage_keychain_master_key()
    rotate_master(database, keychain_provider, b, actor=TEST)
    pending_raw = memory_keyring.entries[(mk.KEYCHAIN_SERVICE, mk.PENDING_USERNAME)]
    memory_keyring.entries[(mk.KEYCHAIN_SERVICE, mk.PREVIOUS_USERNAME)] = memory_keyring.entries[
        (mk.KEYCHAIN_SERVICE, mk.KEYCHAIN_USERNAME)
    ]
    memory_keyring.entries[(mk.KEYCHAIN_SERVICE, mk.KEYCHAIN_USERNAME)] = pending_raw

    code, output = _run("rotate-master")
    assert code == 0, output
    c = mk.load_keychain_master_key()
    assert c.key_id not in (keychain_provider.key_id, b.key_id)
    previous = json.loads(memory_keyring.entries[(mk.KEYCHAIN_SERVICE, mk.PREVIOUS_USERNAME)])
    assert previous["key_id"] == b.key_id
    assert f"{b.key_id} -> {c.key_id}" in output
    assert _decrypts(database, c, token)
