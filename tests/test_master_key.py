import base64
import json
import secrets
from pathlib import Path

import keyring
import pytest
from keyring.errors import KeyringError

from securedb.config import Settings
from securedb.crypto import master_key as mk
from securedb.crypto.local import LocalKeyProvider, LockedKeyProvider
from tests.helpers import MemoryKeyring

FAST = mk.KdfParams(time_cost=1, memory_cost=8 * 1024, parallelism=1)
PASSPHRASE = "correct horse battery staple"
CONTEXT = {"purpose": "test"}


def _settings(**overrides: object) -> Settings:
    url = "postgresql+psycopg://u:p@localhost/x_test"
    return Settings(_env_file=None, database_url=url, migration_database_url=url, **overrides)


# --- OS keychain -------------------------------------------------------------


def test_keychain_init_then_load() -> None:
    key_id = mk.init_keychain_master_key()
    assert key_id.startswith("mk_")
    provider = mk.load_keychain_master_key()
    assert isinstance(provider, LocalKeyProvider)
    assert provider.key_id == key_id
    wrapped = provider.wrap(b"k" * 32, CONTEXT)
    assert mk.load_keychain_master_key().unwrap(wrapped, CONTEXT) == b"k" * 32


def test_keychain_init_refuses_to_overwrite() -> None:
    mk.init_keychain_master_key()
    with pytest.raises(mk.MasterKeyError, match="already exists"):
        mk.init_keychain_master_key()


def test_keychain_load_without_key_explains_how_to_fix() -> None:
    with pytest.raises(mk.MasterKeyError, match="securedb init"):
        mk.load_keychain_master_key()


def test_malformed_keychain_entry_is_rejected(memory_keyring: MemoryKeyring) -> None:
    memory_keyring.set_password(mk.KEYCHAIN_SERVICE, mk.KEYCHAIN_USERNAME, "not json")
    with pytest.raises(mk.MasterKeyError, match="malformed"):
        mk.load_keychain_master_key()


class BrokenKeyring(MemoryKeyring):
    def get_password(self, service: str, username: str) -> str | None:
        raise KeyringError("no backend available")


def test_unavailable_keychain_raises_master_key_error() -> None:
    keyring.set_keyring(BrokenKeyring())
    with pytest.raises(mk.MasterKeyError, match="keychain is unavailable"):
        mk.load_keychain_master_key()
    with pytest.raises(mk.MasterKeyError, match="keychain is unavailable"):
        mk.init_keychain_master_key()


# --- Passphrase file ---------------------------------------------------------


def test_file_init_then_load(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    key_id = mk.init_file_master_key(path, PASSPHRASE, FAST)
    provider = mk.load_file_master_key(path, PASSPHRASE)
    assert provider.key_id == key_id
    wrapped = provider.wrap(b"k" * 32, CONTEXT)
    assert mk.load_file_master_key(path, PASSPHRASE).unwrap(wrapped, CONTEXT) == b"k" * 32


def test_file_never_contains_the_master_key_or_passphrase(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE, FAST)
    master = mk.load_file_master_key(path, PASSPHRASE)._master_key
    text = path.read_text(encoding="utf-8")
    assert PASSPHRASE not in text
    assert base64.b64encode(master).decode() not in text
    assert master.hex() not in text


def test_file_records_production_kdf_parameters_by_default(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE)
    kdf = json.loads(path.read_text(encoding="utf-8"))["kdf"]
    assert kdf["name"] == "argon2id"
    assert (kdf["time_cost"], kdf["memory_cost"], kdf["parallelism"]) == (3, 65536, 4)


def test_file_init_refuses_to_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    path.write_text("existing", encoding="utf-8")
    with pytest.raises(mk.MasterKeyError, match="already exists"):
        mk.init_file_master_key(path, PASSPHRASE, FAST)
    assert path.read_text(encoding="utf-8") == "existing"


@pytest.mark.parametrize("passphrase", ["", "short", "elevenchars"])
def test_short_passphrase_is_rejected(tmp_path: Path, passphrase: str) -> None:
    path = tmp_path / "master.key"
    with pytest.raises(mk.MasterKeyError, match="at least 12"):
        mk.init_file_master_key(path, passphrase, FAST)
    assert not path.exists()


def test_wrong_passphrase_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE, FAST)
    with pytest.raises(mk.MasterKeyError, match="Wrong passphrase"):
        mk.load_file_master_key(path, "not the passphrase")


def _random_like(b64: str) -> str:
    return base64.b64encode(secrets.token_bytes(len(base64.b64decode(b64)))).decode()


@pytest.mark.parametrize("field", ["key_id", "salt", "time_cost", "nonce", "ciphertext"])
def test_tampered_file_fails_closed(tmp_path: Path, field: str) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE, FAST)
    doc = json.loads(path.read_text(encoding="utf-8"))
    if field == "key_id":
        doc["key_id"] = "mk_forged"
    elif field == "salt":
        doc["kdf"]["salt"] = _random_like(doc["kdf"]["salt"])
    elif field == "time_cost":
        doc["kdf"]["time_cost"] += 1
    else:
        doc[field] = _random_like(doc[field])
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(mk.MasterKeyError) as exc_info:
        mk.load_file_master_key(path, PASSPHRASE)
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    "content", ["", "{}", "[]", "not json", '{"format": "other", "version": 1}']
)
def test_malformed_file_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "master.key"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(mk.MasterKeyError, match="malformed"):
        mk.load_file_master_key(path, PASSPHRASE)


def test_missing_file_explains_how_to_fix(tmp_path: Path) -> None:
    with pytest.raises(mk.MasterKeyError, match="securedb init --store file"):
        mk.load_file_master_key(tmp_path / "absent.key", PASSPHRASE)


def test_master_key_error_never_contains_the_passphrase(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE, FAST)
    with pytest.raises(mk.MasterKeyError) as exc_info:
        mk.load_file_master_key(path, "a-wrong-passphrase-value")
    assert "a-wrong-passphrase-value" not in str(exc_info.value)


# --- load_key_provider -------------------------------------------------------


def test_load_key_provider_uses_keychain_by_default() -> None:
    key_id = mk.init_keychain_master_key()
    provider = mk.load_key_provider(_settings())
    assert provider.is_unlocked()
    assert provider.key_id == key_id


def test_load_key_provider_uses_file_store(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    key_id = mk.init_file_master_key(path, PASSPHRASE, FAST)
    provider = mk.load_key_provider(
        _settings(master_key_store="file", master_key_file=path, master_key_passphrase=PASSPHRASE)
    )
    assert provider.is_unlocked()
    assert provider.key_id == key_id


def test_missing_keychain_key_gives_locked_provider() -> None:
    provider = mk.load_key_provider(_settings())
    assert isinstance(provider, LockedKeyProvider)
    assert "securedb init" in provider.reason


def test_file_store_without_passphrase_gives_locked_provider(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE, FAST)
    provider = mk.load_key_provider(_settings(master_key_store="file", master_key_file=path))
    assert isinstance(provider, LockedKeyProvider)
    assert "SECUREDB_MASTER_KEY_PASSPHRASE" in provider.reason


def test_file_store_with_wrong_passphrase_gives_locked_provider(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE, FAST)
    provider = mk.load_key_provider(
        _settings(
            master_key_store="file", master_key_file=path, master_key_passphrase="wrong but long"
        )
    )
    assert isinstance(provider, LockedKeyProvider)


def test_unavailable_keychain_gives_locked_provider() -> None:
    keyring.set_keyring(BrokenKeyring())
    provider = mk.load_key_provider(_settings())
    assert isinstance(provider, LockedKeyProvider)
    assert "keychain" in provider.reason


@pytest.mark.parametrize(
    ("param", "value"),
    [
        ("time_cost", -1),
        ("time_cost", 0),
        ("time_cost", 2**33),
        ("time_cost", 4_000_000_000),
        ("time_cost", 2.5),
        ("time_cost", True),
        ("memory_cost", float("inf")),
        ("memory_cost", 2**40),
        ("memory_cost", 4),
        ("parallelism", -5),
        ("parallelism", 0),
        ("parallelism", 1024),
    ],
)
def test_out_of_range_kdf_parameters_are_rejected_without_running_the_kdf(
    tmp_path: Path, param: str, value: object
) -> None:
    path = tmp_path / "master.key"
    mk.init_file_master_key(path, PASSPHRASE, FAST)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["kdf"][param] = value
    path.write_text(json.dumps(doc), encoding="utf-8")  # inf is written as Infinity
    with pytest.raises(mk.MasterKeyError, match="malformed"):
        mk.load_file_master_key(path, PASSPHRASE)


def test_unreadable_key_file_raises_master_key_error(tmp_path: Path) -> None:
    directory = tmp_path / "not-a-file.key"
    directory.mkdir()
    with pytest.raises(mk.MasterKeyError, match="Cannot read"):
        mk.load_file_master_key(directory, PASSPHRASE)


def test_unreadable_key_file_gives_locked_provider(tmp_path: Path) -> None:
    directory = tmp_path / "not-a-file.key"
    directory.mkdir()
    provider = mk.load_key_provider(
        _settings(
            master_key_store="file", master_key_file=directory, master_key_passphrase=PASSPHRASE
        )
    )
    assert isinstance(provider, LockedKeyProvider)


class ExplodingKeyring(MemoryKeyring):
    def get_password(self, service: str, username: str) -> str | None:
        raise RuntimeError("backend bug with secret-ish detail")


def test_unexpected_keychain_errors_give_locked_provider_without_details() -> None:
    keyring.set_keyring(ExplodingKeyring())
    provider = mk.load_key_provider(_settings())
    assert isinstance(provider, LockedKeyProvider)
    assert provider.reason == "The master key could not be loaded."
