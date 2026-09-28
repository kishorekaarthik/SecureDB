"""Master key storage: the OS keychain, or a file encrypted under an Argon2id passphrase."""

import base64
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import keyring
import structlog
from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw
from keyring.errors import KeyringError

from securedb.config import Settings
from securedb.crypto import aead
from securedb.crypto.local import LocalKeyProvider, LockedKeyProvider
from securedb.crypto.provider import KeyProvider
from securedb.errors import CryptoError

KEYCHAIN_SERVICE = "securedb-vault"
KEYCHAIN_USERNAME = "master-key"
FILE_FORMAT = "securedb-master-key"
MIN_PASSPHRASE_LENGTH = 12
# Upper bounds accepted when reading a key file (defaults are 3 / 64 MiB / 4).
MAX_TIME_COST = 10
MAX_MEMORY_COST = 1_048_576  # KiB (1 GiB)
MAX_PARALLELISM = 16

log = structlog.get_logger(__name__)


class MasterKeyError(Exception):
    """A master key could not be created or unlocked. Messages are safe to show."""


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_cost: int = 65536  # KiB (64 MiB)
    parallelism: int = 4


def new_key_id() -> str:
    return f"mk_{secrets.token_hex(8)}"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: Any) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64 text")
    return base64.b64decode(text, validate=True)


# --- OS keychain -------------------------------------------------------------


def init_keychain_master_key() -> str:
    try:
        if keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME) is not None:
            raise MasterKeyError(
                "A master key already exists in the OS keychain; refusing to overwrite it."
            )
        key_id = new_key_id()
        entry = {"key_id": key_id, "key": _b64e(secrets.token_bytes(aead.KEY_SIZE))}
        keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME, json.dumps(entry))
    except KeyringError:
        raise MasterKeyError("The OS keychain is unavailable.") from None
    return key_id


def load_keychain_master_key() -> LocalKeyProvider:
    try:
        raw = keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME)
    except KeyringError:
        raise MasterKeyError("The OS keychain is unavailable.") from None
    if raw is None:
        raise MasterKeyError("No master key in the OS keychain. Run `securedb init`.")
    try:
        entry = json.loads(raw)
        return LocalKeyProvider(_b64d(entry["key"]), key_id=str(entry["key_id"]))
    except (ValueError, KeyError, TypeError):
        raise MasterKeyError("The OS keychain entry for the master key is malformed.") from None


# --- Passphrase file ---------------------------------------------------------


def _derive_kek(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=aead.KEY_SIZE,
        type=Type.ID,
    )


def _file_aad(key_id: str) -> bytes:
    return aead.canonical_aad("securedb:master-key-file", {"key_id": key_id})


def init_file_master_key(path: Path, passphrase: str, params: KdfParams | None = None) -> str:
    params = params or KdfParams()
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise MasterKeyError(f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters.")
    master_key = secrets.token_bytes(aead.KEY_SIZE)
    key_id = new_key_id()
    salt = secrets.token_bytes(16)
    nonce, ciphertext = aead.encrypt(
        _derive_kek(passphrase, salt, params), master_key, _file_aad(key_id)
    )
    doc = {
        "format": FILE_FORMAT,
        "version": 1,
        "key_id": key_id,
        "kdf": {
            "name": "argon2id",
            "salt": _b64e(salt),
            "time_cost": params.time_cost,
            "memory_cost": params.memory_cost,
            "parallelism": params.parallelism,
        },
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }
    try:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=2)
    except FileExistsError:
        raise MasterKeyError(f"{path} already exists; refusing to overwrite it.") from None
    return key_id


def _bounded_int(value: Any, low: int, high: int) -> int:
    # type() check rejects bool (an int subclass) and floats such as Infinity.
    if type(value) is not int or not low <= value <= high:
        raise ValueError("KDF parameter out of range")
    return value


def _read_key_file(path: Path) -> tuple[str, bytes, KdfParams, bytes, bytes]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:  # a directory, no permission, unreadable share, ...
        raise MasterKeyError(f"Cannot read master key file {path}.") from None
    try:
        doc = json.loads(raw)
        if doc.get("format") != FILE_FORMAT or doc.get("version") != 1:
            raise ValueError("unknown format")
        kdf = doc["kdf"]
        if kdf["name"] != "argon2id":
            raise ValueError("unknown kdf")
        # The file is attacker-writable input: bound the costs before running the KDF,
        # so a tampered file cannot crash (OverflowError) or hang/OOM startup.
        parallelism = _bounded_int(kdf["parallelism"], 1, MAX_PARALLELISM)
        params = KdfParams(
            time_cost=_bounded_int(kdf["time_cost"], 1, MAX_TIME_COST),
            memory_cost=_bounded_int(kdf["memory_cost"], 8 * parallelism, MAX_MEMORY_COST),
            parallelism=parallelism,
        )
        return (
            str(doc["key_id"]),
            _b64d(kdf["salt"]),
            params,
            _b64d(doc["nonce"]),
            _b64d(doc["ciphertext"]),
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        raise MasterKeyError("Master key file is malformed.") from None


def load_file_master_key(path: Path, passphrase: str) -> LocalKeyProvider:
    if not path.exists():
        raise MasterKeyError(f"Master key file {path} not found. Run `securedb init --store file`.")
    key_id, salt, params, nonce, ciphertext = _read_key_file(path)
    try:
        kek = _derive_kek(passphrase, salt, params)
        master_key = aead.decrypt(kek, nonce, ciphertext, _file_aad(key_id))
    except (CryptoError, HashingError, ValueError):
        raise MasterKeyError("Wrong passphrase or tampered master key file.") from None
    return LocalKeyProvider(master_key, key_id=key_id)


# --- Startup -----------------------------------------------------------------


def load_key_provider(settings: Settings) -> KeyProvider:
    """Unlock the configured master key, or return a locked provider explaining why."""
    try:
        if settings.master_key_store == "keychain":
            return load_keychain_master_key()
        if settings.master_key_passphrase is None:
            raise MasterKeyError("SECUREDB_MASTER_KEY_PASSPHRASE is not set.")
        return load_file_master_key(
            settings.master_key_file, settings.master_key_passphrase.get_secret_value()
        )
    except MasterKeyError as exc:
        log.warning("key_provider_locked", reason=str(exc))
        return LockedKeyProvider(str(exc))
    except Exception as exc:
        # Fail closed on anything unexpected (e.g. a keyring backend bug): start locked,
        # and log only the error type since the message could contain sensitive detail.
        log.error("key_provider_load_failed", error_type=type(exc).__name__)
        return LockedKeyProvider("The master key could not be loaded.")
