import secrets

import pytest

from securedb.crypto.local import LocalKeyProvider, LockedKeyProvider
from securedb.crypto.provider import KeyProvider
from securedb.errors import CryptoError, KeyProviderLocked

CONTEXT = {"purpose": "dek", "tenant_id": "t1", "version": "1"}


def test_wrap_round_trip(key_provider: LocalKeyProvider) -> None:
    dek = secrets.token_bytes(32)
    wrapped = key_provider.wrap(dek, CONTEXT)
    assert dek not in wrapped
    assert key_provider.unwrap(wrapped, CONTEXT) == dek


def test_unwrap_with_different_context_fails(key_provider: LocalKeyProvider) -> None:
    wrapped = key_provider.wrap(secrets.token_bytes(32), CONTEXT)
    with pytest.raises(CryptoError):
        key_provider.unwrap(wrapped, {**CONTEXT, "tenant_id": "t2"})


def test_unwrap_with_different_master_key_fails(key_provider: LocalKeyProvider) -> None:
    wrapped = key_provider.wrap(secrets.token_bytes(32), CONTEXT)
    other = LocalKeyProvider(secrets.token_bytes(32), key_id="mk_test")
    with pytest.raises(CryptoError):
        other.unwrap(wrapped, CONTEXT)


def test_master_key_id_is_bound_into_wrapped_keys() -> None:
    master = secrets.token_bytes(32)
    first = LocalKeyProvider(master, key_id="mk_a")
    second = LocalKeyProvider(master, key_id="mk_b")
    with pytest.raises(CryptoError):
        second.unwrap(first.wrap(secrets.token_bytes(32), CONTEXT), CONTEXT)


@pytest.mark.parametrize("wrapped", [b"", b"short", bytes(27), bytes(28)])
def test_malformed_wrapped_keys_fail_closed(key_provider: LocalKeyProvider, wrapped: bytes) -> None:
    with pytest.raises(CryptoError):
        key_provider.unwrap(wrapped, CONTEXT)


def test_master_key_must_be_256_bits() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        LocalKeyProvider(b"x" * 16, key_id="mk_short")


def test_repr_never_contains_key_material() -> None:
    master = secrets.token_bytes(32)
    text = repr(LocalKeyProvider(master, key_id="mk_test"))
    assert text == "LocalKeyProvider(key_id='mk_test')"
    assert master.hex() not in text


def test_local_provider_satisfies_protocol(key_provider: LocalKeyProvider) -> None:
    assert isinstance(key_provider, KeyProvider)
    assert key_provider.name == "local"
    assert key_provider.key_id == "mk_test"
    assert key_provider.is_unlocked() is True


def test_locked_provider_refuses_all_operations() -> None:
    locked = LockedKeyProvider("No master key in the OS keychain.")
    assert isinstance(locked, KeyProvider)
    assert locked.is_unlocked() is False
    assert locked.reason == "No master key in the OS keychain."
    with pytest.raises(KeyProviderLocked, match="locked"):
        locked.wrap(bytes(32), CONTEXT)
    with pytest.raises(KeyProviderLocked, match="locked"):
        locked.unwrap(bytes(40), CONTEXT)
