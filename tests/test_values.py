import uuid
from dataclasses import replace

import pytest

from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.crypto.values import EncryptedValue, ValueCipher
from securedb.db.session import Database
from securedb.errors import CryptoError
from tests.helpers import create_tenant_with_keys

PAN = "ABCDE1234F"
TOKEN = "tok_pan_abc123"

Setup = tuple[ValueCipher, uuid.UUID, uuid.UUID]


@pytest.fixture
def setup(db: Database, key_provider: LocalKeyProvider) -> Setup:
    keyring = KeyRing(key_provider)
    first = create_tenant_with_keys(db, keyring, "acme")
    second = create_tenant_with_keys(db, keyring, "globex")
    return ValueCipher(keyring), first, second


def _encrypt(
    db: Database, cipher: ValueCipher, tenant_id: uuid.UUID, value: str = PAN
) -> EncryptedValue:
    with db.tenant_session(tenant_id) as session:
        return cipher.encrypt(session, tenant_id, TOKEN, "pan", value)


def test_round_trip(db: Database, setup: Setup) -> None:
    cipher, first, _ = setup
    encrypted = _encrypt(db, cipher, first)
    assert encrypted.key_version == 1
    assert PAN.encode() not in encrypted.ciphertext
    with db.tenant_session(first) as session:
        assert cipher.decrypt(session, first, TOKEN, "pan", encrypted) == PAN


def test_unicode_round_trip(db: Database, setup: Setup) -> None:
    cipher, first, _ = setup
    value = "नमस्ते · Ünïcødé · 🔐"
    encrypted = _encrypt(db, cipher, first, value)
    with db.tenant_session(first) as session:
        assert cipher.decrypt(session, first, TOKEN, "pan", encrypted) == value


def test_ciphertext_is_bound_to_its_token(db: Database, setup: Setup) -> None:
    cipher, first, _ = setup
    encrypted = _encrypt(db, cipher, first)
    with db.tenant_session(first) as session, pytest.raises(CryptoError):
        cipher.decrypt(session, first, "tok_pan_other", "pan", encrypted)


def test_ciphertext_is_bound_to_its_type(db: Database, setup: Setup) -> None:
    cipher, first, _ = setup
    encrypted = _encrypt(db, cipher, first)
    with db.tenant_session(first) as session, pytest.raises(CryptoError):
        cipher.decrypt(session, first, TOKEN, "aadhaar", encrypted)


def test_ciphertext_copied_to_another_tenant_fails(db: Database, setup: Setup) -> None:
    cipher, first, second = setup
    encrypted = _encrypt(db, cipher, first)
    with db.tenant_session(second) as session, pytest.raises(CryptoError):
        cipher.decrypt(session, second, TOKEN, "pan", encrypted)


def test_tampered_ciphertext_fails(db: Database, setup: Setup) -> None:
    cipher, first, _ = setup
    encrypted = _encrypt(db, cipher, first)
    flipped = bytes([encrypted.ciphertext[0] ^ 1]) + encrypted.ciphertext[1:]
    with db.tenant_session(first) as session, pytest.raises(CryptoError):
        cipher.decrypt(session, first, TOKEN, "pan", replace(encrypted, ciphertext=flipped))


def test_lookup_hmac_is_deterministic_per_tenant_and_type(db: Database, setup: Setup) -> None:
    cipher, first, second = setup
    with db.tenant_session(first) as session:
        a1 = cipher.lookup_hmac(session, first, "pan", PAN)
        a2 = cipher.lookup_hmac(session, first, "pan", PAN)
        a_other_type = cipher.lookup_hmac(session, first, "generic", PAN)
        a_other_value = cipher.lookup_hmac(session, first, "pan", "ABCDE1234G")
    with db.tenant_session(second) as session:
        b1 = cipher.lookup_hmac(session, second, "pan", PAN)
    assert a1 == a2
    assert len(a1) == 32
    assert len({a1, a_other_type, a_other_value, b1}) == 4
    assert PAN.encode() not in a1
