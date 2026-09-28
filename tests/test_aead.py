import pytest
from hypothesis import given
from hypothesis import strategies as st

from securedb.crypto import aead
from securedb.errors import CryptoError

KEY = bytes(range(32))
AAD = aead.canonical_aad("test", {"tenant_id": "t1"})
PLAINTEXT = b"ABCDE1234F"


def _flip(data: bytes, index: int = 0) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def test_round_trip() -> None:
    nonce, ciphertext = aead.encrypt(KEY, PLAINTEXT, AAD)
    assert aead.decrypt(KEY, nonce, ciphertext, AAD) == PLAINTEXT


def test_fresh_nonce_per_encryption_and_plaintext_hidden() -> None:
    nonce1, ct1 = aead.encrypt(KEY, PLAINTEXT, AAD)
    nonce2, ct2 = aead.encrypt(KEY, PLAINTEXT, AAD)
    assert len(nonce1) == aead.NONCE_SIZE
    assert nonce1 != nonce2
    assert ct1 != ct2
    assert PLAINTEXT not in ct1
    assert len(ct1) == len(PLAINTEXT) + aead.TAG_SIZE


@pytest.mark.parametrize("part", ["nonce", "ciphertext", "tag", "aad", "key"])
def test_any_tampering_is_rejected(part: str) -> None:
    nonce, ciphertext = aead.encrypt(KEY, PLAINTEXT, AAD)
    key, aad = KEY, AAD
    if part == "nonce":
        nonce = _flip(nonce)
    elif part == "ciphertext":
        ciphertext = _flip(ciphertext, 0)
    elif part == "tag":
        ciphertext = _flip(ciphertext, len(ciphertext) - 1)
    elif part == "aad":
        aad = aead.canonical_aad("test", {"tenant_id": "t2"})
    else:
        key = _flip(KEY)
    with pytest.raises(CryptoError):
        aead.decrypt(key, nonce, ciphertext, aad)


def test_wrong_length_nonce_is_rejected() -> None:
    nonce, ciphertext = aead.encrypt(KEY, PLAINTEXT, AAD)
    with pytest.raises(CryptoError):
        aead.decrypt(KEY, nonce[:-1], ciphertext, AAD)


def test_truncated_ciphertext_is_rejected() -> None:
    nonce, _ = aead.encrypt(KEY, PLAINTEXT, AAD)
    with pytest.raises(CryptoError):
        aead.decrypt(KEY, nonce, b"short", AAD)


@pytest.mark.parametrize("bad_key", [b"", b"x" * 16, b"x" * 31, b"x" * 33])
def test_only_256_bit_keys_are_accepted(bad_key: bytes) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        aead.encrypt(bad_key, PLAINTEXT, AAD)
    with pytest.raises(ValueError, match="32 bytes"):
        aead.decrypt(bad_key, bytes(12), bytes(32), AAD)


def test_crypto_error_is_generic_and_has_no_cause() -> None:
    nonce, ciphertext = aead.encrypt(KEY, PLAINTEXT, AAD)
    with pytest.raises(CryptoError) as exc_info:
        aead.decrypt(_flip(KEY), nonce, ciphertext, AAD)
    assert str(exc_info.value) == "Internal Server Error"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True


def test_canonical_aad_is_order_independent_and_unambiguous() -> None:
    assert aead.canonical_aad("x", {"a": "1", "b": "2"}) == aead.canonical_aad(
        "x", {"b": "2", "a": "1"}
    )
    assert aead.canonical_aad("x", {"a": "1|b"}) != aead.canonical_aad("x", {"a": "1", "b": ""})
    assert aead.canonical_aad("x", {"a": "1"}) != aead.canonical_aad("y", {"a": "1"})
    assert aead.canonical_aad("x", {"label": "y"}) != aead.canonical_aad("y", {})


@given(
    plaintext=st.binary(max_size=4096),
    context=st.dictionaries(st.text(max_size=20), st.text(max_size=40), max_size=5),
)
def test_round_trip_property(plaintext: bytes, context: dict[str, str]) -> None:
    aad = aead.canonical_aad("prop", context)
    nonce, ciphertext = aead.encrypt(KEY, plaintext, aad)
    assert aead.decrypt(KEY, nonce, ciphertext, aad) == plaintext
