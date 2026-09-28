"""AES-256-GCM authenticated encryption. The only module that calls AES directly."""

import json
import os
from collections.abc import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securedb.errors import CryptoError

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def canonical_aad(label: str, fields: Mapping[str, str]) -> bytes:
    """Deterministic, unambiguous encoding of the context bound into a ciphertext."""
    return json.dumps(
        [label, sorted(fields.items())], separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 keys must be {KEY_SIZE} bytes")


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext_with_tag). A fresh random nonce is used every call."""
    _check_key(key)
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    _check_key(key)
    if len(nonce) != NONCE_SIZE:
        raise CryptoError()
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise CryptoError() from None
