"""Encryption of token values and the keyed lookup hash used for deduplication."""

import hashlib
import hmac
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from securedb.crypto import aead
from securedb.crypto.tenant_keys import KeyRing


@dataclass(frozen=True)
class EncryptedValue:
    ciphertext: bytes
    nonce: bytes
    key_version: int


def token_aad(tenant_id: uuid.UUID, token: str, field_type: str, key_version: int) -> bytes:
    """Binds a ciphertext to its tenant, token, type and key version (spec §2.4)."""
    return aead.canonical_aad(
        "securedb:token",
        {
            "tenant_id": str(tenant_id),
            "token": token,
            "type": field_type,
            "key_version": str(key_version),
        },
    )


class ValueCipher:
    def __init__(self, keyring: KeyRing) -> None:
        self._keyring = keyring

    def encrypt(
        self,
        session: Session,
        tenant_id: uuid.UUID,
        token: str,
        field_type: str,
        plaintext: str,
    ) -> EncryptedValue:
        data_key = self._keyring.active_dek(session, tenant_id)
        nonce, ciphertext = aead.encrypt(
            data_key.key,
            plaintext.encode("utf-8"),
            token_aad(tenant_id, token, field_type, data_key.version),
        )
        return EncryptedValue(ciphertext=ciphertext, nonce=nonce, key_version=data_key.version)

    def decrypt(
        self,
        session: Session,
        tenant_id: uuid.UUID,
        token: str,
        field_type: str,
        value: EncryptedValue,
    ) -> str:
        key = self._keyring.dek(session, tenant_id, value.key_version)
        plaintext = aead.decrypt(
            key,
            value.nonce,
            value.ciphertext,
            token_aad(tenant_id, token, field_type, value.key_version),
        )
        return plaintext.decode("utf-8")

    def lookup_hmac(
        self, session: Session, tenant_id: uuid.UUID, field_type: str, normalized_value: str
    ) -> bytes:
        key = self._keyring.lookup_key(session, tenant_id)
        message = aead.canonical_aad(
            "securedb:lookup", {"type": field_type, "value": normalized_value}
        )
        return hmac.new(key, message, hashlib.sha256).digest()
