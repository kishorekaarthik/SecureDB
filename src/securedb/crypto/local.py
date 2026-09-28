"""Key providers backed by a master key held in process memory."""

from collections.abc import Mapping

from securedb.crypto import aead
from securedb.errors import CryptoError, KeyProviderLocked


class LocalKeyProvider:
    """Master key unlocked at startup (from the OS keychain or a passphrase file)."""

    name = "local"

    def __init__(self, master_key: bytes, *, key_id: str) -> None:
        if len(master_key) != aead.KEY_SIZE:
            raise ValueError(f"master key must be {aead.KEY_SIZE} bytes")
        self._master_key = master_key
        self.key_id = key_id

    def __repr__(self) -> str:
        return f"LocalKeyProvider(key_id={self.key_id!r})"

    def is_unlocked(self) -> bool:
        return True

    def wrap(self, key: bytes, context: Mapping[str, str]) -> bytes:
        nonce, ciphertext = aead.encrypt(self._master_key, key, self._aad(context))
        return nonce + ciphertext

    def unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        if len(wrapped) < aead.NONCE_SIZE + aead.TAG_SIZE:
            raise CryptoError()
        nonce, ciphertext = wrapped[: aead.NONCE_SIZE], wrapped[aead.NONCE_SIZE :]
        return aead.decrypt(self._master_key, nonce, ciphertext, self._aad(context))

    def _aad(self, context: Mapping[str, str]) -> bytes:
        return aead.canonical_aad("securedb:wrap", {**context, "master_key_id": self.key_id})


class LockedKeyProvider:
    """Stand-in when the master key could not be unlocked: the app runs but is not ready."""

    name = "locked"
    key_id = "none"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def __repr__(self) -> str:
        return f"LockedKeyProvider(reason={self.reason!r})"

    def is_unlocked(self) -> bool:
        return False

    def wrap(self, key: bytes, context: Mapping[str, str]) -> bytes:
        raise KeyProviderLocked("The key provider is locked.")

    def unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        raise KeyProviderLocked("The key provider is locked.")
