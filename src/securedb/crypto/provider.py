"""The interface every master-key holder implements (local now, AWS KMS later)."""

from collections.abc import Mapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class KeyProvider(Protocol):
    """Wraps and unwraps data keys with a master key it never reveals.

    `context` is bound to the wrapped key: unwrapping with a different context fails.
    """

    @property
    def name(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    def is_unlocked(self) -> bool: ...

    def wrap(self, key: bytes, context: Mapping[str, str]) -> bytes: ...

    def unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes: ...
