"""Tokenize, detokenize and delete values (spec §2.6).

Every method expects a session from ``Database.tenant_session(key.tenant_id)``.
"""

import secrets
import string
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from securedb.crypto.tenant_keys import KeyRing
from securedb.crypto.values import EncryptedValue, ValueCipher
from securedb.db.models import Token
from securedb.errors import Forbidden, NotFound, UnprocessableEntity
from securedb.policy.engine import Action, Effect, effects_for
from securedb.tenants.api_keys import AuthenticatedKey
from securedb.vault.fields import (
    FieldType,
    FieldValidationError,
    Output,
    mask,
    normalize,
    to_output,
)

NOT_AVAILABLE = "not_available"
TOKEN_RANDOM_LENGTH = 22  # ~131 bits of base62
_ALPHABET = string.ascii_letters + string.digits


@dataclass(frozen=True)
class TokenizeItem:
    type: FieldType
    value: Any = field(repr=False)
    subject_id: str | None = None


@dataclass(frozen=True)
class TokenizeResult:
    token: str
    type: FieldType
    created: bool


@dataclass(frozen=True)
class DetokenizeResult:
    token: str
    value: Output | None = field(default=None, repr=False)
    masked: bool = False
    error: str | None = None


def new_token(field_type: FieldType) -> str:
    """A random, meaningless token: tok_<type>_<22 base62 characters>."""
    suffix = "".join(secrets.choice(_ALPHABET) for _ in range(TOKEN_RANDOM_LENGTH))
    return f"tok_{field_type.value}_{suffix}"


class TokenService:
    def __init__(self, keyring: KeyRing) -> None:
        self._cipher = ValueCipher(keyring)

    def tokenize(
        self, session: Session, key: AuthenticatedKey, items: Sequence[TokenizeItem]
    ) -> list[TokenizeResult]:
        """All items are checked before anything is written; any failure rejects the batch."""
        allowed = effects_for(session, key.id, Action.tokenize)
        denied = sorted({item.type.value for item in items} - {t.value for t in allowed})
        if denied:
            raise Forbidden(f"This API key may not tokenize: {', '.join(denied)}.")

        normalized: list[str] = []
        problems: list[str] = []
        for index, item in enumerate(items):
            try:
                normalized.append(normalize(item.type, item.value))
            except FieldValidationError as exc:
                problems.append(f"items[{index}]: {exc}")
        if problems:
            raise UnprocessableEntity("; ".join(problems))

        return [
            self._tokenize_one(session, key.tenant_id, item, value)
            for item, value in zip(items, normalized, strict=True)
        ]

    def _tokenize_one(
        self, session: Session, tenant_id: uuid.UUID, item: TokenizeItem, value: str
    ) -> TokenizeResult:
        lookup = self._cipher.lookup_hmac(session, tenant_id, item.type.value, value)
        existing = self._find(session, tenant_id, item.type, lookup)
        if existing is not None:
            return TokenizeResult(existing, item.type, created=False)

        token = new_token(item.type)
        encrypted = self._cipher.encrypt(session, tenant_id, token, item.type.value, value)
        inserted = session.scalar(
            insert(Token)
            .values(
                token=token,
                tenant_id=tenant_id,
                type=item.type.value,
                subject_id=item.subject_id,
                lookup_hmac=lookup,
                ciphertext=encrypted.ciphertext,
                nonce=encrypted.nonce,
                key_version=encrypted.key_version,
            )
            .on_conflict_do_nothing(constraint="uq_tokens_dedup")
            .returning(Token.token)
        )
        if inserted is not None:
            return TokenizeResult(inserted, item.type, created=True)
        # Lost a race with a concurrent request for the same value: use its token.
        winner = self._find(session, tenant_id, item.type, lookup)
        if winner is None:  # pragma: no cover - the conflicting row must be visible
            raise NotFound("Token not found.")
        return TokenizeResult(winner, item.type, created=False)

    @staticmethod
    def _find(
        session: Session, tenant_id: uuid.UUID, field_type: FieldType, lookup: bytes
    ) -> str | None:
        return session.scalar(
            select(Token.token).where(
                Token.tenant_id == tenant_id,
                Token.type == field_type.value,
                Token.lookup_hmac == lookup,
            )
        )

    def detokenize(
        self, session: Session, key: AuthenticatedKey, tokens: Sequence[str]
    ) -> list[DetokenizeResult]:
        """Per-token results; denied and unknown tokens are indistinguishable."""
        effects = effects_for(session, key.id, Action.detokenize)
        rows = {
            row.token: row
            for row in session.scalars(select(Token).where(Token.token.in_(set(tokens))))
        }
        results: list[DetokenizeResult] = []
        for token in tokens:
            row = rows.get(token)
            effect = effects.get(FieldType(row.type), Effect.deny) if row else Effect.deny
            if row is None or effect is Effect.deny:
                results.append(DetokenizeResult(token, error=NOT_AVAILABLE))
                continue
            field_type = FieldType(row.type)
            value = self._cipher.decrypt(
                session,
                key.tenant_id,
                row.token,
                row.type,
                EncryptedValue(row.ciphertext, row.nonce, row.key_version),
            )
            if effect is Effect.mask:
                results.append(DetokenizeResult(token, mask(field_type, value), masked=True))
            else:
                results.append(DetokenizeResult(token, to_output(field_type, value)))
        return results

    def delete_token(self, session: Session, token: str) -> None:
        result = session.execute(delete(Token).where(Token.token == token))
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise NotFound("Token not found.")
