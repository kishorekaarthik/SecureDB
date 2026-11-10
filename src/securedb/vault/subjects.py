"""DPDP data-subject rights: erasure and export (spec §2.6).

A value can belong to several subjects (a shared phone number, a joint account), so
erasure removes the subject's links and deletes a token only when nobody else is linked.
Audit entries identify the subject by a keyed reference (HMAC under the tenant's lookup
key), never by the raw subject ID.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from securedb.audit.log import Actor, append
from securedb.crypto.tenant_keys import KeyRing
from securedb.crypto.values import EncryptedValue, ValueCipher
from securedb.db.models import AuditLog, Token, TokenSubject
from securedb.policy.engine import Action, Effect, effects_for
from securedb.tenants.api_keys import AuthenticatedKey
from securedb.vault.fields import FieldType, Output, mask, to_output

HISTORY_LIMIT = 1000


@dataclass(frozen=True)
class ErasureResult:
    deleted_tokens: list[str]
    retained_shared: int


@dataclass(frozen=True)
class ExportedToken:
    token: str
    type: str
    created_at: datetime
    shared: bool
    value: Output | None = field(default=None, repr=False)
    masked: bool = False


@dataclass(frozen=True)
class HistoryEntry:
    seq: int
    ts: datetime
    action: str
    actor_type: str
    actor_id: str


@dataclass(frozen=True)
class SubjectExport:
    subject_ref: str
    tokens: list[ExportedToken]
    history: list[HistoryEntry]


class SubjectService:
    """Every method expects a session from ``Database.tenant_session(key.tenant_id)``."""

    def __init__(self, keyring: KeyRing) -> None:
        self._cipher = ValueCipher(keyring)

    def subject_ref(self, session: Session, tenant_id: uuid.UUID, subject_id: str) -> str:
        """Stable, keyed, non-reversible reference to a subject for audit entries."""
        return self._cipher.lookup_hmac(session, tenant_id, "subject", subject_id).hex()

    def _subject_tokens(self, session: Session, subject_id: str, *, lock: bool) -> list[str]:
        query = (
            select(Token.token)
            .join(TokenSubject, TokenSubject.token == Token.token)
            .where(TokenSubject.subject_id == subject_id)
            .order_by(Token.token)
        )
        if lock:  # block concurrent links to these tokens while we decide what to delete
            query = query.with_for_update(of=Token)
        return list(session.scalars(query).all())

    def erase(self, session: Session, key: AuthenticatedKey, subject_id: str) -> ErasureResult:
        tenant_id = key.tenant_id
        tokens = self._subject_tokens(session, subject_id, lock=True)
        session.execute(delete(TokenSubject).where(TokenSubject.subject_id == subject_id))
        still_linked = set(
            session.scalars(
                select(TokenSubject.token).where(TokenSubject.token.in_(tokens)).distinct()
            ).all()
        )
        doomed = [token for token in tokens if token not in still_linked]
        if doomed:
            session.execute(delete(Token).where(Token.token.in_(doomed)))
        result = ErasureResult(deleted_tokens=doomed, retained_shared=len(tokens) - len(doomed))
        append(
            session,
            tenant_id,
            Actor.api_key(key.id),
            "subject.erase",
            token_ids=doomed,
            outcome={
                "subject_ref": self.subject_ref(session, tenant_id, subject_id),
                "deleted": len(doomed),
                "retained_shared": result.retained_shared,
            },
        )
        return result

    def export(self, session: Session, key: AuthenticatedKey, subject_id: str) -> SubjectExport:
        tenant_id = key.tenant_id
        token_ids = self._subject_tokens(session, subject_id, lock=False)
        rows = session.scalars(select(Token).where(Token.token.in_(token_ids))).all()
        owners: dict[str, int] = {
            token: count
            for token, count in session.execute(
                select(TokenSubject.token, func.count())
                .where(TokenSubject.token.in_(token_ids))
                .group_by(TokenSubject.token)
            ).all()
        }
        effects = effects_for(session, key.id, Action.detokenize)
        exported: list[ExportedToken] = []
        for row in sorted(rows, key=lambda r: r.token):
            field_type = FieldType(row.type)
            effect = effects.get(field_type, Effect.deny)
            value: Output | None = None
            if effect is not Effect.deny:
                plain = self._cipher.decrypt(
                    session,
                    tenant_id,
                    row.token,
                    row.type,
                    EncryptedValue(row.ciphertext, row.nonce, row.key_version),
                )
                value = (
                    mask(field_type, plain)
                    if effect is Effect.mask
                    else to_output(field_type, plain)
                )
            exported.append(
                ExportedToken(
                    token=row.token,
                    type=row.type,
                    created_at=row.created_at,
                    shared=owners.get(row.token, 0) > 1,
                    value=value,
                    masked=effect is Effect.mask,
                )
            )
        history = (
            [
                HistoryEntry(entry.seq, entry.ts, entry.action, entry.actor_type, entry.actor_id)
                for entry in session.scalars(
                    select(AuditLog)
                    .where(AuditLog.tenant_id == tenant_id, AuditLog.token_ids.overlap(token_ids))
                    .order_by(AuditLog.seq)
                    .limit(HISTORY_LIMIT)
                )
            ]
            if token_ids
            else []
        )
        reference = self.subject_ref(session, tenant_id, subject_id)
        append(
            session,
            tenant_id,
            Actor.api_key(key.id),
            "subject.export",
            token_ids=token_ids,
            outcome={"subject_ref": reference, "tokens": len(token_ids)},
        )
        return SubjectExport(subject_ref=reference, tokens=exported, history=history)
