"""Per-tenant hash-chained audit log (spec §2.7).

Each entry's hash is SHA-256(prev_hash || canonical_json(entry)); the first entry chains
from 32 zero bytes. Appends serialise per tenant with a transaction-scoped advisory lock,
and the application role can only INSERT and SELECT, so history cannot be rewritten by
the app. ``verify`` recomputes the chain and reports the first broken sequence number.

Known limit: deleting the *newest* entries leaves a shorter but valid chain. Operators
should record ``head_hash`` externally (e.g. daily) to detect truncation.
"""

import hashlib
import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from securedb.db.models import AuditLog

GENESIS_HASH = bytes(32)


@dataclass(frozen=True)
class Actor:
    type: str
    id: str

    @classmethod
    def api_key(cls, key_id: uuid.UUID) -> "Actor":
        return cls("api_key", str(key_id))

    @classmethod
    def console_user(cls, user_id: uuid.UUID) -> "Actor":
        return cls("console_user", str(user_id))

    @classmethod
    def system(cls, name: str) -> "Actor":
        return cls("system", name)


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: datetime
    actor_type: str
    actor_id: str
    action: str
    token_ids: list[str]
    outcome: dict[str, Any]
    request_id: str | None
    prev_hash: bytes
    hash: bytes


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    head_hash: str | None
    first_broken_seq: int | None


def _lock_key(tenant_id: uuid.UUID) -> int:
    return int.from_bytes(tenant_id.bytes[:8], "big", signed=True)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat(timespec="microseconds")


def canonical_entry(tenant_id: uuid.UUID, record: AuditRecord) -> bytes:
    """The exact bytes that are hashed for an entry (everything except the hashes)."""
    entry = {
        "tenant_id": str(tenant_id),
        "seq": record.seq,
        "ts": _iso(record.ts),
        "actor_type": record.actor_type,
        "actor_id": record.actor_id,
        "action": record.action,
        "token_ids": list(record.token_ids),
        "outcome": record.outcome,
        "request_id": record.request_id,
    }
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _chain(prev_hash: bytes, tenant_id: uuid.UUID, record: AuditRecord) -> bytes:
    return hashlib.sha256(prev_hash + canonical_entry(tenant_id, record)).digest()


def _record(row: AuditLog) -> AuditRecord:
    return AuditRecord(
        seq=row.seq,
        ts=row.ts,
        actor_type=row.actor_type,
        actor_id=row.actor_id,
        action=row.action,
        token_ids=list(row.token_ids),
        outcome=dict(row.outcome),
        request_id=row.request_id,
        prev_hash=bytes(row.prev_hash),
        hash=bytes(row.hash),
    )


def append(
    session: Session,
    tenant_id: uuid.UUID,
    actor: Actor,
    action: str,
    *,
    token_ids: Iterable[str] = (),
    outcome: dict[str, Any] | None = None,
) -> AuditRecord:
    """Append one entry in the caller's transaction (it commits or rolls back with it)."""
    outcome = outcome or {}
    json.dumps(outcome)  # TypeError for anything that is not plain JSON data
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _lock_key(tenant_id)})
    head = session.execute(
        select(AuditLog.seq, AuditLog.hash)
        .where(AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.seq.desc())
        .limit(1)
    ).one_or_none()
    seq = head.seq + 1 if head else 1
    prev_hash = bytes(head.hash) if head else GENESIS_HASH
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    draft = AuditRecord(
        seq=seq,
        ts=datetime.now(UTC),
        actor_type=actor.type,
        actor_id=actor.id,
        action=action,
        token_ids=list(token_ids),
        outcome=outcome,
        request_id=request_id if isinstance(request_id, str) else None,
        prev_hash=prev_hash,
        hash=b"",
    )
    record = AuditRecord(**{**draft.__dict__, "hash": _chain(prev_hash, tenant_id, draft)})
    session.add(
        AuditLog(
            tenant_id=tenant_id,
            seq=record.seq,
            ts=record.ts,
            actor_type=record.actor_type,
            actor_id=record.actor_id,
            action=record.action,
            token_ids=record.token_ids,
            outcome=record.outcome,
            request_id=record.request_id,
            prev_hash=record.prev_hash,
            hash=record.hash,
        )
    )
    session.flush()
    return record


def verify(session: Session, tenant_id: uuid.UUID) -> VerifyResult:
    """Recompute the whole chain; report the first sequence number that does not check out."""
    expected_seq, prev_hash, count = 1, GENESIS_HASH, 0
    rows = session.scalars(
        select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.seq)
    ).yield_per(1000)
    for row in rows:
        record = _record(row)
        if (
            record.seq != expected_seq
            or record.prev_hash != prev_hash
            or record.hash != _chain(prev_hash, tenant_id, record)
        ):
            return VerifyResult(False, count, prev_hash.hex() if count else None, expected_seq)
        prev_hash, expected_seq, count = record.hash, expected_seq + 1, count + 1
    return VerifyResult(True, count, prev_hash.hex() if count else None, None)


def list_entries(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    after_seq: int = 0,
    limit: int = 50,
    action: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[AuditRecord]:
    """Keyset-paginated entries in sequence order."""
    query = select(AuditLog).where(AuditLog.tenant_id == tenant_id, AuditLog.seq > after_seq)
    if action is not None:
        query = query.where(AuditLog.action == action)
    if since is not None:
        query = query.where(AuditLog.ts >= since)
    if until is not None:
        query = query.where(AuditLog.ts < until)
    rows = session.scalars(query.order_by(AuditLog.seq).limit(limit)).all()
    return [_record(row) for row in rows]
