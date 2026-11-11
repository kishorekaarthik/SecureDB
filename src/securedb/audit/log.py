"""Per-tenant hash-chained audit log (spec §2.7).

Each entry's hash is SHA-256(prev_hash || canonical_json(entry)); the first entry chains
from 32 zero bytes. Appends serialise per tenant with a transaction-scoped advisory lock,
and the application role can only INSERT and SELECT, so history cannot be rewritten by
the app. ``verify`` recomputes the chain and reports the first broken sequence number.

What the chain proves: an edit, deletion or reordering of entries made by anyone who
cannot also rewrite every later hash. It is an *unkeyed* SHA-256 chain, so two things are
only detectable against an anchor kept outside the database:

* truncation of the newest entries (the shorter chain still links), and
* a full rewrite by someone with the table-owner role (who can recompute every hash).

Operators should periodically record ``(entries, head_hash)`` from ``verify`` somewhere
the database owner cannot change, and pass it back as ``anchor_seq``/``anchor_hash``.
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


def _check_outcome(value: Any) -> None:
    """Outcomes must survive a JSONB round trip byte-for-byte, or verify would report
    tampering: only strings, ints, bools, None, lists and string-keyed dicts. Floats are
    refused because PostgreSQL re-renders them (1e16 comes back as 10000000000000000)."""
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, list):
        for item in value:
            _check_outcome(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("audit outcome keys must be strings")
            _check_outcome(item)
        return
    raise TypeError(f"audit outcome values cannot be {type(value).__name__}")


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
    _check_outcome(outcome)
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


def verify(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    anchor_seq: int | None = None,
    anchor_hash: str | None = None,
) -> VerifyResult:
    """Recompute the whole chain; report the first sequence number that does not check out.

    With an anchor (a ``(seq, hash)`` pair recorded earlier outside the database), also
    fail if that entry is missing or its hash changed: this is what detects truncation
    of the newest entries and a full rewrite by someone with the table-owner role.
    """
    expected_seq, prev_hash, count = 1, GENESIS_HASH, 0
    query = select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.seq)
    # yield_per as an *execution option* streams through a server-side cursor; applied
    # to the result afterwards it would still buffer every row in the driver.
    rows = session.scalars(query, execution_options={"yield_per": 1000})

    def broken(seq: int) -> VerifyResult:
        return VerifyResult(False, count, prev_hash.hex() if count else None, seq)

    for row in rows:
        record = _record(row)
        if (
            record.seq != expected_seq
            or record.prev_hash != prev_hash
            or record.hash != _chain(prev_hash, tenant_id, record)
        ):
            return broken(expected_seq)
        if record.seq == anchor_seq and record.hash.hex() != anchor_hash:
            return broken(record.seq)
        prev_hash, expected_seq, count = record.hash, expected_seq + 1, count + 1
    if anchor_seq is not None and count < anchor_seq:
        return broken(count + 1)
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
