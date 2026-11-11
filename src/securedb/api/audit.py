"""/v1/audit: read and verify the tenant's audit log (scope audit:read)."""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import AwareDatetime, BaseModel

from securedb.api.auth import require
from securedb.audit.log import AuditRecord, list_entries, verify
from securedb.db.session import Database
from securedb.errors import UnprocessableEntity
from securedb.tenants.api_keys import AuthenticatedKey, Scope

router = APIRouter(prefix="/v1/audit", tags=["audit"])

AuditReader = Annotated[AuthenticatedKey, Depends(require(Scope.audit_read))]


class AuditEntryOut(BaseModel):
    seq: int
    ts: datetime
    actor_type: str
    actor_id: str
    action: str
    token_ids: list[str]
    outcome: dict[str, Any]
    request_id: str | None
    prev_hash: str
    hash: str

    @classmethod
    def of(cls, record: AuditRecord) -> "AuditEntryOut":
        return cls(
            seq=record.seq,
            ts=record.ts,
            actor_type=record.actor_type,
            actor_id=record.actor_id,
            action=record.action,
            token_ids=record.token_ids,
            outcome=record.outcome,
            request_id=record.request_id,
            prev_hash=record.prev_hash.hex(),
            hash=record.hash.hex(),
        )


class AuditPage(BaseModel):
    items: list[AuditEntryOut]
    next_cursor: int | None


class VerifyOut(BaseModel):
    ok: bool
    entries: int
    head_hash: str | None
    first_broken_seq: int | None


def _db(request: Request) -> Database:
    db: Database = request.app.state.db
    return db


@router.get("", response_model=AuditPage)
def list_audit(
    request: Request,
    key: AuditReader,
    cursor: Annotated[int, Query(ge=0, le=2**62, description="Return entries after this seq.")] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z._]+$")] = None,
    since: Annotated[AwareDatetime | None, Query(alias="from")] = None,
    until: Annotated[AwareDatetime | None, Query(alias="to")] = None,
) -> AuditPage:
    with _db(request).tenant_session(key.tenant_id) as session:
        records = list_entries(
            session,
            key.tenant_id,
            after_seq=cursor,
            limit=limit,
            action=action,
            since=since,
            until=until,
        )
    next_cursor = records[-1].seq if len(records) == limit else None
    return AuditPage(items=[AuditEntryOut.of(r) for r in records], next_cursor=next_cursor)


@router.get("/verify", response_model=VerifyOut)
def verify_audit(
    request: Request,
    key: AuditReader,
    anchor_seq: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    anchor_hash: Annotated[str | None, Query(pattern=r"^[0-9a-f]{64}$")] = None,
) -> VerifyOut:
    """Recompute the chain. Pass an anchor recorded earlier outside the database to also
    detect truncation of recent entries or a full rewrite by the table owner."""
    if (anchor_seq is None) != (anchor_hash is None):
        raise UnprocessableEntity("anchor_seq and anchor_hash must be given together.")
    with _db(request).tenant_session(key.tenant_id) as session:
        result = verify(session, key.tenant_id, anchor_seq=anchor_seq, anchor_hash=anchor_hash)
    return VerifyOut(
        ok=result.ok,
        entries=result.entries,
        head_hash=result.head_hash,
        first_broken_seq=result.first_broken_seq,
    )
