"""/v1/subjects: DPDP erasure and export for one data subject."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel

from securedb.api.auth import require
from securedb.api.tokens import SUBJECT_PATTERN
from securedb.db.session import Database
from securedb.tenants.api_keys import AuthenticatedKey, Scope
from securedb.vault.subjects import SubjectService

router = APIRouter(prefix="/v1/subjects", tags=["subjects"])

SubjectId = Annotated[str, Path(pattern=SUBJECT_PATTERN)]


class ErasureOut(BaseModel):
    deleted: int
    retained_shared: int


class ExportedTokenOut(BaseModel):
    token: str
    type: str
    created_at: datetime
    shared: bool
    value: str | dict[str, str] | None = None
    masked: bool = False


class HistoryOut(BaseModel):
    seq: int
    ts: datetime
    action: str
    actor_type: str
    actor_id: str


class ExportOut(BaseModel):
    subject_ref: str
    tokens: list[ExportedTokenOut]
    history: list[HistoryOut]


def _db(request: Request) -> Database:
    db: Database = request.app.state.db
    return db


def _service(request: Request) -> SubjectService:
    service: SubjectService = request.app.state.subjects
    return service


@router.delete("/{subject_id}", response_model=ErasureOut)
def erase_subject(
    subject_id: SubjectId,
    request: Request,
    key: Annotated[AuthenticatedKey, Depends(require(Scope.subjects_erase))],
) -> ErasureOut:
    """Erase a data subject: tokens nobody else owns are deleted; shared ones are kept."""
    with _db(request).tenant_session(key.tenant_id) as session:
        result = _service(request).erase(session, key, subject_id)
    return ErasureOut(deleted=len(result.deleted_tokens), retained_shared=result.retained_shared)


@router.get("/{subject_id}/export", response_model=ExportOut, response_model_exclude_none=True)
def export_subject(
    subject_id: SubjectId,
    request: Request,
    key: Annotated[AuthenticatedKey, Depends(require(Scope.subjects_export))],
) -> ExportOut:
    """Everything held about a subject; values only as the key's detokenize policy allows."""
    with _db(request).tenant_session(key.tenant_id) as session:
        export = _service(request).export(session, key, subject_id)
    return ExportOut(
        subject_ref=export.subject_ref,
        tokens=[
            ExportedTokenOut(
                token=t.token,
                type=t.type,
                created_at=t.created_at,
                shared=t.shared,
                value=t.value,
                masked=t.masked,
            )
            for t in export.tokens
        ],
        history=[
            HistoryOut(
                seq=h.seq, ts=h.ts, action=h.action, actor_type=h.actor_type, actor_id=h.actor_id
            )
            for h in export.history
        ],
    )
