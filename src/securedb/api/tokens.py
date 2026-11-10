"""/v1/tokens: tokenize, detokenize and delete."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from securedb.api.auth import require
from securedb.db.session import Database
from securedb.tenants.api_keys import AuthenticatedKey, Scope
from securedb.vault.fields import FieldType
from securedb.vault.service import TokenizeItem, TokenService

router = APIRouter(prefix="/v1/tokens", tags=["tokens"])

TokenStr = Annotated[str, Field(min_length=1, max_length=128)]


class BankAccountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_number: str = Field(max_length=64)
    ifsc: str = Field(max_length=32)


class TokenizeItemIn(BaseModel):
    type: FieldType
    value: str | BankAccountIn
    subject_id: str | None = Field(default=None, min_length=1, max_length=128)


class TokenizeRequest(BaseModel):
    items: list[TokenizeItemIn] = Field(min_length=1, max_length=100)


class TokenizeItemOut(BaseModel):
    token: str
    type: FieldType
    created: bool


class TokenizeResponse(BaseModel):
    items: list[TokenizeItemOut]


class DetokenizeRequest(BaseModel):
    tokens: list[TokenStr] = Field(min_length=1, max_length=100)


class DetokenizeItemOut(BaseModel):
    token: str
    value: str | dict[str, str] | None = None
    masked: bool = False
    error: str | None = None


class DetokenizeResponse(BaseModel):
    items: list[DetokenizeItemOut]


def _db(request: Request) -> Database:
    db: Database = request.app.state.db
    return db


def _service(request: Request) -> TokenService:
    service: TokenService = request.app.state.tokens
    return service


@router.post("", response_model=TokenizeResponse)
def tokenize(
    body: TokenizeRequest,
    request: Request,
    key: Annotated[AuthenticatedKey, Depends(require(Scope.tokenize))],
) -> TokenizeResponse:
    items = [
        TokenizeItem(
            type=item.type,
            value=item.value.model_dump() if isinstance(item.value, BankAccountIn) else item.value,
            subject_id=item.subject_id,
        )
        for item in body.items
    ]
    with _db(request).tenant_session(key.tenant_id) as session:
        results = _service(request).tokenize(session, key, items)
    return TokenizeResponse(
        items=[TokenizeItemOut(token=r.token, type=r.type, created=r.created) for r in results]
    )


@router.post("/detokenize", response_model=DetokenizeResponse, response_model_exclude_none=True)
def detokenize(
    body: DetokenizeRequest,
    request: Request,
    key: Annotated[AuthenticatedKey, Depends(require(Scope.detokenize))],
) -> DetokenizeResponse:
    with _db(request).tenant_session(key.tenant_id) as session:
        results = _service(request).detokenize(session, key, body.tokens)
    return DetokenizeResponse(
        items=[
            DetokenizeItemOut(token=r.token, value=r.value, masked=r.masked, error=r.error)
            for r in results
        ]
    )


@router.delete("/{token}", status_code=204, response_class=Response)
def delete_token(
    token: Annotated[str, Path(min_length=1, max_length=128)],
    request: Request,
    key: Annotated[AuthenticatedKey, Depends(require(Scope.subjects_erase))],
) -> Response:
    with _db(request).tenant_session(key.tenant_id) as session:
        _service(request).delete_token(session, token)
    return Response(status_code=204)
