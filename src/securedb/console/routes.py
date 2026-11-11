"""Server-rendered admin console (no JavaScript; every state change is a CSRF-checked POST)."""

import hmac
import secrets
import uuid
from importlib import resources
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Form, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, PackageLoader, select_autoescape
from sqlalchemy import func, select

from securedb.api.ratelimit import FixedWindowRateLimiter
from securedb.audit.log import append, verify
from securedb.console import auth
from securedb.console.auth import SessionInfo
from securedb.crypto.rotation import reencrypt, rotate_dek
from securedb.db.models import ApiKey, AuditLog, Policy, Tenant, TenantKey, Token
from securedb.db.session import Database
from securedb.errors import DomainError, Forbidden, NotFound, UnprocessableEntity
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import (
    AuthenticatedKey,
    Scope,
    issue_api_key,
    revoke_api_key,
    update_api_key_scopes,
)
from securedb.vault.fields import FieldType
from securedb.vault.service import DetokenizeResult, TokenizeItem, TokenService

SESSION_COOKIE = "__Host-sdb_session"
PRE_LOGIN_COOKIE = "__Host-sdb_csrf"  # double-submit token for the login form
LOGIN_ERROR = "Invalid tenant, e-mail or password."
AUDIT_PAGE_SIZE = 50
MESSAGES = {
    "revoked": "API key revoked.",
    "policy": "Policy updated.",
    "scopes": "Scopes updated.",
    "rotated": "A new data key is active. Re-encrypt to move existing values.",
    "reencrypted": "Re-encryption finished.",
}

router = APIRouter(prefix="/console", include_in_schema=False)
_templates = Environment(
    loader=PackageLoader("securedb.console", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
)
_CSS = resources.files("securedb.console").joinpath("static/console.css").read_text("utf-8")


class LoginRequired(Exception):
    pass


def _db(request: Request) -> Database:
    db: Database = request.app.state.db
    return db


def _page(
    name: str, request: Request, info: SessionInfo | None = None, status: int = 200, **context: Any
) -> HTMLResponse:
    html = _templates.get_template(name).render(
        user=info.user if info else None,
        csrf_token=info.csrf_token if info else context.pop("csrf_token", ""),
        path=request.url.path,
        message=MESSAGES.get(request.query_params.get("msg", "")),
        **context,
    )
    return HTMLResponse(html, status_code=status)


def _set_cookie(response: Response, name: str, value: str) -> None:
    response.set_cookie(name, value, httponly=True, secure=True, samesite="strict", path="/")


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _check_csrf(expected: str | None, submitted: str) -> None:
    if (
        not expected
        or not submitted
        or not hmac.compare_digest(expected.encode(), submitted.encode())
    ):
        raise Forbidden("Missing or invalid CSRF token.")


# --- Dependencies ----------------------------------------------------------------


def _session(request: Request) -> SessionInfo | None:
    raw = request.cookies.get(SESSION_COOKIE)
    return auth.load_session(_db(request), raw) if raw else None


def signed_in(request: Request) -> SessionInfo:
    info = _session(request)
    if info is None or not info.verified:
        raise LoginRequired
    return info


def owner_page(info: Annotated[SessionInfo, Depends(signed_in)]) -> SessionInfo:
    if not info.user.is_owner:
        raise Forbidden("Only owners can use this page.")
    return info


def posted(  # nosec B107
    info: Annotated[SessionInfo, Depends(signed_in)], csrf_token: Annotated[str, Form()] = ""
) -> SessionInfo:
    _check_csrf(info.csrf_token, csrf_token)
    return info


def owner_action(info: Annotated[SessionInfo, Depends(posted)]) -> SessionInfo:
    if not info.user.is_owner:
        raise Forbidden("Only owners can make changes.")
    return info


SignedIn = Annotated[SessionInfo, Depends(signed_in)]
OwnerPage = Annotated[SessionInfo, Depends(owner_page)]
OwnerAction = Annotated[SessionInfo, Depends(owner_action)]


# --- Login -----------------------------------------------------------------------


@router.get("/static/console.css")
def stylesheet() -> Response:
    return Response(_CSS, media_type="text/css")


@router.get("/login")
def login_form(request: Request) -> HTMLResponse:
    token = request.cookies.get(PRE_LOGIN_COOKIE) or secrets.token_urlsafe(32)
    response = _page("login.html", request, csrf_token=token)
    _set_cookie(response, PRE_LOGIN_COOKIE, token)
    return response


@router.post("/login")
def login(  # nosec B107
    request: Request,
    tenant: Annotated[str, Form(max_length=200)] = "",
    email: Annotated[str, Form(max_length=254)] = "",
    password: Annotated[str, Form(max_length=1024)] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    expected = request.cookies.get(PRE_LOGIN_COOKIE)
    _check_csrf(expected, csrf_token)
    # Throttle before any password hashing: per client and per account.
    limiter: FixedWindowRateLimiter = request.app.state.login_limiter
    limiter.hit(f"ip:{request.client.host if request.client else 'unknown'}")
    limiter.hit(f"user:{tenant.strip()}|{email.strip().lower()}")
    user = auth.check_password(_db(request), tenant, email, password)
    if user is None:
        return _page("login.html", request, status=401, csrf_token=expected, error=LOGIN_ERROR)
    response = _redirect("/console/login/totp")
    _set_cookie(response, SESSION_COOKIE, auth.start_session(_db(request), user, verified=False))
    return response


def _pending(request: Request) -> SessionInfo:
    info = _session(request)
    if info is None or info.verified:
        raise LoginRequired
    return info


@router.get("/login/totp")
def totp_form(request: Request) -> HTMLResponse:
    return _page("totp.html", request, _pending(request))


@router.post("/login/totp")
def totp(  # nosec B107
    request: Request,
    code: Annotated[str, Form(max_length=16)] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    pending = _pending(request)
    _check_csrf(pending.csrf_token, csrf_token)
    db = _db(request)
    if not auth.check_totp(db, request.app.state.keyring, pending.user, code):
        return _page("totp.html", request, pending, status=401, error="Invalid code.")
    auth.end_session(db, pending)  # new session ID after authentication (no fixation)
    response = _redirect("/console")
    _set_cookie(response, SESSION_COOKIE, auth.start_session(db, pending.user, verified=True))
    response.delete_cookie(PRE_LOGIN_COOKIE, path="/", secure=True, httponly=True)
    return response


@router.post("/logout")
def logout(request: Request, info: Annotated[SessionInfo, Depends(posted)]) -> Response:
    auth.end_session(_db(request), info)
    response = _redirect("/console/login")
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True)
    return response


# --- Overview --------------------------------------------------------------------


@router.get("")
def overview(request: Request, info: SignedIn) -> HTMLResponse:
    tenant_id = info.user.tenant_id
    with _db(request).tenant_session(tenant_id) as session:
        tenant_name = session.scalar(select(Tenant.name).where(Tenant.id == tenant_id))
        counts = session.execute(
            select(Token.type, func.count()).group_by(Token.type).order_by(Token.type)
        ).all()
        active_version = session.scalar(
            select(TenantKey.version).where(TenantKey.status == "active")
        )
        recent = session.scalars(select(AuditLog).order_by(AuditLog.seq.desc()).limit(10)).all()
        active_keys = session.scalar(
            select(func.count()).select_from(ApiKey).where(ApiKey.revoked_at.is_(None))
        )
    return _page(
        "overview.html",
        request,
        info,
        tenant_name=tenant_name,
        counts=[(row[0], row[1]) for row in counts],
        total=sum(row[1] for row in counts),
        active_version=active_version,
        active_keys=active_keys,
        recent=recent,
    )


# --- API keys and policies ---------------------------------------------------------


def _keys_page(request: Request, info: SessionInfo, **context: Any) -> HTMLResponse:
    with _db(request).tenant_session(info.user.tenant_id) as session:
        keys = session.scalars(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
        policies: dict[uuid.UUID, list[Policy]] = {}
        for policy in session.scalars(select(Policy).order_by(Policy.field_type, Policy.action)):
            policies.setdefault(policy.api_key_id, []).append(policy)
    return _page(
        "keys.html",
        request,
        info,
        keys=keys,
        policies=policies,
        scopes=[scope.value for scope in Scope],
        field_types=[t.value for t in FieldType],
        **context,
    )


@router.get("/keys")
def keys(request: Request, info: SignedIn) -> HTMLResponse:
    return _keys_page(request, info)


@router.post("/keys")
def create_key(
    request: Request,
    info: OwnerAction,
    name: Annotated[str, Form(min_length=1, max_length=64)],
    scopes: Annotated[list[Scope], Form(default_factory=list)],
) -> HTMLResponse:
    if not scopes:
        return _keys_page(request, info, error="Choose at least one scope.")
    tenant_id = info.user.tenant_id
    with _db(request).tenant_session(tenant_id) as session:
        issued = issue_api_key(session, tenant_id, name.strip(), scopes, actor=info.user.actor)
    return _keys_page(request, info, new_key=issued.plaintext)


@router.post("/keys/{key_id}/revoke")
def revoke_key(request: Request, info: OwnerAction, key_id: uuid.UUID) -> Response:
    with _db(request).tenant_session(info.user.tenant_id) as session:
        revoke_api_key(session, key_id, actor=info.user.actor)
    return _redirect("/console/keys?msg=revoked")


@router.post("/keys/{key_id}/scopes")
def change_scopes(
    request: Request,
    info: OwnerAction,
    key_id: uuid.UUID,
    scopes: Annotated[list[Scope], Form(default_factory=list)],
) -> Response:
    try:
        with _db(request).tenant_session(info.user.tenant_id) as session:
            update_api_key_scopes(session, key_id, scopes, actor=info.user.actor)
    except ValueError as exc:
        return _keys_page(request, info, error=str(exc))
    return _redirect("/console/keys?msg=scopes")


@router.post("/keys/{key_id}/policy")
def change_policy(
    request: Request,
    info: OwnerAction,
    key_id: uuid.UUID,
    field_type: Annotated[FieldType, Form()],
    action: Annotated[Action, Form()],
    effect: Annotated[Effect, Form()],
) -> Response:
    tenant_id = info.user.tenant_id
    try:
        with _db(request).tenant_session(tenant_id) as session:
            set_policy(
                session, tenant_id, key_id, field_type, action, effect, actor=info.user.actor
            )
    except ValueError as exc:
        return _keys_page(request, info, error=str(exc))
    return _redirect("/console/keys?msg=policy")


# --- Audit log -------------------------------------------------------------------


@router.get("/audit")
def audit_log(
    request: Request,
    info: SignedIn,
    before: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z._]*$")] = None,
) -> HTMLResponse:
    query = select(AuditLog).order_by(AuditLog.seq.desc()).limit(AUDIT_PAGE_SIZE)
    if before is not None:
        query = query.where(AuditLog.seq < before)
    if action:
        query = query.where(AuditLog.action == action)
    with _db(request).tenant_session(info.user.tenant_id) as session:
        entries = session.scalars(query).all()
    older = entries[-1].seq if len(entries) == AUDIT_PAGE_SIZE else None
    return _page("audit.html", request, info, entries=entries, older=older, action=action or "")


@router.get("/audit/verify")
def audit_verify(
    request: Request,
    info: SignedIn,
    anchor_seq: Annotated[int | None, Query(ge=1, le=2**62)] = None,
    anchor_hash: Annotated[str | None, Query(pattern=r"^[0-9a-f]{64}$")] = None,
) -> HTMLResponse:
    if (anchor_seq is None) != (anchor_hash is None):
        raise UnprocessableEntity("anchor_seq and anchor_hash must be given together.")
    tenant_id = info.user.tenant_id
    with _db(request).tenant_session(tenant_id) as session:
        result = verify(session, tenant_id, anchor_seq=anchor_seq, anchor_hash=anchor_hash)
    return _page("verify.html", request, info, result=result, anchored=anchor_seq is not None)


# --- Encryption keys -------------------------------------------------------------


@router.get("/encryption")
def encryption(request: Request, info: SignedIn) -> HTMLResponse:
    with _db(request).tenant_session(info.user.tenant_id) as session:
        versions = session.scalars(select(TenantKey).order_by(TenantKey.version.desc())).all()
        usage = {
            row[0]: row[1]
            for row in session.execute(
                select(Token.key_version, func.count()).group_by(Token.key_version)
            ).all()
        }
    return _page("encryption.html", request, info, versions=versions, usage=usage)


@router.post("/encryption/rotate")
def rotate(request: Request, info: OwnerAction) -> Response:
    tenant_id = info.user.tenant_id
    with _db(request).tenant_session(tenant_id) as session:
        rotate_dek(session, request.app.state.keyring, tenant_id, actor=info.user.actor)
    return _redirect("/console/encryption?msg=rotated")


@router.post("/encryption/reencrypt")
def reencrypt_values(request: Request, info: OwnerAction) -> Response:
    reencrypt(_db(request), request.app.state.keyring, info.user.tenant_id, actor=info.user.actor)
    return _redirect("/console/encryption?msg=reencrypted")


# --- Playground ------------------------------------------------------------------


def _playground(request: Request, info: SessionInfo, **context: Any) -> HTMLResponse:
    with _db(request).tenant_session(info.user.tenant_id) as session:
        keys = session.scalars(
            select(ApiKey).where(ApiKey.revoked_at.is_(None)).order_by(ApiKey.name)
        ).all()
    return _page(
        "playground.html",
        request,
        info,
        keys=keys,
        field_types=[t.value for t in FieldType],
        **context,
    )


def _acting_key(request: Request, info: SessionInfo, key_id: uuid.UUID) -> AuthenticatedKey:
    with _db(request).tenant_session(info.user.tenant_id) as session:
        row = session.get(ApiKey, key_id)  # row-level security hides other tenants' keys
        if row is None or row.revoked_at is not None:
            raise NotFound("API key not found.")
        return AuthenticatedKey(row.id, row.tenant_id, frozenset(row.scopes))


@router.get("/playground")
def playground(request: Request, info: OwnerPage) -> HTMLResponse:
    return _playground(request, info)


@router.post("/playground/tokenize")
def playground_tokenize(
    request: Request,
    info: OwnerAction,
    key_id: Annotated[uuid.UUID, Form()],
    type: Annotated[FieldType, Form()],
    value: Annotated[str, Form(max_length=4096)] = "",
    ifsc: Annotated[str, Form(max_length=32)] = "",
    subject_id: Annotated[str, Form(pattern=r"^[A-Za-z0-9._:@-]{0,128}$")] = "",
) -> HTMLResponse:
    service: TokenService = request.app.state.tokens
    db, tenant_id = _db(request), info.user.tenant_id
    raw: Any = {"account_number": value, "ifsc": ifsc} if type is FieldType.bank_account else value
    try:
        key = _acting_key(request, info, key_id)
        if not key.allows(Scope.tokenize):  # same gate the API applies
            raise Forbidden("This API key lacks the 'tokenize' scope.")
        with db.tenant_session(tenant_id) as session:
            [result] = service.tokenize(
                session,
                key,
                [TokenizeItem(type, raw, subject_id or None)],
                actor=info.user.actor,
            )
    except (Forbidden, UnprocessableEntity) as exc:
        with db.tenant_session(tenant_id) as session:
            append(
                session,
                tenant_id,
                info.user.actor,
                "tokenize.rejected",
                outcome={
                    "reason": "forbidden" if isinstance(exc, Forbidden) else "invalid",
                    "items": 1,
                    "via_key": str(key_id),
                },
            )
        return _playground(request, info, error=exc.detail)
    except DomainError as exc:
        return _playground(request, info, error=exc.detail)
    return _playground(request, info, tokenized=result)


@router.post("/playground/detokenize")
def playground_detokenize(
    request: Request,
    info: OwnerAction,
    key_id: Annotated[uuid.UUID, Form()],
    token: Annotated[str, Form(max_length=64, pattern=r"^tok_[a-z_]+_[A-Za-z0-9]{22}$")],
) -> HTMLResponse:
    service: TokenService = request.app.state.tokens
    try:
        key = _acting_key(request, info, key_id)
        if not key.allows(Scope.detokenize):  # same gate the API applies
            with _db(request).tenant_session(info.user.tenant_id) as session:
                append(
                    session,
                    info.user.tenant_id,
                    info.user.actor,
                    "detokenize.rejected",
                    token_ids=[token],
                    outcome={"reason": "scope", "via_key": str(key_id)},
                )
            return _playground(request, info, error="This API key lacks the 'detokenize' scope.")
        with _db(request).tenant_session(info.user.tenant_id) as session:
            results: list[DetokenizeResult] = service.detokenize(
                session, key, [token], actor=info.user.actor
            )
    except DomainError as exc:
        return _playground(request, info, error=exc.detail)
    return _playground(request, info, detokenized=results[0])


# --- Wiring ----------------------------------------------------------------------


async def _to_login(_request: Request, _exc: Exception) -> Response:
    return _redirect("/console/login")


def install_console(app: FastAPI) -> None:
    app.include_router(router)
    app.add_exception_handler(LoginRequired, _to_login)
