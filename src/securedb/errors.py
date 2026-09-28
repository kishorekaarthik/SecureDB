"""Domain errors and RFC 7807 problem+json responses."""

import traceback
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, ClassVar, cast

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

PROBLEM_JSON = "application/problem+json"

log = structlog.get_logger(__name__)


class DomainError(Exception):
    status_code: ClassVar[int] = 400
    title: ClassVar[str] = "Bad Request"

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail or self.title
        super().__init__(self.detail)


class NotFound(DomainError):
    status_code = 404
    title = "Not Found"


class Unauthorized(DomainError):
    status_code = 401
    title = "Unauthorized"


def get_request_id(request: Request) -> str:
    state = request.scope.get("state") or {}
    request_id = state.get("request_id")
    return request_id if isinstance(request_id, str) else "unknown"


def problem_response(
    status: int,
    title: str,
    detail: str,
    request_id: str,
    *,
    headers: Mapping[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    body = {
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
        "request_id": request_id,
        **extra,
    }
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON, headers=headers)


# Handlers take (Request, Exception) to match Starlette's handler type; each is only
# registered for its own exception class, so the casts below are safe.


async def _handle_domain_error(request: Request, exc: Exception) -> JSONResponse:
    error = cast(DomainError, exc)
    return problem_response(error.status_code, error.title, error.detail, get_request_id(request))


async def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    error = cast(StarletteHTTPException, exc)
    title = HTTPStatus(error.status_code).phrase
    detail = error.detail if isinstance(error.detail, str) else title
    return problem_response(
        error.status_code, title, detail, get_request_id(request), headers=error.headers
    )


async def _handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
    error = cast(RequestValidationError, exc)
    # Deliberately drop "input" and "ctx": they can contain the submitted PII.
    errors = [
        {"loc": list(err["loc"]), "msg": err["msg"], "type": err["type"]} for err in error.errors()
    ]
    return problem_response(
        422,
        HTTPStatus.UNPROCESSABLE_CONTENT.phrase,
        "Request validation failed.",
        get_request_id(request),
        errors=errors,
    )


async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    request_id = get_request_id(request)
    if isinstance(exc, SQLAlchemyError):
        # Database error messages embed row values (e.g. "Key (name)=(...)"), so log
        # only the error class, SQLSTATE and the stack frames, never the message.
        log.error(
            "unhandled_error",
            request_id=request_id,
            error_type=type(exc).__name__,
            sqlstate=getattr(getattr(exc, "orig", None), "sqlstate", None),
            stack="".join(traceback.format_tb(exc.__traceback__)),
        )
    else:
        log.error("unhandled_error", request_id=request_id, exc_info=exc)
    return problem_response(
        500, "Internal Server Error", "An unexpected error occurred.", request_id
    )


class UnhandledErrorMiddleware:
    """Turns unexpected exceptions into a 500 problem response inside the app.

    Starlette's outermost ServerErrorMiddleware re-raises after responding, so the
    server would log the raw, unredacted traceback a second time. Catching here
    means exceptions never reach the server, and the response still passes through
    RequestIdMiddleware (so it gets an X-Request-ID header).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            if response_started:  # too late to send a clean 500
                raise
            response = await _handle_unexpected(Request(scope), exc)
            await response(scope, receive, send)


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(DomainError, _handle_domain_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(Exception, _handle_unexpected)
