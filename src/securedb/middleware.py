"""ASGI middleware: request IDs, body size limits and security headers."""

import re
import uuid

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_INBOUND_ID = re.compile(r"[A-Za-z0-9-]{1,64}")


class RequestIdMiddleware:
    """Accepts a well-formed inbound X-Request-ID or generates one.

    The ID is stored in scope["state"] (visible to error handlers, including the
    outermost 500 handler), bound into structlog context, and returned as a header.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        inbound = Headers(scope=scope).get("x-request-id", "")
        request_id = inbound if _INBOUND_ID.fullmatch(inbound) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).append("X-Request-ID", request_id)
            await send(message)

        with structlog.contextvars.bound_contextvars(request_id=request_id):
            await self.app(scope, receive, send_with_request_id)


class BodySizeLimitMiddleware:
    """Rejects request bodies over `max_bytes` with 413, before anything parses them.

    FastAPI reads and parses JSON bodies before running dependencies (including
    authentication), so without this an anonymous client could make the server buffer
    arbitrarily large bodies. Checks Content-Length up front and counts streamed bytes;
    once the limit is passed the app is told the client disconnected and its output is
    replaced by the 413.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(scope, receive, send)
            return

        received = 0
        too_large = False

        async def counting_receive() -> Message:
            nonlocal received, too_large
            if too_large:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            if not too_large:
                await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except Exception:
            if not too_large:
                raise
        if too_large:
            await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Imported here to avoid a cycle: errors -> middleware is not needed at import.
        from starlette.requests import Request

        from securedb.errors import get_request_id, problem_response

        response = problem_response(
            413,
            "Content Too Large",
            f"Request body exceeds {self.max_bytes} bytes.",
            get_request_id(Request(scope)),
        )
        await response(scope, receive, send)


CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)
_CSP_EXEMPT = ("/docs", "/openapi.json")  # Swagger UI (dev only) loads scripts from a CDN
_CACHEABLE = ("/console/static/",)


class SecurityHeadersMiddleware:
    """Adds security headers to every response (API and console alike).

    The CSP allows no scripts at all: the console is plain HTML forms. Responses are
    marked no-store because they can contain decrypted values or one-time secrets.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        https = scope.get("scheme") == "https"

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                if not path.startswith(_CSP_EXEMPT):
                    headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
                if not path.startswith(_CACHEABLE):
                    headers["Cache-Control"] = "no-store"
                if https:
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_with_headers)
