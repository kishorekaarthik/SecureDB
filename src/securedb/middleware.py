"""ASGI middleware that assigns every request an ID."""

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
