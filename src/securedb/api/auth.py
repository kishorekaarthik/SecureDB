"""API-key authentication and scope checks as FastAPI dependencies."""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, Request

from securedb.api.ratelimit import FixedWindowRateLimiter
from securedb.errors import Forbidden
from securedb.tenants.api_keys import AuthenticatedKey, Scope, authenticate


def current_key(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> AuthenticatedKey:
    key = authenticate(request.app.state.db, authorization)
    limiter: FixedWindowRateLimiter = request.app.state.rate_limiter
    limiter.hit(str(key.id))
    return key


def require(scope: Scope) -> Callable[[AuthenticatedKey], AuthenticatedKey]:
    def dependency(key: Annotated[AuthenticatedKey, Depends(current_key)]) -> AuthenticatedKey:
        if not key.allows(scope):
            raise Forbidden(f"This API key lacks the '{scope.value}' scope.")
        return key

    return dependency
