"""Liveness and readiness probes."""

from collections.abc import Callable

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])
log = structlog.get_logger(__name__)


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(request: Request) -> JSONResponse:
    checks: list[tuple[str, Callable[[], bool]]] = request.app.state.readiness_checks
    results = {name: _run_check(name, check) for name, check in checks}
    ready = all(results.values())
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", "checks": results},
        status_code=200 if ready else 503,
    )


def _run_check(name: str, check: Callable[[], bool]) -> bool:
    try:
        return bool(check())
    except Exception:
        log.exception("readiness_check_failed", check=name)
        return False
