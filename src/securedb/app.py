"""FastAPI application factory."""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from securedb import __version__
from securedb.api import health
from securedb.config import Settings, get_settings
from securedb.db.session import Database
from securedb.errors import UnhandledErrorMiddleware, install_error_handlers
from securedb.logs import configure_logging
from securedb.middleware import RequestIdMiddleware


def create_app(settings: Settings | None = None, database: Database | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    db = database or Database(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        db.dispose()

    app = FastAPI(
        title="SecureDB Vault",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    readiness_checks: list[tuple[str, Callable[[], bool]]] = [("database", db.ping)]
    app.state.settings = settings
    app.state.db = db
    app.state.readiness_checks = readiness_checks

    # Added first = innermost: errors are caught inside RequestIdMiddleware.
    app.add_middleware(UnhandledErrorMiddleware)
    app.add_middleware(RequestIdMiddleware)
    install_error_handlers(app)
    app.include_router(health.router)
    return app
