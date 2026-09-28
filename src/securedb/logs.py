"""Structured JSON logging with redaction of sensitive fields."""

import logging
import re
import sys
from collections.abc import Mapping
from typing import Any, cast

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

REDACTED = "[REDACTED]"
SENSITIVE_KEYS = frozenset(
    {"value", "values", "secret", "password", "totp", "authorization", "api_key"}
)
_API_KEY_PATTERN = re.compile(r"sdb_(?:live|test)_[A-Za-z0-9]+_[A-Za-z0-9]+")


def _scrub(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {
            key: REDACTED if isinstance(key, str) and key.lower() in SENSITIVE_KEYS else _scrub(val)
            for key, val in obj.items()
        }
    if isinstance(obj, list | tuple):
        return type(obj)(_scrub(item) for item in obj)
    if isinstance(obj, str):
        return _API_KEY_PATTERN.sub(REDACTED, obj)
    return obj


def redact_sensitive(_logger: WrappedLogger, _method_name: str, event_dict: EventDict) -> EventDict:
    return cast(EventDict, _scrub(dict(event_dict)))


def configure_logging(level: str = "INFO") -> None:
    numeric_level = logging.getLevelNamesMapping()[level]
    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    render: list[Processor] = [
        structlog.processors.format_exc_info,
        redact_sensitive,
        structlog.processors.JSONRenderer(),
    ]

    # structlog loggers (our code)
    structlog.configure(
        processors=[*shared, *render],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )

    # stdlib loggers (uvicorn, sqlalchemy, alembic) go through the same pipeline
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared,
            processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, *render],
        )
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(numeric_level)
