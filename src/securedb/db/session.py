"""Engine and transactional sessions, including tenant-scoped sessions for RLS."""

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker


class Database:
    def __init__(self, url: str, *, pool_size: int = 5, max_overflow: int = 10) -> None:
        self.engine: Engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=pool_size,
            max_overflow=max_overflow,
            hide_parameters=True,  # keep bound values (PII) out of exception text
        )
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """One transaction: commits on success, rolls back on any exception."""
        with self._sessions() as session, session.begin():
            yield session

    @contextmanager
    def tenant_session(self, tenant_id: uuid.UUID) -> Iterator[Session]:
        """A transaction with app.tenant_id set for row-level security.

        set_config(..., true) is transaction-local, so the value cannot leak to
        the next user of the pooled connection.
        """
        with self.session() as session:
            session.execute(
                text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
            yield session

    def ping(self) -> bool:
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return False
        return True

    def dispose(self) -> None:
        self.engine.dispose()
