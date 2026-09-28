import uuid

import pytest
from sqlalchemy import select, text

from securedb.config import Settings
from securedb.db.models import Tenant
from securedb.db.session import Database

CURRENT_TENANT = text("SELECT current_setting('app.tenant_id', true)")


def test_session_commits_on_success(db: Database) -> None:
    with db.session() as session:
        session.add(Tenant(name="acme"))
    with db.session() as session:
        assert session.scalars(select(Tenant.name)).all() == ["acme"]


def test_session_rolls_back_on_error(db: Database) -> None:
    with pytest.raises(RuntimeError, match="boom"), db.session() as session:
        session.add(Tenant(name="ghost"))
        session.flush()
        raise RuntimeError("boom")
    with db.session() as session:
        assert session.scalars(select(Tenant)).all() == []


def test_tenant_session_sets_tenant_context(db: Database) -> None:
    tenant_id = uuid.uuid4()
    with db.tenant_session(tenant_id) as session:
        assert session.scalar(CURRENT_TENANT) == str(tenant_id)


def test_tenant_context_does_not_leak_to_next_transaction(
    settings: Settings, clean_db: None
) -> None:
    database = Database(settings.database_url, pool_size=1, max_overflow=0)
    try:
        with database.tenant_session(uuid.uuid4()):
            pass
        with database.session() as session:  # same pooled connection
            assert session.scalar(CURRENT_TENANT) in (None, "")
    finally:
        database.dispose()


def test_ping_succeeds_against_test_database(db: Database) -> None:
    assert db.ping() is True


def test_ping_fails_when_database_unreachable(offline_settings: Settings) -> None:
    database = Database(offline_settings.database_url)
    try:
        assert database.ping() is False
    finally:
        database.dispose()
