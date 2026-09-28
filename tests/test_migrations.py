import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from securedb.db.models import Base


def test_app_role_can_insert_and_read_tenants(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (name) VALUES ('acme')"))
    with app_engine.connect() as conn:
        row = conn.execute(text("SELECT id, name, created_at FROM tenants")).one()
    assert row.name == "acme"
    assert row.id is not None
    assert row.created_at is not None


def test_tenant_names_are_unique(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (name) VALUES ('acme')"))
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (name) VALUES ('acme')"))


def test_app_role_cannot_delete_tenants(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (name) VALUES ('acme')"))
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text("DELETE FROM tenants"))


def test_app_role_cannot_create_tables(app_engine: Engine) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text("CREATE TABLE evil (id int)"))


def test_models_match_migrations(owner_engine: Engine) -> None:
    with owner_engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
