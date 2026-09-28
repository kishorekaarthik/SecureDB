import uuid

import pytest
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from tests.helpers import set_tenant


def _insert_tenant(conn: Connection, name: str) -> uuid.UUID:
    tenant_id: uuid.UUID = conn.execute(
        text("INSERT INTO tenants (name) VALUES (:name) RETURNING id"), {"name": name}
    ).scalar_one()
    return tenant_id


def _insert_key(conn: Connection, tenant_id: uuid.UUID, version: int, status: str) -> None:
    conn.execute(
        text(
            "INSERT INTO tenant_keys (tenant_id, version, wrapped_dek, provider, "
            "provider_key_id, status) VALUES (:t, :v, :w, 'local', 'mk_test', :s)"
        ),
        {"t": tenant_id, "v": version, "w": b"wrapped", "s": status},
    )


@pytest.fixture
def two_tenants(app_engine: Engine) -> tuple[uuid.UUID, uuid.UUID]:
    with app_engine.begin() as conn:
        first = _insert_tenant(conn, "acme")
        second = _insert_tenant(conn, "globex")
    for tenant_id in (first, second):
        with app_engine.begin() as conn:
            set_tenant(conn, tenant_id)
            _insert_key(conn, tenant_id, 1, "active")
    return first, second


def test_keys_are_invisible_without_tenant_context(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    with app_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM tenant_keys")).scalar_one() == 0


def test_tenant_sees_only_its_own_keys(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    first, _ = two_tenants
    with app_engine.begin() as conn:
        set_tenant(conn, first)
        rows = conn.execute(text("SELECT tenant_id FROM tenant_keys")).scalars().all()
    assert rows == [first]


def test_cannot_insert_keys_for_another_tenant(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    first, second = two_tenants
    with pytest.raises(ProgrammingError, match="row-level security"), app_engine.begin() as conn:
        set_tenant(conn, first)
        _insert_key(conn, second, 2, "retired")


def test_only_one_active_key_per_tenant(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    first, _ = two_tenants
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        set_tenant(conn, first)
        _insert_key(conn, first, 2, "active")


def test_status_values_are_constrained(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    first, _ = two_tenants
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        set_tenant(conn, first)
        _insert_key(conn, first, 2, "bogus")


@pytest.mark.parametrize(
    "statement", ["UPDATE tenant_keys SET status = 'retired'", "DELETE FROM tenant_keys"]
)
def test_app_role_cannot_modify_existing_keys(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID], statement: str
) -> None:
    first, _ = two_tenants
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        set_tenant(conn, first)
        conn.execute(text(statement))


def test_rls_applies_to_the_table_owner_too(
    owner_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    with owner_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM tenant_keys")).scalar_one() == 0


def test_tenants_have_a_nullable_wrapped_lookup_key(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        tenant_id = _insert_tenant(conn, "acme")
        conn.execute(
            text("UPDATE tenants SET wrapped_lookup_key = :w WHERE id = :t"),
            {"w": b"wrapped", "t": tenant_id},
        )
        stored = conn.execute(
            text("SELECT wrapped_lookup_key FROM tenants WHERE id = :t"), {"t": tenant_id}
        ).scalar_one()
    assert stored == b"wrapped"
