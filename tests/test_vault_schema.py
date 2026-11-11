import uuid

import pytest
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from tests.helpers import set_tenant


def _tenant(conn: Connection, name: str) -> uuid.UUID:
    tenant_id: uuid.UUID = conn.execute(
        text("INSERT INTO tenants (name) VALUES (:n) RETURNING id"), {"n": name}
    ).scalar_one()
    return tenant_id


def _api_key(conn: Connection, tenant_id: uuid.UUID, prefix: str) -> uuid.UUID:
    set_tenant(conn, tenant_id)
    key_id: uuid.UUID = conn.execute(
        text(
            "INSERT INTO api_keys (tenant_id, prefix, secret_hash, name, scopes) "
            "VALUES (:t, :p, :h, 'svc', ARRAY['tokenize']) RETURNING id"
        ),
        {"t": tenant_id, "p": prefix, "h": b"hash"},
    ).scalar_one()
    return key_id


def _token(conn: Connection, tenant_id: uuid.UUID, token: str, lookup: bytes) -> None:
    set_tenant(conn, tenant_id)
    conn.execute(
        text(
            "INSERT INTO tokens (token, tenant_id, type, lookup_hmac, ciphertext, nonce, "
            "key_version) VALUES (:tok, :t, 'pan', :l, :c, :n, 1)"
        ),
        {"tok": token, "t": tenant_id, "l": lookup, "c": b"ct", "n": b"n" * 12},
    )


@pytest.fixture
def world(app_engine: Engine) -> dict[str, uuid.UUID]:
    with app_engine.begin() as conn:
        a = _tenant(conn, "acme")
        b = _tenant(conn, "globex")
    with app_engine.begin() as conn:
        key_a = _api_key(conn, a, "prefixAAAAAA")
    with app_engine.begin() as conn:
        key_b = _api_key(conn, b, "prefixBBBBBB")
    with app_engine.begin() as conn:
        _token(conn, a, "tok_pan_a", b"lookup-a")
    with app_engine.begin() as conn:
        _token(conn, b, "tok_pan_b", b"lookup-b")
    return {"a": a, "b": b, "key_a": key_a, "key_b": key_b}


def _count(conn: Connection, table: str) -> int:
    count: int = conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
    return count


@pytest.mark.parametrize("table", ["api_keys", "policies", "tokens", "token_subjects"])
def test_tables_are_invisible_without_tenant_context(
    app_engine: Engine, world: dict[str, uuid.UUID], table: str
) -> None:
    with app_engine.connect() as conn:
        assert _count(conn, table) == 0


def test_tenant_sees_only_its_own_tokens(app_engine: Engine, world: dict[str, uuid.UUID]) -> None:
    with app_engine.begin() as conn:
        set_tenant(conn, world["a"])
        assert conn.execute(text("SELECT token FROM tokens")).scalars().all() == ["tok_pan_a"]


def test_auth_lookup_sees_exactly_the_presented_prefix(
    app_engine: Engine, world: dict[str, uuid.UUID]
) -> None:
    with app_engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.api_key_prefix', 'prefixAAAAAA', true)"))
        rows = conn.execute(text("SELECT id FROM api_keys")).scalars().all()
    assert rows == [world["key_a"]]


def test_auth_lookup_with_unknown_prefix_sees_nothing(
    app_engine: Engine, world: dict[str, uuid.UUID]
) -> None:
    with app_engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.api_key_prefix', 'nope', true)"))
        assert _count(conn, "api_keys") == 0


def test_auth_lookup_cannot_update_keys(app_engine: Engine, world: dict[str, uuid.UUID]) -> None:
    with app_engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.api_key_prefix', 'prefixAAAAAA', true)"))
        result = conn.execute(text("UPDATE api_keys SET name = 'hijacked'"))
    assert result.rowcount == 0


def test_token_dedup_is_unique_per_tenant_and_type(
    app_engine: Engine, world: dict[str, uuid.UUID]
) -> None:
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        _token(conn, world["a"], "tok_pan_dup", b"lookup-a")
    with app_engine.begin() as conn:  # same lookup in another tenant is fine
        _token(conn, world["b"], "tok_pan_other", b"lookup-a")


def test_tokenize_policies_cannot_mask(app_engine: Engine, world: dict[str, uuid.UUID]) -> None:
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        set_tenant(conn, world["a"])
        conn.execute(
            text(
                "INSERT INTO policies (tenant_id, api_key_id, field_type, action, effect) "
                "VALUES (:t, :k, 'pan', 'tokenize', 'mask')"
            ),
            {"t": world["a"], "k": world["key_a"]},
        )


@pytest.mark.parametrize(
    "statement",
    ["UPDATE tokens SET type = 'email'", "DELETE FROM api_keys"],
)
def test_app_role_cannot_rewrite_tokens_or_delete_keys(
    app_engine: Engine, world: dict[str, uuid.UUID], statement: str
) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        set_tenant(conn, world["a"])
        conn.execute(text(statement))
