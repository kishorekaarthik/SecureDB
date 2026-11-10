import uuid

import pytest
from sqlalchemy import Engine, text

from securedb.audit.log import Actor
from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import ApiKey
from securedb.db.session import Database
from securedb.errors import NotFound, Unauthorized
from securedb.tenants.api_keys import (
    AuthenticatedKey,
    IssuedKey,
    Scope,
    authenticate,
    issue_api_key,
    revoke_api_key,
)
from tests.helpers import create_tenant_with_keys, set_tenant


@pytest.fixture
def tenant(db: Database, key_provider: LocalKeyProvider) -> uuid.UUID:
    return create_tenant_with_keys(db, KeyRing(key_provider), "acme")


def _issue(db: Database, tenant_id: uuid.UUID, *scopes: Scope) -> IssuedKey:
    with db.tenant_session(tenant_id) as session:
        return issue_api_key(
            session,
            tenant_id,
            "billing-service",
            scopes or (Scope.tokenize,),
            actor=Actor.system("test"),
        )


def test_issue_then_authenticate(db: Database, tenant: uuid.UUID) -> None:
    issued = _issue(db, tenant, Scope.detokenize, Scope.tokenize, Scope.tokenize)
    assert issued.plaintext.startswith(f"sdb_live_{issued.prefix}_")
    key = authenticate(db, f"Bearer {issued.plaintext}")
    assert key == AuthenticatedKey(
        id=issued.id, tenant_id=tenant, scopes=frozenset({"tokenize", "detokenize"})
    )
    assert key.allows(Scope.detokenize)
    assert not key.allows(Scope.audit_read)


def test_only_a_hash_of_the_secret_is_stored(
    db: Database, tenant: uuid.UUID, owner_engine: Engine
) -> None:
    issued = _issue(db, tenant)
    secret = issued.plaintext.rsplit("_", 1)[1]
    with owner_engine.begin() as conn:
        set_tenant(conn, tenant)
        row = conn.execute(text("SELECT prefix, secret_hash FROM api_keys")).one()
    assert row.prefix == issued.prefix
    assert secret.encode() not in row.secret_hash
    assert len(row.secret_hash) == 32


def test_authentication_records_last_use(db: Database, tenant: uuid.UUID) -> None:
    issued = _issue(db, tenant)
    authenticate(db, f"Bearer {issued.plaintext}")
    with db.tenant_session(tenant) as session:
        stored = session.get(ApiKey, issued.id)
        assert stored is not None and stored.last_used_at is not None


def _wrong_secret(issued: IssuedKey) -> str:
    return f"sdb_live_{issued.prefix}_{'A' * 32}"


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer not-a-key",
        "Bearer sdb_live_short_secret",
        "Bearer sdb_live_ZZZZZZZZZZZZ_" + "B" * 32,
        "WRONG_SECRET",
    ],
)
def test_bad_credentials_are_rejected_identically(
    db: Database, tenant: uuid.UUID, header: str | None
) -> None:
    issued = _issue(db, tenant)
    if header == "WRONG_SECRET":
        header = f"Bearer {_wrong_secret(issued)}"
    with pytest.raises(Unauthorized) as exc_info:
        authenticate(db, header)
    assert str(exc_info.value) == "Invalid or missing API key."


def test_revoked_keys_are_rejected(db: Database, tenant: uuid.UUID) -> None:
    issued = _issue(db, tenant)
    with db.tenant_session(tenant) as session:
        revoke_api_key(session, issued.id, actor=Actor.system("test"))
    with pytest.raises(Unauthorized):
        authenticate(db, f"Bearer {issued.plaintext}")


def test_cannot_revoke_another_tenants_key(
    db: Database, tenant: uuid.UUID, key_provider: LocalKeyProvider
) -> None:
    other = create_tenant_with_keys(db, KeyRing(key_provider), "globex")
    issued = _issue(db, tenant)
    with db.tenant_session(other) as session, pytest.raises(NotFound):
        revoke_api_key(session, issued.id, actor=Actor.system("test"))
    assert authenticate(db, f"Bearer {issued.plaintext}").tenant_id == tenant


def test_issued_key_repr_hides_the_secret(db: Database, tenant: uuid.UUID) -> None:
    issued = _issue(db, tenant)
    assert issued.plaintext not in repr(issued)
