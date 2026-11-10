import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import structlog
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError

from securedb.audit.log import (
    GENESIS_HASH,
    Actor,
    AuditRecord,
    append,
    canonical_entry,
    list_entries,
    verify,
)
from securedb.db.models import Tenant
from securedb.db.session import Database
from tests.helpers import set_tenant

CLI = Actor.system("cli")


@pytest.fixture
def tenant(db: Database) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    with db.session() as session:
        session.add(Tenant(id=tenant_id, name="acme"))
    return tenant_id


def _append(db: Database, tenant: uuid.UUID, action: str = "test", **kw: object) -> AuditRecord:
    with db.tenant_session(tenant) as session:
        return append(session, tenant, CLI, action, **kw)  # type: ignore[arg-type]


def _verify(db: Database, tenant: uuid.UUID):  # type: ignore[no-untyped-def]
    with db.tenant_session(tenant) as session:
        return verify(session, tenant)


def test_chain_starts_at_genesis_and_links(db: Database, tenant: uuid.UUID) -> None:
    first = _append(db, tenant, "tokenize", token_ids=["tok_pan_a"], outcome={"created": 1})
    second = _append(db, tenant, "detokenize", token_ids=["tok_pan_a"], outcome={"allowed": 1})
    assert (first.seq, second.seq) == (1, 2)
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert first.hash == hashlib.sha256(GENESIS_HASH + canonical_entry(tenant, first)).digest()


def test_records_actor_and_request_id(db: Database, tenant: uuid.UUID) -> None:
    with structlog.contextvars.bound_contextvars(request_id="req-123"):
        record = _append(db, tenant)
    assert (record.actor_type, record.actor_id, record.request_id) == ("system", "cli", "req-123")


def test_verify_accepts_an_intact_chain(db: Database, tenant: uuid.UUID) -> None:
    records = [_append(db, tenant, outcome={"n": i}) for i in range(5)]
    result = _verify(db, tenant)
    assert result.ok and result.entries == 5 and result.first_broken_seq is None
    assert result.head_hash == records[-1].hash.hex()


def test_verify_on_empty_log(db: Database, tenant: uuid.UUID) -> None:
    result = _verify(db, tenant)
    assert (result.ok, result.entries, result.head_hash) == (True, 0, None)


def test_verify_is_independent_of_session_timezone(db: Database, tenant: uuid.UUID) -> None:
    _append(db, tenant)
    with db.tenant_session(tenant) as session:
        session.execute(text("SET LOCAL TIME ZONE 'Asia/Kolkata'"))
        assert verify(session, tenant).ok


@pytest.mark.parametrize(
    ("statement", "broken_seq"),
    [
        ("UPDATE audit_log SET outcome = '{\"n\": 99}' WHERE seq = 2", 2),
        ("UPDATE audit_log SET actor_id = 'someone-else' WHERE seq = 3", 3),
        ("DELETE FROM audit_log WHERE seq = 2", 2),
        ("UPDATE audit_log SET ts = ts + interval '1 second' WHERE seq = 1", 1),
    ],
)
def test_verify_detects_tampering(
    db: Database, tenant: uuid.UUID, owner_engine: Engine, statement: str, broken_seq: int
) -> None:
    for i in range(4):
        _append(db, tenant, outcome={"n": i})
    with owner_engine.begin() as conn:  # only the table owner can rewrite history
        set_tenant(conn, tenant)
        conn.execute(text(statement))
    result = _verify(db, tenant)
    assert result.ok is False
    assert result.first_broken_seq == broken_seq


@pytest.mark.parametrize(
    "statement", ["UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log"]
)
def test_app_role_cannot_rewrite_history(
    db: Database, tenant: uuid.UUID, app_engine: Engine, statement: str
) -> None:
    _append(db, tenant)
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        set_tenant(conn, tenant)
        conn.execute(text(statement))


def test_other_tenants_cannot_read_the_log(db: Database, tenant: uuid.UUID) -> None:
    _append(db, tenant)
    other = uuid.uuid4()
    with db.session() as session:
        session.add(Tenant(id=other, name="globex"))
    with db.tenant_session(other) as session:
        assert list_entries(session, tenant) == []


def test_concurrent_appends_stay_contiguous(db: Database, tenant: uuid.UUID) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: _append(db, tenant, outcome={"n": i}), range(40)))
    result = _verify(db, tenant)
    assert result.ok and result.entries == 40


def test_list_entries_paginates_and_filters(db: Database, tenant: uuid.UUID) -> None:
    for i in range(6):
        _append(db, tenant, "tokenize" if i % 2 == 0 else "detokenize")
    with db.tenant_session(tenant) as session:
        page1 = list_entries(session, tenant, limit=2)
        page2 = list_entries(session, tenant, after_seq=page1[-1].seq, limit=2)
        tokenizes = list_entries(session, tenant, action="tokenize")
    assert [r.seq for r in page1] == [1, 2]
    assert [r.seq for r in page2] == [3, 4]
    assert [r.seq for r in tokenizes] == [1, 3, 5]


def test_outcome_values_must_be_json_scalars_lists_or_dicts(
    db: Database, tenant: uuid.UUID
) -> None:
    with pytest.raises(TypeError):
        _append(db, tenant, outcome={"bad": object()})
