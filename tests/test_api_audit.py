import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from securedb.app import create_app
from securedb.audit.log import Actor
from securedb.config import Settings
from securedb.crypto.local import LocalKeyProvider
from securedb.db.session import Database
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import Scope, issue_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType
from tests.helpers import set_tenant

PAN = "ABCDE1234F"


@pytest.fixture
def ctx(
    settings: Settings, key_provider: LocalKeyProvider, clean_db: None
) -> Iterator[tuple[TestClient, Database, uuid.UUID]]:
    app = create_app(settings, Database(settings.database_url), key_provider)
    tenant = create_tenant(app.state.db, app.state.keyring, "acme", actor=Actor.system("test"))
    yield TestClient(app), app.state.db, tenant
    app.state.db.dispose()


def _key(db: Database, tenant: uuid.UUID, *scopes: Scope) -> dict[str, str]:
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", scopes, actor=Actor.system("test"))
        set_policy(
            session,
            tenant,
            issued.id,
            FieldType.pan,
            Action.tokenize,
            Effect.allow,
            actor=Actor.system("test"),
        )
    return {"Authorization": f"Bearer {issued.plaintext}"}


def test_list_requires_audit_scope(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    assert client.get("/v1/audit", headers=_key(db, tenant, Scope.tokenize)).status_code == 403
    assert (
        client.get("/v1/audit/verify", headers=_key(db, tenant, Scope.tokenize)).status_code == 403
    )


def test_list_paginates_with_cursor(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    headers = _key(db, tenant, Scope.audit_read)  # tenant.create, api_key.create, policy.set
    first = client.get("/v1/audit", params={"limit": 2}, headers=headers).json()
    assert [e["seq"] for e in first["items"]] == [1, 2]
    assert first["next_cursor"] == 2
    second = client.get(
        "/v1/audit", params={"limit": 2, "cursor": first["next_cursor"]}, headers=headers
    ).json()
    assert [e["seq"] for e in second["items"]] == [3]
    assert second["next_cursor"] is None
    entry = first["items"][0]
    assert entry["action"] == "tenant.create"
    assert len(entry["hash"]) == 64 and len(entry["prev_hash"]) == 64


def test_list_filters_by_action(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    headers = _key(db, tenant, Scope.audit_read, Scope.tokenize)
    for _ in range(2):
        client.post("/v1/tokens", json={"items": [{"type": "pan", "value": PAN}]}, headers=headers)
    items = client.get("/v1/audit", params={"action": "tokenize"}, headers=headers).json()["items"]
    assert [e["action"] for e in items] == ["tokenize", "tokenize"]
    assert all(PAN not in str(e) for e in items)


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 201},
        {"cursor": -1},
        {"action": "DROP TABLE"},
        {"from": "2026-01-01T00:00:00"},
    ],
)
def test_bad_query_parameters_are_422(
    ctx: tuple[TestClient, Database, uuid.UUID], params: dict[str, object]
) -> None:
    client, db, tenant = ctx
    response = client.get("/v1/audit", params=params, headers=_key(db, tenant, Scope.audit_read))
    assert response.status_code == 422


def test_list_filters_by_time(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    headers = _key(db, tenant, Scope.audit_read)
    future = client.get("/v1/audit", params={"from": "2999-01-01T00:00:00Z"}, headers=headers)
    assert future.json()["items"] == []
    past = client.get("/v1/audit", params={"to": "2000-01-01T00:00:00Z"}, headers=headers)
    assert past.json()["items"] == []


def test_verify_reports_ok_and_breaks(
    ctx: tuple[TestClient, Database, uuid.UUID], owner_engine: Engine
) -> None:
    client, db, tenant = ctx
    headers = _key(db, tenant, Scope.audit_read)
    ok = client.get("/v1/audit/verify", headers=headers).json()
    assert ok["ok"] is True and ok["entries"] == 3 and ok["first_broken_seq"] is None
    with owner_engine.begin() as conn:
        set_tenant(conn, tenant)
        conn.execute(text("UPDATE audit_log SET action = 'tampered' WHERE seq = 2"))
    broken = client.get("/v1/audit/verify", headers=headers).json()
    assert (broken["ok"], broken["entries"], broken["first_broken_seq"]) == (False, 1, 2)
    assert len(broken["head_hash"]) == 64  # hash of the last intact entry


def test_verify_accepts_an_external_anchor(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    headers = _key(db, tenant, Scope.audit_read)
    head = client.get("/v1/audit/verify", headers=headers).json()
    good = {"anchor_seq": head["entries"], "anchor_hash": head["head_hash"]}
    assert client.get("/v1/audit/verify", params=good, headers=headers).json()["ok"] is True
    bad = {"anchor_seq": head["entries"], "anchor_hash": "0" * 64}
    result = client.get("/v1/audit/verify", params=bad, headers=headers).json()
    assert (result["ok"], result["first_broken_seq"]) == (False, head["entries"])


@pytest.mark.parametrize(
    "params",
    [
        {"anchor_seq": 1},
        {"anchor_hash": "0" * 64},
        {"anchor_seq": 0, "anchor_hash": "0" * 64},
        {"anchor_seq": 1, "anchor_hash": "XYZ"},
    ],
)
def test_anchor_parameters_are_validated(
    ctx: tuple[TestClient, Database, uuid.UUID], params: dict[str, object]
) -> None:
    client, db, tenant = ctx
    response = client.get(
        "/v1/audit/verify", params=params, headers=_key(db, tenant, Scope.audit_read)
    )
    assert response.status_code == 422
