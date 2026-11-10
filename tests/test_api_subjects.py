import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from securedb.app import create_app
from securedb.audit.log import Actor
from securedb.config import Settings
from securedb.crypto.local import LocalKeyProvider
from securedb.db.session import Database
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import Scope, issue_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType

TEST = Actor.system("test")
PAN = "ABCDE1234F"


@pytest.fixture
def ctx(
    settings: Settings, key_provider: LocalKeyProvider, clean_db: None
) -> Iterator[tuple[TestClient, Database, uuid.UUID]]:
    app = create_app(settings, Database(settings.database_url), key_provider)
    tenant = create_tenant(app.state.db, app.state.keyring, "acme", actor=TEST)
    yield TestClient(app), app.state.db, tenant
    app.state.db.dispose()


def _headers(db: Database, tenant: uuid.UUID, *scopes: Scope) -> dict[str, str]:
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", [Scope.tokenize, *scopes], actor=TEST)
        set_policy(
            session, tenant, issued.id, FieldType.pan, Action.tokenize, Effect.allow, actor=TEST
        )
        set_policy(
            session, tenant, issued.id, FieldType.pan, Action.detokenize, Effect.mask, actor=TEST
        )
    return {"Authorization": f"Bearer {issued.plaintext}"}


def _tokenize(client: TestClient, headers: dict[str, str], subject: str) -> str:
    body = {"items": [{"type": "pan", "value": PAN, "subject_id": subject}]}
    token: str = client.post("/v1/tokens", json=body, headers=headers).json()["items"][0]["token"]
    return token


def test_export_then_erase(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    headers = _headers(db, tenant, Scope.subjects_export, Scope.subjects_erase)
    token = _tokenize(client, headers, "cust-42")

    export = client.get("/v1/subjects/cust-42/export", headers=headers)
    assert export.status_code == 200
    body = export.json()
    assert len(body["subject_ref"]) == 64
    [item] = body["tokens"]
    assert item["token"] == token and item["type"] == "pan"
    assert (item["value"], item["masked"], item["shared"]) == ("XXXXXX234F", True, False)
    assert [h["action"] for h in body["history"]] == ["tokenize"]

    erased = client.delete("/v1/subjects/cust-42", headers=headers)
    assert erased.status_code == 200
    assert erased.json() == {"deleted": 1, "retained_shared": 0}
    assert client.get("/v1/subjects/cust-42/export", headers=headers).json()["tokens"] == []


def test_scopes_are_enforced(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    headers = _headers(db, tenant)
    assert client.get("/v1/subjects/cust-42/export", headers=headers).status_code == 403
    assert client.delete("/v1/subjects/cust-42", headers=headers).status_code == 403


@pytest.mark.parametrize("subject", ["has%20space", "x" * 129, "semi;colon"])
def test_malformed_subject_ids_are_422(
    ctx: tuple[TestClient, Database, uuid.UUID], subject: str
) -> None:
    client, db, tenant = ctx
    headers = _headers(db, tenant, Scope.subjects_export, Scope.subjects_erase)
    assert client.get(f"/v1/subjects/{subject}/export", headers=headers).status_code == 422
    assert client.delete(f"/v1/subjects/{subject}", headers=headers).status_code == 422


def test_unknown_subject_is_an_empty_result(ctx: tuple[TestClient, Database, uuid.UUID]) -> None:
    client, db, tenant = ctx
    headers = _headers(db, tenant, Scope.subjects_export, Scope.subjects_erase)
    assert client.delete("/v1/subjects/nobody", headers=headers).json() == {
        "deleted": 0,
        "retained_shared": 0,
    }
    assert client.get("/v1/subjects/nobody/export", headers=headers).json()["tokens"] == []
