import json
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from securedb.app import create_app
from securedb.audit.log import Actor, AuditRecord, list_entries, verify
from securedb.config import Settings
from securedb.crypto.local import LocalKeyProvider
from securedb.db.session import Database
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import Scope, issue_api_key, revoke_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType

PAN = "ABCDE1234F"


@pytest.fixture
def app_and_tenant(
    settings: Settings, key_provider: LocalKeyProvider, clean_db: None
) -> Iterator[tuple[TestClient, Database, uuid.UUID]]:
    app = create_app(settings, Database(settings.database_url), key_provider)
    tenant = create_tenant(app.state.db, app.state.keyring, "acme", actor=Actor.system("test"))
    yield TestClient(app), app.state.db, tenant
    app.state.db.dispose()


def _entries(db: Database, tenant: uuid.UUID) -> list[AuditRecord]:
    with db.tenant_session(tenant) as session:
        return list_entries(session, tenant, limit=200)


def _key(db: Database, tenant: uuid.UUID, *policies: tuple[FieldType, Action, Effect]) -> str:
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(
            session,
            tenant,
            "svc",
            [Scope.tokenize, Scope.detokenize, Scope.subjects_erase],
            actor=Actor.system("test"),
        )
        for field_type, action, effect in policies:
            set_policy(
                session, tenant, issued.id, field_type, action, effect, actor=Actor.system("test")
            )
    return issued.plaintext


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def test_tenant_creation_is_the_first_entry(
    app_and_tenant: tuple[TestClient, Database, uuid.UUID],
) -> None:
    _, db, tenant = app_and_tenant
    [entry] = _entries(db, tenant)
    assert (entry.seq, entry.action, entry.actor_type) == (1, "tenant.create", "system")
    assert entry.outcome == {"name": "acme"}


def test_key_and_policy_changes_are_audited_without_secrets(
    app_and_tenant: tuple[TestClient, Database, uuid.UUID],
) -> None:
    _, db, tenant = app_and_tenant
    plaintext = _key(db, tenant, (FieldType.pan, Action.detokenize, Effect.mask))
    prefix = plaintext.split("_")[2]
    actions = [e.action for e in _entries(db, tenant)]
    assert actions == ["tenant.create", "api_key.create", "policy.set"]
    create, policy = _entries(db, tenant)[1:]
    assert create.outcome["prefix"] == prefix
    assert create.outcome["scopes"] == ["detokenize", "subjects:erase", "tokenize"]
    assert policy.outcome == {
        "key_id": create.outcome["key_id"],
        "field_type": "pan",
        "action": "detokenize",
        "effect": "mask",
    }
    assert plaintext.rsplit("_", 1)[1] not in json.dumps([e.outcome for e in _entries(db, tenant)])


def test_revocation_is_audited(app_and_tenant: tuple[TestClient, Database, uuid.UUID]) -> None:
    _, db, tenant = app_and_tenant
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", [Scope.tokenize], actor=Actor.system("test"))
        revoke_api_key(session, issued.id, actor=Actor.system("test"))
    last = _entries(db, tenant)[-1]
    assert (last.action, last.outcome) == ("api_key.revoke", {"key_id": str(issued.id)})


def test_token_operations_are_audited_with_ids_but_never_values(
    app_and_tenant: tuple[TestClient, Database, uuid.UUID],
) -> None:
    client, db, tenant = app_and_tenant
    key = _key(
        db,
        tenant,
        (FieldType.pan, Action.tokenize, Effect.allow),
        (FieldType.pan, Action.detokenize, Effect.mask),
        (FieldType.email, Action.tokenize, Effect.allow),
    )
    body = {"items": [{"type": "pan", "value": PAN}, {"type": "email", "value": "a@b.co"}]}
    pan, email = (
        i["token"] for i in client.post("/v1/tokens", json=body, headers=_auth(key)).json()["items"]
    )
    missing = "tok_pan_" + "m" * 22
    client.post("/v1/tokens/detokenize", json={"tokens": [pan, email, missing]}, headers=_auth(key))
    client.delete(f"/v1/tokens/{pan}", headers=_auth(key))

    tokenize, detokenize, delete = _entries(db, tenant)[-3:]
    assert tokenize.action == "tokenize" and tokenize.actor_type == "api_key"
    assert tokenize.token_ids == [pan, email]
    assert tokenize.outcome == {"items": 2, "created": 2, "types": ["email", "pan"]}
    assert detokenize.token_ids == [pan, email, missing]
    assert detokenize.outcome == {"results": ["masked", "denied", "not_found"]}
    assert (delete.action, delete.token_ids) == ("token.delete", [pan])
    dump = json.dumps([e.outcome for e in _entries(db, tenant)])
    assert PAN not in dump and "a@b.co" not in dump
    assert all(e.request_id for e in (tokenize, detokenize, delete))


def test_rejected_tokenize_is_audited_even_though_it_rolls_back(
    app_and_tenant: tuple[TestClient, Database, uuid.UUID],
) -> None:
    client, db, tenant = app_and_tenant
    key = _key(db, tenant, (FieldType.pan, Action.tokenize, Effect.allow))
    forbidden = {"items": [{"type": "email", "value": "a@b.co"}]}
    invalid = {"items": [{"type": "pan", "value": "NOTAPAN99"}]}
    assert client.post("/v1/tokens", json=forbidden, headers=_auth(key)).status_code == 403
    assert client.post("/v1/tokens", json=invalid, headers=_auth(key)).status_code == 422
    rejected = [e for e in _entries(db, tenant) if e.action == "tokenize.rejected"]
    assert [e.outcome for e in rejected] == [
        {"reason": "forbidden", "items": 1},
        {"reason": "invalid", "items": 1},
    ]
    assert "NOTAPAN99" not in json.dumps([e.outcome for e in rejected])
    assert not [e for e in _entries(db, tenant) if e.action == "tokenize"]


def test_chain_verifies_after_mixed_activity(
    app_and_tenant: tuple[TestClient, Database, uuid.UUID],
) -> None:
    client, db, tenant = app_and_tenant
    key = _key(db, tenant, (FieldType.pan, Action.tokenize, Effect.allow))
    for _ in range(3):
        client.post(
            "/v1/tokens", json={"items": [{"type": "pan", "value": PAN}]}, headers=_auth(key)
        )
    with db.tenant_session(tenant) as session:
        assert verify(session, tenant).ok
