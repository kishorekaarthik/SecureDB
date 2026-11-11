from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from securedb.app import create_app
from securedb.audit.log import Actor
from securedb.config import Settings
from securedb.crypto.local import LocalKeyProvider
from securedb.db.models import ApiKey
from securedb.db.session import Database
from securedb.errors import PROBLEM_JSON
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import Scope, issue_api_key, revoke_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType

PAN = "ABCDE1234F"
ACCOUNT = {"account_number": "123456789012", "ifsc": "HDFC0001234"}


@dataclass
class Api:
    app: FastAPI
    client: TestClient
    tenant: object

    def key(self, *scopes: Scope, policies: dict[tuple[FieldType, Action], Effect]) -> str:
        db: Database = self.app.state.db
        with db.tenant_session(self.tenant) as session:  # type: ignore[arg-type]
            issued = issue_api_key(session, self.tenant, "svc", scopes, actor=Actor.system("test"))  # type: ignore[arg-type]
            for (field_type, action), effect in policies.items():
                set_policy(
                    session,
                    self.tenant,
                    issued.id,
                    field_type,
                    action,
                    effect,
                    actor=Actor.system("test"),
                )  # type: ignore[arg-type]
        return issued.plaintext


FULL = {
    (FieldType.pan, Action.tokenize): Effect.allow,
    (FieldType.pan, Action.detokenize): Effect.allow,
    (FieldType.bank_account, Action.tokenize): Effect.allow,
    (FieldType.bank_account, Action.detokenize): Effect.mask,
}
ALL_SCOPES = (Scope.tokenize, Scope.detokenize, Scope.subjects_erase)


def _make(settings: Settings, provider: LocalKeyProvider, rate_limit: int) -> Api:
    tuned = settings.model_copy(update={"rate_limit_per_minute": rate_limit})
    app = create_app(tuned, Database(settings.database_url), provider)
    tenant = create_tenant(app.state.db, app.state.keyring, "acme", actor=Actor.system("test"))
    return Api(app, TestClient(app), tenant)


@pytest.fixture
def api(settings: Settings, key_provider: LocalKeyProvider, clean_db: None) -> Iterator[Api]:
    made = _make(settings, key_provider, rate_limit=10_000)
    yield made
    made.app.state.db.dispose()


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _tokenize(api: Api, key: str, *items: dict[str, object]) -> list[str]:
    response = api.client.post("/v1/tokens", json={"items": list(items)}, headers=_auth(key))
    assert response.status_code == 200, response.text
    return [item["token"] for item in response.json()["items"]]


def test_tokenize_then_detokenize(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    pan, account = _tokenize(
        api, key, {"type": "pan", "value": PAN}, {"type": "bank_account", "value": ACCOUNT}
    )
    response = api.client.post(
        "/v1/tokens/detokenize",
        json={"tokens": [pan, account, "tok_pan_uuuuuuuuuuuuuuuuuuuuuu"]},
        headers=_auth(key),
    )
    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {"token": pan, "value": PAN, "masked": False},
            {
                "token": account,
                "value": {"account_number": "XXXXXXXX9012", "ifsc": "HDFC0001234"},
                "masked": True,
            },
            {"token": "tok_pan_uuuuuuuuuuuuuuuuuuuuuu", "masked": False, "error": "not_available"},
        ]
    }


def test_tokenize_response_reports_creation(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    body = {"items": [{"type": "pan", "value": PAN}]}
    first = api.client.post("/v1/tokens", json=body, headers=_auth(key)).json()["items"][0]
    second = api.client.post("/v1/tokens", json=body, headers=_auth(key)).json()["items"][0]
    assert (first["created"], second["created"]) == (True, False)
    assert first["token"] == second["token"]
    assert first["type"] == "pan"


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer sdb_live_xxxxxxxxxxxx_" + "y" * 32}]
)
def test_missing_or_bad_key_is_401(api: Api, headers: dict[str, str]) -> None:
    response = api.client.post("/v1/tokens", json={"items": []}, headers=headers)
    assert response.status_code == 401
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.headers["www-authenticate"] == "Bearer"


def test_revoked_key_is_401(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    prefix = key.split("_")[2]
    db: Database = api.app.state.db
    with db.tenant_session(api.tenant) as session:  # type: ignore[arg-type]
        key_id = session.scalar(select(ApiKey.id).where(ApiKey.prefix == prefix))
        assert key_id is not None
        revoke_api_key(session, key_id, actor=Actor.system("test"))
    response = api.client.post(
        "/v1/tokens", json={"items": [{"type": "pan", "value": PAN}]}, headers=_auth(key)
    )
    assert response.status_code == 401


def test_missing_scope_is_403(api: Api) -> None:
    key = api.key(Scope.tokenize, policies=FULL)
    response = api.client.post(
        "/v1/tokens/detokenize",
        json={"tokens": ["tok_pan_xxxxxxxxxxxxxxxxxxxxxx"]},
        headers=_auth(key),
    )
    assert response.status_code == 403
    assert "detokenize" in response.json()["detail"]


def test_missing_policy_is_403(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies={})
    response = api.client.post(
        "/v1/tokens", json={"items": [{"type": "pan", "value": PAN}]}, headers=_auth(key)
    )
    assert response.status_code == 403


def test_invalid_value_is_422_without_echo(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    response = api.client.post(
        "/v1/tokens", json={"items": [{"type": "pan", "value": "SECRET99X"}]}, headers=_auth(key)
    )
    assert response.status_code == 422
    assert response.headers["content-type"] == PROBLEM_JSON
    assert "SECRET99X" not in response.text


@pytest.mark.parametrize("count", [0, 101])
def test_batch_size_limits(api: Api, count: int) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    items = [{"type": "pan", "value": PAN}] * count
    assert (
        api.client.post("/v1/tokens", json={"items": items}, headers=_auth(key)).status_code == 422
    )
    tokens = ["tok_pan_xxxxxxxxxxxxxxxxxxxxxx"] * count
    response = api.client.post("/v1/tokens/detokenize", json={"tokens": tokens}, headers=_auth(key))
    assert response.status_code == 422


def test_unknown_field_type_is_422_without_echo(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    response = api.client.post(
        "/v1/tokens",
        json={"items": [{"type": "passport", "value": "Z1234567"}]},
        headers=_auth(key),
    )
    assert response.status_code == 422
    assert "Z1234567" not in response.text


def test_delete_token(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    [pan] = _tokenize(api, key, {"type": "pan", "value": PAN})
    assert api.client.delete(f"/v1/tokens/{pan}", headers=_auth(key)).status_code == 204
    assert api.client.delete(f"/v1/tokens/{pan}", headers=_auth(key)).status_code == 404
    response = api.client.post("/v1/tokens/detokenize", json={"tokens": [pan]}, headers=_auth(key))
    assert response.json()["items"][0]["error"] == "not_available"


def test_delete_requires_erase_scope(api: Api) -> None:
    key = api.key(Scope.tokenize, Scope.detokenize, policies=FULL)
    [pan] = _tokenize(api, key, {"type": "pan", "value": PAN})
    assert api.client.delete(f"/v1/tokens/{pan}", headers=_auth(key)).status_code == 403


def test_rate_limit_returns_429_with_retry_after(
    settings: Settings, key_provider: LocalKeyProvider, clean_db: None
) -> None:
    limited = _make(settings, key_provider, rate_limit=2)
    try:
        key = limited.key(*ALL_SCOPES, policies=FULL)
        body = {"items": [{"type": "pan", "value": PAN}]}
        for _ in range(2):
            assert (
                limited.client.post("/v1/tokens", json=body, headers=_auth(key)).status_code == 200
            )
        response = limited.client.post("/v1/tokens", json=body, headers=_auth(key))
        assert response.status_code == 429
        assert int(response.headers["retry-after"]) >= 1
    finally:
        limited.app.state.db.dispose()


@pytest.mark.parametrize(
    "token", ["tok_pan_has\u0000nul000000000000", "not-a-token", "tok_pan_short", "x" * 129]
)
def test_malformed_tokens_are_422(api: Api, token: str) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    response = api.client.post(
        "/v1/tokens/detokenize", json={"tokens": [token]}, headers=_auth(key)
    )
    assert response.status_code == 422


@pytest.mark.parametrize("path", ["tok_pan_has%00nul000000000000", "not-a-token"])
def test_malformed_token_in_delete_path_is_422(api: Api, path: str) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    assert api.client.delete(f"/v1/tokens/{path}", headers=_auth(key)).status_code == 422


@pytest.mark.parametrize("subject", ["cust\u000042", "", "x" * 129, "has space"])
def test_malformed_subject_ids_are_422(api: Api, subject: str) -> None:
    key = api.key(*ALL_SCOPES, policies=FULL)
    item = {"type": "pan", "value": PAN, "subject_id": subject}
    response = api.client.post("/v1/tokens", json={"items": [item]}, headers=_auth(key))
    assert response.status_code == 422


def test_lone_surrogate_value_is_422_not_500(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies={(FieldType.generic, Action.tokenize): Effect.allow})
    raw = b'{"items": [{"type": "generic", "value": "\\ud800"}]}'  # escaped lone surrogate
    response = api.client.post(
        "/v1/tokens", content=raw, headers={**_auth(key), "Content-Type": "application/json"}
    )
    assert response.status_code == 422


def test_oversized_value_is_422(api: Api) -> None:
    key = api.key(*ALL_SCOPES, policies={(FieldType.generic, Action.tokenize): Effect.allow})
    item = {"type": "generic", "value": "x" * 4097}
    response = api.client.post("/v1/tokens", json={"items": [item]}, headers=_auth(key))
    assert response.status_code == 422
    assert "xxxx" not in response.text


def test_oversized_body_is_rejected_before_authentication(api: Api) -> None:
    body = b'{"items": [{"type": "generic", "value": "' + b"x" * (2 * 1024 * 1024) + b'"}]}'
    response = api.client.post(
        "/v1/tokens", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["request_id"] == response.headers["X-Request-ID"]


def test_oversized_chunked_body_is_rejected(api: Api) -> None:
    def chunks():  # no Content-Length: streamed with chunked transfer encoding
        yield b'{"items": [{"type": "generic", "value": "'
        for _ in range(64):
            yield b"x" * 32_768
        yield b'"}]}'

    response = api.client.post(
        "/v1/tokens", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
