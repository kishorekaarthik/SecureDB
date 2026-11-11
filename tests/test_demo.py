from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from securedb import cli
from securedb.app import create_app
from securedb.audit.log import verify
from securedb.config import Settings
from securedb.console import auth
from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.provider import KeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.session import Database
from securedb.demo import DEMO_TENANTS, seed_demo
from securedb.errors import Conflict

PASSWORD = "correct horse battery staple"


@pytest.fixture
def database(settings: Settings, clean_db: None) -> Iterator[Database]:
    database = Database(settings.database_url)
    yield database
    database.dispose()


def _client(settings: Settings, database: Database, provider: LocalKeyProvider) -> TestClient:
    return TestClient(create_app(settings, database, provider))


def test_seed_creates_two_isolated_tenants_with_working_keys(
    settings: Settings, database: Database, key_provider: LocalKeyProvider
) -> None:
    result = seed_demo(database, KeyRing(key_provider), PASSWORD)
    assert [t.name for t in result.tenants] == list(DEMO_TENANTS)
    client = _client(settings, database, key_provider)
    first, second = result.tenants

    # The backend key sees full values; the support key sees the same tokens masked.
    tokens = first.sample_tokens
    assert len(tokens) >= 4
    full = client.post(
        "/v1/tokens/detokenize",
        json={"tokens": tokens},
        headers={"Authorization": f"Bearer {first.backend_key}"},
    ).json()["items"]
    masked = client.post(
        "/v1/tokens/detokenize",
        json={"tokens": tokens},
        headers={"Authorization": f"Bearer {first.support_key}"},
    ).json()["items"]
    assert all(item["masked"] is False and "value" in item for item in full)
    assert all(item["masked"] is True for item in masked)
    assert [i["value"] for i in full] != [i["value"] for i in masked]

    # The other tenant's key cannot see any of them.
    other = client.post(
        "/v1/tokens/detokenize",
        json={"tokens": tokens},
        headers={"Authorization": f"Bearer {second.backend_key}"},
    ).json()["items"]
    assert all(item.get("error") == "not_available" for item in other)


def test_seed_creates_console_owners_and_intact_audit_chains(
    database: Database, key_provider: LocalKeyProvider
) -> None:
    result = seed_demo(database, KeyRing(key_provider), PASSWORD)
    for tenant in result.tenants:
        assert tenant.totp_uri.startswith("otpauth://totp/")
        assert auth.check_password(database, tenant.name, tenant.console_email, PASSWORD)
        with database.tenant_session(tenant.id) as session:
            assert verify(session, tenant.id).ok


def test_seed_refuses_to_run_twice(database: Database, key_provider: LocalKeyProvider) -> None:
    seed_demo(database, KeyRing(key_provider), PASSWORD)
    with pytest.raises(Conflict):
        seed_demo(database, KeyRing(key_provider), PASSWORD)


def test_seed_demo_command(
    monkeypatch: pytest.MonkeyPatch, database: Database, key_provider: LocalKeyProvider
) -> None:
    def fake_open() -> tuple[Database, KeyProvider]:
        return database, key_provider

    monkeypatch.setattr(cli, "_open", fake_open)
    result = CliRunner().invoke(cli.app, ["seed-demo"], input=f"{PASSWORD}\n{PASSWORD}\n")
    assert result.exit_code == 0, result.output
    for name in DEMO_TENANTS:
        assert name in result.output
    assert result.output.count("sdb_live_") == 4
    assert result.output.count("otpauth://") == 2
    assert PASSWORD not in result.output
