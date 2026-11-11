from fastapi.testclient import TestClient

from securedb.app import create_app
from securedb.config import Settings
from securedb.crypto.local import LocalKeyProvider, LockedKeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.session import Database


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings, Database(settings.database_url)))


def test_docs_available_in_dev(offline_settings: Settings) -> None:
    client = _client(offline_settings.model_copy(update={"env": "dev"}))
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_docs_hidden_outside_dev(offline_settings: Settings) -> None:
    client = _client(offline_settings)  # env="test"
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_app_state_is_wired(offline_settings: Settings, key_provider: LocalKeyProvider) -> None:
    database = Database(offline_settings.database_url)
    app = create_app(offline_settings, database, key_provider)
    assert app.state.settings is offline_settings
    assert app.state.db is database
    assert app.state.key_provider is key_provider
    assert isinstance(app.state.keyring, KeyRing)
    assert [name for name, _ in app.state.readiness_checks] == ["database", "key_provider"]


def test_app_without_master_key_starts_locked(offline_settings: Settings) -> None:
    app = create_app(offline_settings, Database(offline_settings.database_url))
    assert isinstance(app.state.key_provider, LockedKeyProvider)
    assert "securedb init" in app.state.key_provider.reason
