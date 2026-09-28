from fastapi.testclient import TestClient

from securedb.app import create_app
from securedb.config import Settings
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


def test_app_state_is_wired(offline_settings: Settings) -> None:
    database = Database(offline_settings.database_url)
    app = create_app(offline_settings, database)
    assert app.state.settings is offline_settings
    assert app.state.db is database
    assert [name for name, _ in app.state.readiness_checks] == ["database"]
