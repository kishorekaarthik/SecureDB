from fastapi.testclient import TestClient

from securedb.app import create_app
from securedb.config import Settings
from securedb.db.session import Database


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings, Database(settings.database_url)))


def test_healthz_is_ok_without_database(offline_settings: Settings) -> None:
    response = _client(offline_settings).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_ready_when_database_reachable(settings: Settings) -> None:
    response = _client(settings).get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": True}}


def test_app_starts_and_reports_not_ready_when_database_down(
    offline_settings: Settings,
) -> None:
    client = _client(offline_settings)
    assert client.get("/healthz").status_code == 200
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "checks": {"database": False}}


def test_readyz_treats_raising_check_as_not_ready(offline_settings: Settings) -> None:
    app = create_app(offline_settings, Database(offline_settings.database_url))

    def exploding_check() -> bool:
        raise RuntimeError("provider exploded")

    app.state.readiness_checks = [("database", lambda: True), ("boom", exploding_check)]
    response = TestClient(app).get("/readyz")
    assert response.status_code == 503
    assert response.json()["checks"] == {"database": True, "boom": False}
    assert "exploded" not in response.text
