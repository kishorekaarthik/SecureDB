import re

import pytest
from fastapi.testclient import TestClient

from securedb.app import create_app
from securedb.config import Settings
from securedb.db.session import Database

HEX32 = re.compile(r"^[0-9a-f]{32}$")


@pytest.fixture
def client(offline_settings: Settings) -> TestClient:
    return TestClient(create_app(offline_settings, Database(offline_settings.database_url)))


def test_generates_request_id_when_absent(client: TestClient) -> None:
    response = client.get("/no-such-route")
    request_id = response.headers["X-Request-ID"]
    assert HEX32.match(request_id)
    assert response.json()["request_id"] == request_id


def test_echoes_well_formed_inbound_request_id(client: TestClient) -> None:
    response = client.get("/no-such-route", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers["X-Request-ID"] == "trace-abc-123"
    assert response.json()["request_id"] == "trace-abc-123"


@pytest.mark.parametrize("hostile", ["x" * 65, "bad id!", "<script>", "a;b"])
def test_replaces_malformed_inbound_request_id(client: TestClient, hostile: str) -> None:
    response = client.get("/no-such-route", headers={"X-Request-ID": hostile})
    assert HEX32.match(response.headers["X-Request-ID"])
    assert hostile not in response.text
