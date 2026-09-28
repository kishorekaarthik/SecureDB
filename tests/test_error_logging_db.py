import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from securedb.app import create_app
from securedb.config import Settings
from securedb.db.models import Tenant
from securedb.db.session import Database


class NewTenant(BaseModel):
    name: str


def test_database_error_values_are_not_logged(
    settings: Settings, clean_db: None, capsys: pytest.CaptureFixture[str]
) -> None:
    database = Database(settings.database_url)
    app = create_app(settings, database)

    @app.post("/tenants")
    def add_tenant(body: NewTenant) -> None:
        with database.session() as session:
            session.add(Tenant(name=body.name))

    client = TestClient(app, raise_server_exceptions=False)
    try:
        assert client.post("/tenants", json={"name": "PII-VALUE-123"}).status_code == 200
        response = client.post("/tenants", json={"name": "PII-VALUE-123"})  # unique violation
    finally:
        database.dispose()

    assert response.status_code == 500
    out = capsys.readouterr().out
    assert "unhandled_error" in out
    assert "IntegrityError" in out
    assert "23505" in out  # sqlstate unique_violation is kept for debugging
    assert "PII-VALUE-123" not in out
