import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from securedb.app import create_app
from securedb.config import Settings
from securedb.db.session import Database
from securedb.errors import PROBLEM_JSON, NotFound, Unauthorized


class EchoBody(BaseModel):
    count: int


@pytest.fixture
def app(offline_settings: Settings) -> FastAPI:
    application = create_app(offline_settings, Database(offline_settings.database_url))

    @application.get("/raise/not-found")
    def raise_not_found() -> None:
        raise NotFound("Token not found.")

    @application.get("/raise/unauthorized")
    def raise_unauthorized() -> None:
        raise Unauthorized()

    @application.get("/raise/crash")
    def raise_crash() -> None:
        raise RuntimeError("leaked sdb_live_ab12_SeCrEt99")

    @application.post("/echo")
    def echo(body: EchoBody) -> dict[str, int]:
        return {"count": body.count}

    return application


def _assert_problem(response_json: dict[str, object], status: int, title: str) -> None:
    assert response_json["type"] == "about:blank"
    assert response_json["status"] == status
    assert response_json["title"] == title
    assert isinstance(response_json["request_id"], str)


def test_domain_error_becomes_problem_json(app: FastAPI) -> None:
    response = TestClient(app).get("/raise/not-found")
    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_JSON
    _assert_problem(response.json(), 404, "Not Found")
    assert response.json()["detail"] == "Token not found."


def test_domain_error_without_detail_uses_title(app: FastAPI) -> None:
    response = TestClient(app).get("/raise/unauthorized")
    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_unknown_route_is_problem_json(app: FastAPI) -> None:
    response = TestClient(app).get("/nope")
    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_JSON
    _assert_problem(response.json(), 404, "Not Found")


def test_wrong_method_is_problem_json_with_allow_header(app: FastAPI) -> None:
    response = TestClient(app).delete("/echo")
    assert response.status_code == 405
    assert response.headers["content-type"] == PROBLEM_JSON
    assert "POST" in response.headers["allow"]


def test_validation_error_does_not_echo_submitted_values(app: FastAPI) -> None:
    response = TestClient(app).post("/echo", json={"count": "ABCDE1234F"})
    assert response.status_code == 422
    body = response.json()
    _assert_problem(body, 422, "Unprocessable Content")
    assert body["errors"][0]["loc"] == ["body", "count"]
    assert set(body["errors"][0]) == {"loc", "msg", "type"}
    assert "ABCDE1234F" not in response.text


def test_unhandled_error_is_generic_and_secret_free(
    app: FastAPI, capsys: pytest.CaptureFixture[str]
) -> None:
    response = TestClient(app, raise_server_exceptions=False).get("/raise/crash")
    assert response.status_code == 500
    assert response.headers["content-type"] == PROBLEM_JSON
    body = response.json()
    _assert_problem(body, 500, "Internal Server Error")
    assert body["detail"] == "An unexpected error occurred."
    assert re.fullmatch(r"[0-9a-f]{32}", body["request_id"])
    assert "sdb_live" not in response.text

    logs = capsys.readouterr().out
    assert "unhandled_error" in logs
    assert body["request_id"] in logs
    assert "SeCrEt99" not in logs


def test_unhandled_errors_do_not_reach_the_server(app: FastAPI) -> None:
    # Starlette's ServerErrorMiddleware re-raises after responding, which makes the
    # server log the raw traceback (unredacted). Errors must be fully handled inside.
    response = TestClient(app).get("/raise/crash")  # raise_server_exceptions=True
    assert response.status_code == 500
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["X-Request-ID"])
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
