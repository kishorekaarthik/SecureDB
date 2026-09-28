from typing import Any

import pytest
from typer.testing import CliRunner

from securedb import __version__, cli

runner = CliRunner()

Calls = list[tuple[tuple[Any, ...], dict[str, Any]]]


def test_version_prints_package_version() -> None:
    result = runner.invoke(cli.app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__


def _capture_uvicorn(monkeypatch: pytest.MonkeyPatch) -> Calls:
    calls: Calls = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **k: calls.append((a, k)))
    return calls


def test_serve_defaults_to_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture_uvicorn(monkeypatch)
    result = runner.invoke(cli.app, ["serve"])
    assert result.exit_code == 0, result.output
    [(args, kwargs)] = calls
    assert args == ("securedb.app:create_app",)
    assert kwargs["factory"] is True
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8000
    assert kwargs["reload"] is False


def test_serve_accepts_host_and_port(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture_uvicorn(monkeypatch)
    result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0", "--port", "9000"])
    assert result.exit_code == 0, result.output
    [(_, kwargs)] = calls
    assert kwargs["host"] == "0.0.0.0"
    assert kwargs["port"] == 9000
