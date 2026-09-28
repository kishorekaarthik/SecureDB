import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from securedb import __version__, cli
from securedb.crypto import master_key as mk
from tests.helpers import MemoryKeyring

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


PASSPHRASE = "correct horse battery staple"


def test_init_creates_master_key_in_keychain(memory_keyring: MemoryKeyring) -> None:
    result = runner.invoke(cli.app, ["init"])
    assert result.exit_code == 0, result.output
    key_id = mk.load_keychain_master_key().key_id
    assert key_id in result.output
    stored = json.loads(memory_keyring.entries[(mk.KEYCHAIN_SERVICE, mk.KEYCHAIN_USERNAME)])
    assert stored["key"] not in result.output


def test_init_refuses_to_overwrite_existing_key() -> None:
    assert runner.invoke(cli.app, ["init"]).exit_code == 0
    result = runner.invoke(cli.app, ["init"])
    assert result.exit_code == 1
    assert "already exists" in result.output


def test_init_file_store_prompts_for_passphrase(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    result = runner.invoke(
        cli.app,
        ["init", "--store", "file", "--key-file", str(path)],
        input=f"{PASSPHRASE}\n{PASSPHRASE}\n",
    )
    assert result.exit_code == 0, result.output
    assert PASSPHRASE not in result.output
    assert mk.load_file_master_key(path, PASSPHRASE).key_id in result.output


def test_init_file_store_rejects_short_passphrase(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    result = runner.invoke(
        cli.app, ["init", "--store", "file", "--key-file", str(path)], input="short\nshort\n"
    )
    assert result.exit_code == 1
    assert "at least 12" in result.output
    assert not path.exists()
