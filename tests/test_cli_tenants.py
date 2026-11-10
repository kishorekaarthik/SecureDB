import re
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text
from typer.testing import CliRunner

from securedb import cli
from securedb.config import Settings
from securedb.crypto.local import LocalKeyProvider, LockedKeyProvider
from securedb.crypto.provider import KeyProvider
from securedb.db.session import Database
from securedb.errors import Unauthorized
from securedb.policy.engine import Action, Effect, decide
from securedb.tenants.api_keys import authenticate
from securedb.tenants.service import find_tenant_id
from securedb.vault.fields import FieldType
from tests.helpers import set_tenant

runner = CliRunner()
KEY = re.compile(r"sdb_live_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}")


@pytest.fixture
def database(settings: Settings, clean_db: None) -> Iterator[Database]:
    database = Database(settings.database_url)
    yield database
    database.dispose()


@pytest.fixture
def wired(
    monkeypatch: pytest.MonkeyPatch, database: Database, key_provider: LocalKeyProvider
) -> Database:
    def fake_open() -> tuple[Database, KeyProvider]:
        return database, key_provider

    monkeypatch.setattr(cli, "_open", fake_open)
    return database


def _run(*args: str) -> tuple[int, str]:
    result = runner.invoke(cli.app, list(args))
    return result.exit_code, result.output


def _new_key(*scopes: str) -> str:
    args = ["create-api-key", "--tenant", "acme", "--name", "billing"]
    for scope in scopes:
        args += ["--scope", scope]
    code, output = _run(*args)
    assert code == 0, output
    match = KEY.search(output)
    assert match is not None
    return match.group(0)


def test_create_tenant(wired: Database) -> None:
    code, output = _run("create-tenant", "acme")
    assert code == 0, output
    assert str(find_tenant_id(wired, "acme")) in output


def test_duplicate_tenant_fails_cleanly(wired: Database) -> None:
    assert _run("create-tenant", "acme")[0] == 0
    code, output = _run("create-tenant", "acme")
    assert code == 1
    assert "already exists" in output


def test_create_api_key_prints_it_once_and_it_works(wired: Database) -> None:
    _run("create-tenant", "acme")
    key = _new_key("tokenize", "detokenize")
    authenticated = authenticate(wired, f"Bearer {key}")
    assert authenticated.scopes == frozenset({"tokenize", "detokenize"})


def test_set_policy(wired: Database) -> None:
    _run("create-tenant", "acme")
    key = _new_key("detokenize")
    prefix = key.split("_")[2]
    code, output = _run(
        "set-policy", "--tenant", "acme", "--key", prefix,
        "--type", "pan", "--action", "detokenize", "--effect", "mask",
    )  # fmt: skip
    assert code == 0, output
    authenticated = authenticate(wired, f"Bearer {key}")
    with wired.tenant_session(authenticated.tenant_id) as session:
        assert decide(session, authenticated.id, FieldType.pan, Action.detokenize) is Effect.mask


def test_revoke_api_key(wired: Database) -> None:
    _run("create-tenant", "acme")
    key = _new_key("tokenize")
    code, output = _run("revoke-api-key", "--tenant", "acme", key.split("_")[2])
    assert code == 0, output
    with pytest.raises(Unauthorized):
        authenticate(wired, f"Bearer {key}")


def test_unknown_tenant_fails_cleanly(wired: Database) -> None:
    code, output = _run(
        "create-api-key", "--tenant", "nobody", "--name", "x", "--scope", "tokenize"
    )
    assert code == 1
    assert "Tenant not found" in output


def test_locked_vault_refuses_to_create_tenants(
    monkeypatch: pytest.MonkeyPatch, database: Database
) -> None:
    monkeypatch.setattr(
        cli, "_open", lambda: (database, LockedKeyProvider("No master key. Run `securedb init`."))
    )
    code, output = _run("create-tenant", "acme")
    assert code == 1
    assert "securedb init" in output


def test_verify_audit(wired: Database, owner_engine: Engine) -> None:
    _run("create-tenant", "acme")
    code, output = _run("verify-audit", "--tenant", "acme")
    assert code == 0, output
    assert "OK" in output and "1 entries" in output
    with owner_engine.begin() as conn:
        set_tenant(conn, find_tenant_id(wired, "acme"))
        conn.execute(text("UPDATE audit_log SET action = 'tampered'"))
    code, output = _run("verify-audit", "--tenant", "acme")
    assert code == 2
    assert "BROKEN" in output and "seq 1" in output


def test_verify_audit_with_anchor(wired: Database) -> None:
    _run("create-tenant", "acme")
    code, output = _run("verify-audit", "--tenant", "acme")
    head = output.strip().rsplit(" ", 1)[1]
    ok_code, _ = _run(
        "verify-audit", "--tenant", "acme", "--anchor-seq", "1", "--anchor-hash", head
    )
    bad_code, bad_output = _run(
        "verify-audit", "--tenant", "acme", "--anchor-seq", "1", "--anchor-hash", "0" * 64
    )
    assert (code, ok_code, bad_code) == (0, 0, 2)
    assert "BROKEN at seq 1" in bad_output
