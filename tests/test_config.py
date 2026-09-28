import pytest
from pydantic import ValidationError

from securedb.config import Settings

APP_URL = "postgresql+psycopg://securedb_app:pw@localhost:5432/securedb"
OWNER_URL = "postgresql+psycopg://securedb_owner:pw@localhost:5432/securedb"


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SECUREDB_ENV",
        "SECUREDB_DATABASE_URL",
        "SECUREDB_MIGRATION_DATABASE_URL",
        "SECUREDB_LOG_LEVEL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_reads_prefixed_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUREDB_DATABASE_URL", APP_URL)
    monkeypatch.setenv("SECUREDB_MIGRATION_DATABASE_URL", OWNER_URL)
    monkeypatch.setenv("SECUREDB_LOG_LEVEL", "DEBUG")

    settings = Settings(_env_file=None)

    assert settings.database_url == APP_URL
    assert settings.migration_database_url == OWNER_URL
    assert settings.log_level == "DEBUG"
    assert settings.env == "dev"


def test_missing_database_urls_are_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    missing = {err["loc"][0] for err in exc_info.value.errors()}
    assert missing == {"database_url", "migration_database_url"}


@pytest.mark.parametrize(
    "bad_url",
    ["postgresql://u:p@localhost/db", "sqlite:///x.db", "mongodb://localhost/securedb"],
)
def test_database_urls_must_use_psycopg_driver(bad_url: str) -> None:
    with pytest.raises(ValidationError, match=r"postgresql\+psycopg://"):
        Settings(_env_file=None, database_url=bad_url, migration_database_url=OWNER_URL)


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            env="staging",
            database_url=APP_URL,
            migration_database_url=OWNER_URL,
        )


@pytest.mark.parametrize(("env", "enabled"), [("dev", True), ("test", False), ("prod", False)])
def test_docs_enabled_only_in_dev(env: str, enabled: bool) -> None:
    settings = Settings(
        _env_file=None, env=env, database_url=APP_URL, migration_database_url=OWNER_URL
    )
    assert settings.docs_enabled is enabled


def test_validation_errors_do_not_echo_database_passwords() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            database_url="postgresql://app:S3cretPw@localhost/securedb",
            migration_database_url=OWNER_URL,
        )
    assert "S3cretPw" not in str(exc_info.value)
