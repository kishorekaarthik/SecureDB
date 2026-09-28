from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import NullPool

from securedb.config import Settings
from tests.helpers import is_test_database, truncate_all

ROOT = Path(__file__).resolve().parents[1]
OFFLINE_URL = "postgresql+psycopg://nobody:nopass@127.0.0.1:1/offline_test?connect_timeout=1"


@pytest.fixture
def offline_settings() -> Settings:
    """Settings pointing at an unreachable database, for tests that need no DB."""
    return Settings(
        _env_file=None,
        env="test",
        database_url=OFFLINE_URL,
        migration_database_url=OFFLINE_URL,
    )


@pytest.fixture(scope="session")
def settings() -> Settings:
    env_file = ROOT / ".env.test"
    try:
        loaded = Settings(_env_file=env_file if env_file.exists() else None, env="test")
    except ValidationError as exc:
        pytest.exit(
            "Test database settings are missing. Run `uv run python scripts/make_dev_env.py` "
            f"and scripts/bootstrap_db.ps1.\n{exc}",
            returncode=2,
        )
    for url in (loaded.database_url, loaded.migration_database_url):
        if not is_test_database(url):
            pytest.exit("Refusing to run: test database names must end with '_test'.", 2)
    return loaded


@pytest.fixture(scope="session")
def migrated(settings: Settings) -> None:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["url"] = settings.migration_database_url
    cfg.attributes["configure_logger"] = False
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@pytest.fixture
def clean_db(settings: Settings, migrated: None) -> Iterator[None]:
    yield
    truncate_all(settings.migration_database_url)


@pytest.fixture
def owner_engine(settings: Settings, clean_db: None) -> Iterator[Engine]:
    engine = create_engine(settings.migration_database_url, poolclass=NullPool)
    yield engine
    engine.dispose()


@pytest.fixture
def app_engine(settings: Settings, clean_db: None) -> Iterator[Engine]:
    engine = create_engine(settings.database_url, poolclass=NullPool)
    yield engine
    engine.dispose()
