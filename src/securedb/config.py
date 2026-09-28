"""Application settings, loaded from SECUREDB_* environment variables and .env."""

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DB_SCHEME = "postgresql+psycopg://"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECUREDB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["dev", "test", "prod"] = "dev"
    database_url: str
    migration_database_url: str
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def _require_psycopg_driver(cls, value: str) -> str:
        if not value.startswith(_DB_SCHEME):
            raise ValueError(f"must start with {_DB_SCHEME}")
        return value

    @property
    def docs_enabled(self) -> bool:
        return self.env == "dev"


@lru_cache
def get_settings() -> Settings:
    return Settings()
