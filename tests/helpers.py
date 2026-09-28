"""Test-only helpers: database safety and cleanup, in-memory OS keychain."""

from keyring.backend import KeyringBackend
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool


def is_test_database(url: str) -> bool:
    return (make_url(url).database or "").endswith("_test")


def truncate_all(owner_url: str) -> None:
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with engine.begin() as conn:
            tables = (
                conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables "
                        "WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
                    )
                )
                .scalars()
                .all()
            )
            if tables:
                names = ", ".join(f'"{name}"' for name in tables)
                conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
    finally:
        engine.dispose()


class MemoryKeyring(KeyringBackend):
    """In-memory keyring so tests never touch the real OS keychain."""

    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.entries: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.entries[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.entries.pop((service, username), None)
