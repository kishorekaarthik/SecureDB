"""Test-only helpers for database safety and cleanup."""

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
