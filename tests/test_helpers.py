import pytest

from tests.helpers import is_test_database


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("postgresql+psycopg://u:p@localhost/securedb_test", True),
        ("postgresql+psycopg://u:p@localhost/securedb", False),
        ("postgresql+psycopg://u:p@localhost/securedb_test_backup", False),
        ("postgresql+psycopg://u:p@localhost/", False),
    ],
)
def test_is_test_database(url: str, expected: bool) -> None:
    assert is_test_database(url) is expected
