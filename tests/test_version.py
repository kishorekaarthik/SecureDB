from importlib.metadata import version

import securedb


def test_package_version_matches_metadata() -> None:
    assert securedb.__version__ == version("securedb") == "0.1.0"
