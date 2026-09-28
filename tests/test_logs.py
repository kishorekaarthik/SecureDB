import json
import logging

import pytest
import structlog

from securedb.logs import REDACTED, configure_logging, redact_sensitive


def _run(event: dict[str, object]) -> dict[str, object]:
    return dict(redact_sensitive(None, "info", dict(event)))


def test_sensitive_keys_are_redacted_case_insensitively() -> None:
    out = _run({"event": "x", "value": "ABCDE1234F", "Password": "hunter2", "TOTP": "123456"})
    assert out == {"event": "x", "value": REDACTED, "Password": REDACTED, "TOTP": REDACTED}


def test_nested_structures_are_redacted() -> None:
    out = _run({"event": "x", "items": [{"type": "pan", "value": "ABCDE1234F"}]})
    assert out["items"] == [{"type": "pan", "value": REDACTED}]


def test_api_keys_inside_strings_are_redacted() -> None:
    out = _run({"event": "auth failed for sdb_live_ab12_SeCrEt99 from 10.0.0.1"})
    assert out["event"] == f"auth failed for {REDACTED} from 10.0.0.1"


def test_non_sensitive_values_pass_through() -> None:
    event = {"event": "tokenized", "count": 3, "type": "pan", "ok": True}
    assert _run(event) == event


def test_configured_logger_emits_redacted_json(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    structlog.get_logger().info("tokenize", value="ABCDE1234F", count=1)

    line = capsys.readouterr().out.strip().splitlines()[-1]
    record = json.loads(line)
    assert record["event"] == "tokenize"
    assert record["value"] == REDACTED
    assert record["count"] == 1
    assert record["level"] == "info"
    assert "ABCDE1234F" not in line


def test_log_level_filters_lower_levels(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("WARNING")
    structlog.get_logger().info("quiet")
    assert capsys.readouterr().out == ""


def test_stdlib_tracebacks_are_json_and_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    try:
        raise RuntimeError("boom sdb_live_ab12_SeCrEt99")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception("Exception in ASGI application")

    out = capsys.readouterr().out
    record = json.loads(out.strip().splitlines()[-1])
    assert record["event"] == "Exception in ASGI application"
    assert record["level"] == "error"
    assert "RuntimeError" in record["exception"]
    assert "SeCrEt99" not in out
