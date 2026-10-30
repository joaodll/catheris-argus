import json
import logging
import sys

from argus.core.logging import JsonFormatter


def test_json_formatter_emits_one_object_with_extras() -> None:
    record = logging.makeLogRecord(
        {"name": "argus.test", "levelname": "INFO", "msg": "run %s done", "args": ("r1",)}
    )
    record.run_id = "r1"

    entry = json.loads(JsonFormatter().format(record))

    assert entry["msg"] == "run r1 done"
    assert entry["level"] == "INFO"
    assert entry["run_id"] == "r1"
    assert "args" not in entry


def test_messages_fields_and_exceptions_are_redacted() -> None:
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS's documented example key
    try:
        raise ValueError(f"bad row: AWS_SECRET_ACCESS_KEY={secret}")
    except ValueError:
        record = logging.makeLogRecord(
            {
                "name": "argus.test",
                "levelname": "ERROR",
                "msg": f"ingest failed: password={secret}",
                "exc_info": sys.exc_info(),
            }
        )
    record.detail = f"token={secret}"
    record.count = 3

    line = JsonFormatter().format(record)

    assert secret not in line
    entry = json.loads(line)
    assert entry["msg"].startswith("ingest failed: password=")
    assert entry["count"] == 3 and "ValueError" in entry["exc"]
