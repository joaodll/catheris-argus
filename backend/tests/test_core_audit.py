"""Every audit row is also one structured log line (review F10)."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, text

from argus.core import audit
from argus.core.logging import JsonFormatter

SRC = Path(__file__).resolve().parents[1] / "src" / "argus"


@pytest.fixture
def quiet_root() -> Iterator[None]:
    """The root at WARNING, as ARGUS_LOG_LEVEL=WARNING sets it."""
    root = logging.getLogger()
    before = root.level
    root.setLevel(logging.WARNING)
    yield
    root.setLevel(before)


def _lines(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [
        json.loads(JsonFormatter().format(r)) for r in caplog.records if r.name == "argus.audit"
    ]


def test_a_record_is_a_row_and_one_line_even_at_warning(
    worker: Engine, caplog: pytest.LogCaptureFixture, quiet_root: None
) -> None:
    with worker.begin() as conn:  # the worker's role inserts and can't read back
        audit.record(
            conn,
            actor="alice",
            action="settings.retention",
            target_type="setting",
            target_id="retention",
            detail={"history_days": 90, "nested": {"note": "kept"}},
            client_ip="192.0.2.7",
        )

    [line] = _lines(caplog)
    assert line["audit"] is True and line["level"] == "INFO"
    assert {k: line[k] for k in ("actor", "action", "target_type", "target_id", "client_ip")} == {
        "actor": "alice",
        "action": "settings.retention",
        "target_type": "setting",
        "target_id": "retention",
        "client_ip": "192.0.2.7",
    }
    assert json.loads(str(line["detail"])) == {"history_days": 90, "nested": {"note": "kept"}}


def test_the_line_matches_the_row(owner: Engine, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="argus.audit")
    with owner.begin() as conn:
        audit.record(conn, actor="bob", action="user.create", target_type="user", target_id="7")
        row = conn.execute(
            text("SELECT actor, action, target_type, target_id, detail FROM audit_log")
        ).one()
    [line] = _lines(caplog)
    assert (line["actor"], line["action"], line["target_type"], line["target_id"]) == tuple(row[:4])
    assert json.loads(str(line["detail"])) == row.detail == {}


def test_a_secret_in_detail_is_masked_in_the_line_even_nested(
    owner: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="argus.audit")
    planted = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS's documented example key
    with owner.begin() as conn:
        audit.record(
            conn, actor="carol", action="connection.update", detail={"outer": {"token": planted}}
        )
    assert caplog.records
    assert planted not in "\n".join(JsonFormatter().format(r) for r in caplog.records)


def test_a_limited_sign_in_writes_a_line_only_with_its_row(
    owner: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="argus.audit")
    with owner.begin() as conn:
        for _ in range(3):  # a burst inside one window: one row, so one line
            audit.record_sign_in_limited(
                conn, actor="mallory", client_ip="198.51.100.4", window_minutes=15
            )
        rows = conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one()
    lines = _lines(caplog)
    assert rows == len(lines) == 1
    assert lines[0]["action"] == "auth.sign_in.limited" and lines[0]["actor"] == "mallory"


def test_every_audit_row_is_inserted_by_core_audit() -> None:
    """A row inserted anywhere else would have no log line."""
    elsewhere = [
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if p != SRC / "core" / "audit.py" and "insert into audit_log" in p.read_text().lower()
    ]
    assert elsewhere == []
