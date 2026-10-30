"""Migration 0031 re-masks stored text with the fixed assignment rule: a secret written after
another word ("ingest failed: password=x") was kept before 2026-10-24."""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import Engine, text

from argus.core.redaction import redact_text

pytestmark = pytest.mark.db
MIGRATION = Path(__file__).resolve().parents[2] / "migrations/versions/0031_remask_assignments.py"
# Fake values only, built at runtime so no scanner mistakes them for real ones.
LEAK = "pw-" + "not-real-" + "0031"
CASES = [
    f"ingest failed: password={LEAK}",
    f"bad row: AWS_SECRET_ACCESS_KEY={LEAK}",
    f"ValueError: config: token: {LEAK}",
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdEf",
    "Scanning region=us-east-1 with 12 checks: done",
]


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0031", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("line", CASES, ids=["word", "env", "two-words", "arn", "diagnostic"])
def test_the_frozen_rule_matches_redaction_today(line: str) -> None:
    assert _migration().remask(line) == redact_text(line)


def test_stored_text_is_re_masked(migrated: Engine) -> None:
    # One transaction, rolled back: the schema tests expect an empty connection table.
    with migrated.connect() as conn, conn.begin() as tx:
        cid = conn.execute(
            text(
                "INSERT INTO connection (name, kind, account_id, auth_method, demo_seed, "
                "created_by, updated_by) VALUES ('remask', 'demo', '100000000099', 'none', 0, "
                "'t', 't') RETURNING id"
            )
        ).scalar_one()
        rid = conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, requested_by, error) "
                "VALUES (:c, 'prowler', 'manual', 'admin', :e) RETURNING id"
            ),
            {"c": cid, "e": "\n".join(CASES)},
        ).scalar_one()
        changed = _migration().remask_stored(conn)
        error = conn.execute(
            text("SELECT error FROM run_request WHERE id = :i"), {"i": rid}
        ).scalar_one()
        again = _migration().remask_stored(conn)
        tx.rollback()
    assert changed == 1 and again == 0  # idempotent
    assert LEAK not in error
    assert "secret:prod/db-AbCdEf" in error and "region=us-east-1" in error
