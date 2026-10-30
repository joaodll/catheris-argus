from datetime import date

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from argus.collection import TOOL_ORDER
from argus.scheduling import create_demo_connection

pytestmark = pytest.mark.db
TODAY = date(2026, 10, 2)


@pytest.fixture
def engine(migrated: Engine) -> Engine:
    with migrated.begin() as conn:
        conn.execute(text("TRUNCATE connection, run_request, audit_log RESTART IDENTITY CASCADE"))
    return migrated


def test_creates_connection_backfill_and_audit_in_one_go(engine: Engine) -> None:
    connection, queued = create_demo_connection(
        engine, name="demo-prod", seed=0, days=3, today=TODAY, actor="admin"
    )

    assert connection.kind == "demo" and connection.account_id == "100000000010"
    assert queued == 3 * len(TOOL_ORDER)
    with engine.connect() as conn:
        requests = conn.execute(
            text(
                "SELECT snapshot_date, tool FROM run_request WHERE connection_id = :c ORDER BY id"
            ),
            {"c": connection.id},
        ).all()
        audit = conn.execute(text("SELECT action, target_id FROM audit_log")).all()
    # Oldest day first, tools in the throttling order within each day.
    assert [r.snapshot_date for r in requests[:3]] == [date(2026, 9, 30)] * 3
    assert [r.tool for r in requests[:3]] == list(TOOL_ORDER)
    assert requests[-1].snapshot_date == TODAY
    assert audit == [("connection.create", str(connection.id))]


def test_a_failed_create_leaves_nothing_behind(engine: Engine) -> None:
    create_demo_connection(engine, name="demo", seed=0, days=1, today=TODAY, actor="admin")
    with pytest.raises(IntegrityError):
        create_demo_connection(engine, name="demo", seed=1, days=1, today=TODAY, actor="admin")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM connection")).scalar_one() == 1
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == 1


@pytest.mark.parametrize("days", [0, 401])
def test_backfill_days_are_bounded(engine: Engine, days: int) -> None:
    with pytest.raises(ValueError, match="days must be"):
        create_demo_connection(engine, name="d", seed=0, days=days, today=TODAY, actor="admin")
