"""All connections = each enabled connection's latest result on or before the day, at most 31
days old (decided 2026-10-08): accounts scanned on different days still add up. Events, which
happened on one day, are not carried."""

from datetime import date, timedelta

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus import metrics
from argus.core.rawstore import FilesystemRawStore

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)


def _put(
    engine: Engine, connection_id: int, day: date, values: dict[tuple[str, str], float]
) -> None:
    with engine.begin() as conn:
        conn.execute(text("SELECT argus_ensure_partitions(:a, :b)"), {"a": day, "b": day})
        metrics.put(conn, day=day, connection_id=connection_id, values=values)
        metrics.rollup(conn, day=day, metrics=sorted({m for m, _ in values}))


def _all(engine: Engine, day: date, metric: str, dimension: str = "") -> float | None:
    with engine.connect() as conn:
        value = conn.execute(
            text(
                "SELECT value FROM metric_daily WHERE connection_id = 0 AND snapshot_date = :d "
                "AND metric = :m AND dimension = :dim"
            ),
            {"d": day, "m": metric, "dim": dimension},
        ).scalar_one_or_none()
    return None if value is None else float(value)


def test_an_account_counts_with_its_latest_scan_until_the_next(
    owner: Engine, worker: Engine
) -> None:
    a, b = (make_demo(owner, seed).connection_id for seed in (0, 1))
    _put(worker, a, DAY, {("assets.total", ""): 100, ("findings.events", "new"): 7})
    _put(
        worker,
        b,
        DAY + timedelta(days=1),
        {("assets.total", ""): 50, ("findings.events", "new"): 2},
    )
    assert _all(worker, DAY + timedelta(days=1), "assets.total") == 150  # A from the day before
    assert _all(worker, DAY + timedelta(days=1), "findings.events", "new") == 2  # not carried

    # A's next scan replaces its value; an account last seen over 31 days ago drops out.
    _put(worker, a, DAY + timedelta(days=2), {("assets.total", ""): 120})
    assert _all(worker, DAY + timedelta(days=2), "assets.total") == 170
    _put(worker, a, DAY + timedelta(days=40), {("assets.total", ""): 90})
    assert _all(worker, DAY + timedelta(days=40), "assets.total") == 90


def test_a_disabled_connection_leaves_the_totals(owner: Engine, worker: Engine) -> None:
    a, b = (make_demo(owner, seed).connection_id for seed in (0, 1))
    _put(worker, a, DAY, {("assets.total", ""): 100})
    with owner.begin() as conn:
        conn.execute(text("UPDATE connection SET enabled = false WHERE id = :i"), {"i": a})
    _put(worker, b, DAY + timedelta(days=1), {("assets.total", ""): 50})
    assert _all(worker, DAY + timedelta(days=1), "assets.total") == 50


def test_the_requirement_list_and_score_combine_accounts_scanned_on_different_days(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    a, b = make_demo(owner, 0), make_demo(owner, 1)
    run_tool(worker, store, a, "prowler", DAY)
    run_tool(worker, store, b, "prowler", DAY + timedelta(days=1))
    with owner.connect() as conn:
        assessed = conn.execute(
            text(
                "SELECT max(fail_connections + manual_connections + pass_connections) "
                "FROM compliance_rollup WHERE snapshot_date = :d"
            ),
            {"d": DAY + timedelta(days=1)},
        ).scalar_one()
        parts = conn.execute(
            text(
                "SELECT connection_id, value FROM metric_daily "
                "WHERE metric = 'compliance.assessed' "
                "AND dimension = 'cis_6.0_aws' AND snapshot_date = :d"
            ),
            {"d": DAY + timedelta(days=1)},
        ).all()
    assert assessed == 2  # both accounts, though A ran the day before
    by_connection = dict(parts)
    with owner.connect() as conn:
        a_value = conn.execute(
            text(
                "SELECT value FROM metric_daily WHERE metric = 'compliance.assessed' "
                "AND dimension = 'cis_6.0_aws' AND snapshot_date = :d AND connection_id = :c"
            ),
            {"d": DAY, "c": a.connection_id},
        ).scalar_one()
    assert by_connection[0] == a_value + by_connection[b.connection_id]
