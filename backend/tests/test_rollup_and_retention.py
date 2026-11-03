"""What the Overview's rollups add up to across connections, and what retention deletes."""

from datetime import date, timedelta

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import TOOL_ORDER, FilesystemRawStore
from argus.retention import run_retention

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)


def _metric(engine: Engine, metric: str, dimension: str, connection_id: int, day: date) -> float:
    with engine.connect() as conn:
        value = conn.execute(
            text(
                "SELECT value FROM metric_daily WHERE metric = :m AND dimension = :d "
                "AND connection_id = :c AND snapshot_date = :day"
            ),
            {"m": metric, "d": dimension, "c": connection_id, "day": day},
        ).scalar_one()
    return float(value)


def test_overview_metrics_for_each_connection_and_all(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    prod, staging = make_demo(owner, 0), make_demo(owner, 1)
    for target in (prod, staging):
        for tool in TOOL_ORDER:
            run_tool(worker, store, target, tool, DAY)
    for metric, dimension in (
        ("assets.total", ""),
        ("checks.status", "PASS"),
        ("findings.open_by_severity", "critical"),
        ("threatscore.score", ""),
        ("compliance.score", "cis_6.0_aws"),
    ):
        for cid in (prod.connection_id, staging.connection_id, 0):
            _metric(owner, metric, dimension, cid, DAY)
    assert _metric(owner, "assets.total", "", 0, DAY) == (
        _metric(owner, "assets.total", "", prod.connection_id, DAY)
        + _metric(owner, "assets.total", "", staging.connection_id, DAY)
    )
    num = sum(
        _metric(owner, "threatscore.numerator", "", c, DAY)
        for c in (prod.connection_id, staging.connection_id)
    )
    den = sum(
        _metric(owner, "threatscore.denominator", "", c, DAY)
        for c in (prod.connection_id, staging.connection_id)
    )
    assert _metric(owner, "threatscore.score", "", 0, DAY) == pytest.approx(100 * num / den)
    assert 0 < _metric(owner, "threatscore.score", "", 0, DAY) < 100
    with owner.connect() as conn:
        pillars = set(
            conn.execute(
                text(
                    "SELECT dimension FROM metric_daily WHERE metric = 'threatscore.score' "
                    "AND connection_id = 0 AND dimension <> ''"
                )
            ).scalars()
        )
    assert {"1. IAM", "2. Attack Surface"} <= pillars


def test_retention_drops_old_history_and_prunes_demo_raw(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    old = DAY - timedelta(days=400)
    run_tool(worker, store, target, "steampipe", old)
    run_tool(worker, store, target, "steampipe", DAY)
    result = run_retention(worker, store=store, today=DAY, retention_days=180, demo_raw_days=7)
    assert f"resource_snapshot_{old:%Y%m}" in result.partitions_dropped
    assert result.demo_runs_pruned == 1
    with owner.connect() as conn:
        days = set(
            conn.execute(text("SELECT DISTINCT snapshot_date FROM resource_snapshot")).scalars()
        )
    assert days == {DAY}
