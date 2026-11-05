"""What the Overview's rollups add up to across connections, and what retention deletes."""

from datetime import date, timedelta

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError
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


def test_retention_purges_old_sign_in_rows_and_keeps_the_audit_log(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    with owner.begin() as conn:
        conn.execute(text("DELETE FROM login_failure"))
        conn.execute(text("DELETE FROM user_session"))
        user = conn.execute(
            text(
                "INSERT INTO app_user (username, password_hash, role, is_active, "
                "must_change_password, created_by, updated_by) "
                "VALUES ('purge.check', 'x', 'viewer', true, false, 't', 't') RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text("""
            INSERT INTO login_failure (username, failed_at) VALUES
              ('old', now() - interval '31 days'), ('recent', now() - interval '29 days')
        """)
        )
        conn.execute(
            text("""
            INSERT INTO user_session (token_hash, user_agent, user_id, idle_expires_at,
                                      absolute_expires_at)
            VALUES (sha256('a'), 'old', :u, now() - interval '31 days', now() - interval '31 days'),
                   (sha256('b'), 'recent', :u, now() - interval '29 days',
                    now() - interval '29 days'),
                   (sha256('c'), 'live', :u, now() + interval '1 hour', now() + interval '1 hour')
        """),
            {"u": user},
        )
        conn.execute(
            text(
                "INSERT INTO audit_log (actor, action, occurred_at) "
                "VALUES ('old', 'auth.sign_in.failed', now() - interval '400 days')"
            )
        )
    result = run_retention(worker, store=store, today=DAY, retention_days=180, demo_raw_days=7)
    assert result.sign_in_rows_purged == 2
    with owner.connect() as conn:
        assert list(conn.execute(text("SELECT username FROM login_failure")).scalars()) == [
            "recent"
        ]
        assert set(conn.execute(text("SELECT user_agent FROM user_session")).scalars()) == {
            "recent",
            "live",
        }
        assert (
            conn.execute(text("SELECT count(*) FROM audit_log WHERE actor = 'old'")).scalar_one()
            == 1
        )


@pytest.mark.parametrize("table", ["login_failure", "user_session"])
def test_the_worker_still_cannot_read_sign_in_data(worker: Engine, table: str) -> None:
    with worker.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(text(f"SELECT * FROM {table}"))  # noqa: S608 - two fixed names


def test_only_the_worker_may_purge_sign_in_rows(owner: Engine) -> None:
    with owner.connect() as conn:
        allowed = conn.execute(
            text("""
            SELECT rolname FROM pg_roles
            WHERE rolname IN ('argus_api', 'argus_scheduler', 'argus_worker')
              AND has_function_privilege(oid, 'argus_purge_sign_in_rows()', 'EXECUTE')
        """)
        ).scalars()
        assert set(allowed) == {"argus_worker"}


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
