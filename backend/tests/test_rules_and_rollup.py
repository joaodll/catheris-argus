"""Two failures the 180-day backfill on the running stack exposed (2026-10-03)."""

import threading
from datetime import date
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo

from argus import metrics
from argus.attackpaths import load_path_kinds
from argus.relationships import load_rules
from argus.relationships.engine import RuleError

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def test_a_missing_rules_directory_fails_loudly(tmp_path: Path) -> None:
    # The worker once got a dev-container path: no rules, no edges, no attack paths, no error.
    with pytest.raises(RuleError, match="no relationship rules"):
        load_rules(tmp_path)
    with pytest.raises(ValueError, match="no attack-path kinds"):
        load_path_kinds(tmp_path)
    assert load_rules(RULES_DIR) and load_path_kinds(RULES_DIR)


@pytest.mark.db
def test_concurrent_rollups_for_one_day_do_not_collide(owner: Engine, worker: Engine) -> None:
    day = date(2026, 10, 2)
    targets = [make_demo(owner, seed) for seed in (0, 1)]
    with owner.begin() as conn:
        conn.execute(text("SELECT argus_ensure_partitions(:d, :d)"), {"d": day})
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def ingest(connection_id: int, value: float) -> None:
        try:
            with worker.begin() as conn:
                metrics.put(
                    conn, day=day, connection_id=connection_id, values={("assets.total", ""): value}
                )
                barrier.wait(timeout=10)  # both transactions now race into the rollup
                metrics.rollup(conn, day=day, metrics=["assets.total"])
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=ingest, args=(t.connection_id, v))
        for t, v in zip(targets, (100.0, 50.0), strict=True)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == []
    with owner.connect() as conn:
        total = conn.execute(
            text(
                "SELECT value FROM metric_daily WHERE connection_id = 0 "
                "AND metric = 'assets.total' AND snapshot_date = :d"
            ),
            {"d": day},
        ).scalar_one()
    assert total == 150.0
