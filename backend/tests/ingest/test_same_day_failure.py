"""What the Overview shows after real first scans (2026-10-06): a failed run never erases what
a good run of the same day loaded; a partial Prowler run shows what it evaluated; each block
reads its own tool's latest scan, whichever tool ran first."""

from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus import metrics
from argus.collection import CollectOptions, FilesystemRawStore
from argus.ingest import ingest_run, register_failed_run

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)


def _values(owner: Engine, metric: str, connection_id: int) -> dict[str, float]:
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT dimension, value FROM metric_daily WHERE snapshot_date = :d "
                "AND connection_id = :c AND metric = :m"
            ),
            {"d": DAY, "c": connection_id, "m": metric},
        )
        return {r.dimension: float(r.value) for r in rows}


def test_a_failed_run_after_a_complete_one_keeps_the_day(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    assert run_tool(worker, store, target, "steampipe", DAY).status == "complete"
    before = _values(owner, "assets.total", target.connection_id)
    assert before

    with worker.begin() as conn:
        failed = register_failed_run(
            conn,
            connection_id=target.connection_id,
            tool="steampipe",
            source="synthetic",
            day=DAY,
            run_uid=uuid4(),
            raw_path="",
            started_at=datetime.now(UTC),
            error="OSError: [Errno 28] No space left on device",
        )
    assert ingest_run(worker, store=store, scan_run_id=failed, rules_dir=RULES_DIR).status == (
        "failed"
    )

    assert _values(owner, "assets.total", target.connection_id) == before
    with owner.connect() as conn:
        overview = metrics.build_overview(conn, connection_id=target.connection_id, as_of=DAY)
    assert overview["data_through"] == DAY


def test_a_partial_prowler_run_on_the_first_day_shows_its_results(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Prowler on a real account is often throttled somewhere: its partial run still shows
    the check results and ThreatScore it evaluated (it resolves nothing)."""
    target = make_demo(owner)
    throttled = CollectOptions(synthetic_throttle_share=1.0)
    assert run_tool(worker, store, target, "prowler", DAY, throttled).status == "partial"

    assert _values(owner, "checks.status", target.connection_id)
    with owner.connect() as conn:
        overview = metrics.build_overview(conn, connection_id=target.connection_id, as_of=DAY)
    assert overview["data_through"] == DAY
    assert overview["kpis"]["threatscore"]["value"] is not None
    assert overview["check_results"]["passed"] is not None


def test_each_overview_block_reads_its_own_tool(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """CloudFox alone fills its own blocks: with no inventory its public endpoints are the only
    paths, each a door at candidate (ADR-0037, second amendment), counted, not "no data"."""
    target = make_demo(owner)
    assert run_tool(worker, store, target, "cloudfox", DAY).status == "complete"
    with owner.connect() as conn:
        overview = metrics.build_overview(conn, connection_id=target.connection_id, as_of=DAY)
        doors = conn.execute(
            text(
                "SELECT rule_id, confidence, severity FROM attack_path WHERE connection_id = :c "
                "AND state = 'open'"
            ),
            {"c": target.connection_id},
        ).all()
    # Every path starts at a CloudFox door, so every one is Candidate: the doors themselves,
    # and a workload CloudFox reports with a secret in its environment (wave 3).
    kinds = {d.rule_id for d in doors}
    assert doors and {d.confidence for d in doors} == {"candidate"}
    exposure = {"internet-exposed", "internet-exposed-admin-port"}
    assert kinds <= exposure | {"internet-to-workload-secret"}
    # Exploitable: critical and high (an administrative port), a count even when zero.
    exploitable = sum(d.severity in ("critical", "high") for d in doors)
    assert overview["data_through"] == DAY
    assert overview["kpis"]["exploitable_paths"]["value"] == exploitable
    assert overview["kpis"]["assets"]["value"] is None  # Steampipe has not run
    assert overview["check_results"]["passed"] is None  # nor has Prowler

    # Prowler the next day: its blocks show its scan, CloudFox's keep theirs.
    next_day = DAY + timedelta(days=1)
    assert run_tool(worker, store, target, "prowler", next_day).status == "complete"
    with owner.connect() as conn:
        overview = metrics.build_overview(conn, connection_id=target.connection_id, as_of=next_day)
    assert overview["data_through"] == next_day
    assert overview["check_results"]["passed"] is not None
    assert overview["kpis"]["exploitable_paths"]["value"] == exploitable


def test_a_failed_prowler_run_carries_compliance_forward(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """The score history has no gap: the failed connection keeps its last requirement results
    and scores, and all connections are rebuilt from both (Posture -> Compliance)."""
    good, failing = make_demo(owner, 0), make_demo(owner, 1)
    for target in (good, failing):
        assert run_tool(worker, store, target, "prowler", DAY).status == "complete"
    next_day = DAY + timedelta(days=1)
    assert run_tool(worker, store, good, "prowler", next_day).status == "complete"
    with worker.begin() as conn:
        failed = register_failed_run(
            conn,
            connection_id=failing.connection_id,
            tool="prowler",
            source="synthetic",
            day=next_day,
            run_uid=uuid4(),
            raw_path="",
            started_at=datetime.now(UTC),
            error="throttled everywhere",
        )
    assert ingest_run(worker, store=store, scan_run_id=failed, rules_dir=RULES_DIR).status == (
        "failed"
    )

    def scores(day: date, connection_id: int) -> dict[str, float]:
        with owner.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT dimension, value FROM metric_daily WHERE snapshot_date = :d "
                    "AND connection_id = :c AND metric = 'compliance.score'"
                ),
                {"d": day, "c": connection_id},
            )
            return {r.dimension: float(r.value) for r in rows}

    assert scores(next_day, failing.connection_id) == scores(DAY, failing.connection_id)
    assert set(scores(next_day, 0)) == {"cis_6.0_aws", "prowler_threatscore_aws"}
    with owner.connect() as conn:
        carried = conn.execute(
            text(
                "SELECT count(*) FROM compliance_snapshot WHERE snapshot_date = :d "
                "AND connection_id = :c"
            ),
            {"d": next_day, "c": failing.connection_id},
        ).scalar_one()
        assessed = set(
            conn.execute(
                text(
                    "SELECT fail_connections + manual_connections + pass_connections "
                    "FROM compliance_rollup WHERE snapshot_date = :d"
                ),
                {"d": next_day},
            ).scalars()
        )
    assert carried > 0 and assessed == {2}
