"""Vulnerabilities runs through ingest (ADR-0042), on the Demo estate in AWS Inspector's shape:
CVEs link to the inventory, carry their vulnerability facts, resolve only on a complete run, and
stay out of the Resources "Open findings" count and attack-path severity."""

from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus.collection import CollectOptions, FilesystemRawStore
from argus.findings import FAILING_FINDINGS_SQL, open_finding_counts
from argus.ingest import ingest_run, register_failed_run

DAY = date(2026, 10, 2)


def _scalar(engine: Engine, sql: str, **params: Any) -> Any:
    with engine.connect() as conn:
        return conn.execute(text(sql), params).scalar_one()


def test_cves_link_to_the_inventory_with_their_facts_and_coverage(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    outcome = run_tool(worker, store, target, "vulnerabilities", DAY)
    assert outcome.status == "complete" and outcome.loaded["findings"] > 0
    # Every instance and function CVE resolves to an inventoried resource.
    unlinked = _scalar(
        owner, "SELECT count(*) FROM finding WHERE tool = 'vulnerabilities' AND resource_id IS NULL"
    )
    assert unlinked == 0
    facts = _scalar(
        owner,
        "SELECT count(*) FROM finding f JOIN finding_vulnerability v ON v.finding_id = f.id "
        "WHERE f.tool = 'vulnerabilities'",
    )
    assert facts == outcome.loaded["findings"] == outcome.loaded["vulnerabilities"]
    assert outcome.loaded["skipped type NETWORK_REACHABILITY"] > 0
    with owner.connect() as conn:
        coverage = conn.execute(
            text("SELECT status_code, status_reason FROM vulnerability_coverage")
        ).all()
        types = set(
            conn.execute(
                text(
                    "SELECT DISTINCT check_id LIKE 'code:%' FROM finding "
                    "WHERE tool = 'vulnerabilities'"
                )
            ).scalars()
        )
    assert ("INACTIVE", "UNMANAGED_EC2_INSTANCE") in coverage and (
        "ACTIVE",
        "SUCCESSFUL",
    ) in coverage
    assert types == {True, False}  # package and code vulnerabilities


def test_cves_stay_out_of_open_findings_and_attack_path_severity(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "vulnerabilities", DAY)
    with owner.connect() as conn:
        ids = list(
            conn.execute(
                text("SELECT DISTINCT resource_id FROM finding WHERE tool = 'vulnerabilities'")
            ).scalars()
        )
        failing = conn.execute(
            text(f"SELECT count(*) FROM ({FAILING_FINDINGS_SQL}) f"),  # noqa: S608 - constant
            {"connection_id": target.connection_id},
        ).scalar_one()
        counts = open_finding_counts(conn, ids)
    assert ids and failing == 0 and counts == {}


def test_a_complete_run_resolves_what_it_no_longer_reports_and_a_partial_one_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "vulnerabilities", DAY)
    later = DAY + timedelta(days=30)
    throttled = CollectOptions(synthetic_throttle_share=1.0)
    partial = run_tool(worker, store, target, "vulnerabilities", later, throttled)
    assert partial.status == "partial" and partial.loaded["resolved"] == 0
    complete = run_tool(worker, store, target, "vulnerabilities", later)
    assert complete.status == "complete" and complete.loaded["resolved"] > 0
    resolved = _scalar(
        owner,
        "SELECT count(*) FROM finding WHERE tool = 'vulnerabilities' AND state = 'resolved' "
        "AND resolved_on = :d",
        d=later,
    )
    assert resolved == complete.loaded["resolved"]


def test_a_failed_inspector_run_is_recorded_and_resolves_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Inspector has no metric to carry forward (ADR-0042): a failed run still ends failed,
    with nothing loaded and nothing resolved."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "vulnerabilities", DAY)
    later = DAY + timedelta(days=30)
    with worker.begin() as conn:
        failed = register_failed_run(
            conn,
            connection_id=target.connection_id,
            tool="vulnerabilities",
            source="synthetic",
            day=later,
            run_uid=uuid4(),
            raw_path="",
            started_at=datetime.now(UTC),
            error="the export was killed",
        )
    outcome = ingest_run(worker, store=store, scan_run_id=failed, rules_dir=RULES_DIR)
    assert outcome.status == "failed"
    resolved = _scalar(
        owner, "SELECT count(*) FROM finding WHERE tool = 'vulnerabilities' AND state = 'resolved'"
    )
    assert resolved == 0
