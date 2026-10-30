from datetime import date, timedelta

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus.collection import CollectOptions, FilesystemRawStore
from argus.collection.synthetic.estate import (
    REGRESSION_BUCKET,
    REGRESSION_CHECK,
    day_number,
)
from argus.collection.synthetic.source import FAIL_EVERY_DAYS
from argus.findings import (
    ANY_REGION,
    FindingResult,
    load_tool_findings,
    put_findings_metrics,
    remove_compliance_items,
)
from argus.findings import prowler as prowler_adapter
from argus.ingest import ingest_run

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)
HISTORY = ("finding", "finding_event", "finding_snapshot", "compliance_snapshot", "metric_daily")


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _counts(engine: Engine) -> dict[str, int]:
    return {t: _count(engine, f"SELECT count(*) FROM {t}") for t in HISTORY}  # noqa: S608


def _day_with_phase(phase: int) -> date:
    return next(
        DAY + timedelta(days=i)
        for i in range(90)
        if day_number(DAY + timedelta(days=i)) % 90 == phase
    )


def test_prowler_run_loads_findings_compliance_and_check_counts(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    outcome = run_tool(worker, store, target, "prowler", DAY)
    assert outcome.status == "complete"
    assert (
        _count(owner, "SELECT count(*) FROM finding WHERE state = 'open'")
        == outcome.loaded["findings"]
        > 50
    )
    with owner.connect() as conn:
        frameworks = set(
            conn.execute(
                text(
                    "SELECT DISTINCT cr.framework FROM compliance_snapshot cs "
                    "JOIN compliance_requirement cr ON cr.id = cs.requirement_id"
                )
            ).scalars()
        )
    assert frameworks == {"cis_6.0_aws", "prowler_threatscore_aws"}
    # compliance/*.ocsf.json (one item per finding and requirement) is never read as findings.
    assert (
        _count(
            owner,
            "SELECT count(*) FROM finding f "
            "WHERE f.tool = 'prowler' AND (f.finding_uid NOT LIKE 'prowler-aws-%' "
            "OR f.check_id = 'manual')",
        )
        == 0
    )
    assert (
        _count(
            owner,
            "SELECT count(*) FROM compliance_requirement WHERE framework = "
            "'prowler_threatscore_aws' AND (weight IS NULL OR level_of_risk IS NULL)",
        )
        == 0
    )
    # One row for the connection and one for the all-connections rollup (connection_id 0).
    assert (
        _count(
            owner,
            "SELECT count(*) FROM metric_daily WHERE metric = 'checks.status' "
            "AND dimension = 'PASS'",
        )
        == 2
    )


def test_replaying_a_prowler_run_changes_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    outcome = run_tool(worker, store, target, "prowler", DAY)
    before = _counts(owner)
    ingest_run(worker, store=store, scan_run_id=outcome.scan_run_id, rules_dir=RULES_DIR)
    assert _counts(owner) == before


def test_the_regression_is_resolved_then_reopened(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    failing = _day_with_phase(29)  # one 90-day cycle: failing, fixed the next day, back at 70
    fixed, back = failing + timedelta(days=1), failing + timedelta(days=41)
    for day in (failing, fixed, back):
        run_tool(worker, store, target, "prowler", day)
    with owner.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM finding WHERE check_id = :c AND finding_uid LIKE :n"),
            {"c": REGRESSION_CHECK, "n": f"%-{REGRESSION_BUCKET}-%"},
        ).scalar_one()
        events = (
            conn.execute(
                text(
                    "SELECT e.event FROM finding_event e JOIN finding f ON f.id = e.finding_id "
                    "WHERE f.check_id = :c AND f.finding_uid LIKE :n ORDER BY e.occurred_on"
                ),
                {"c": REGRESSION_CHECK, "n": f"%-{REGRESSION_BUCKET}-%"},
            )
            .scalars()
            .all()
        )
    assert state == "reopened"
    assert events == ["opened", "resolved", "reopened"]


def test_a_partial_run_resolves_nothing_and_keeps_its_results(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "prowler", DAY)
    open_before = _count(owner, "SELECT count(*) FROM finding WHERE state = 'open'")
    later = DAY + timedelta(days=1)  # carry-forward reaches back at most 31 days
    partial = run_tool(
        worker, store, target, "prowler", later, CollectOptions(synthetic_throttle_share=1.0)
    )
    assert partial.status == "partial"
    assert partial.loaded["resolved"] == 0
    assert _count(owner, "SELECT count(*) FROM finding WHERE state = 'resolved'") == 0
    assert (
        _count(owner, "SELECT count(*) FROM finding WHERE state IN ('open', 'reopened')")
        >= open_before
    )
    assert (
        _count(
            owner,
            "SELECT count(*) FROM metric_daily WHERE snapshot_date = :d "
            "AND metric = 'checks.status'",
            d=later,
        )
        > 0
    )  # the partial run's own check results


def test_a_complete_run_resolves_what_disappeared(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "prowler", DAY)
    complete = run_tool(worker, store, target, "prowler", DAY + timedelta(days=45))
    assert complete.loaded["resolved"] > 0
    assert (
        _count(owner, "SELECT count(*) FROM finding_event WHERE event = 'resolved'")
        == complete.loaded["resolved"]
    )


def test_a_failed_run_loads_and_resolves_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner, seed=1)  # staging
    failing = next(
        DAY + timedelta(days=i)
        for i in range(FAIL_EVERY_DAYS)
        if day_number(DAY + timedelta(days=i)) % FAIL_EVERY_DAYS == 0
    )
    run_tool(worker, store, target, "prowler", failing - timedelta(days=1))
    before = _counts(owner)
    outcome = run_tool(worker, store, target, "prowler", failing)
    assert outcome.status == "failed"
    after = _counts(owner)
    del before["metric_daily"], after["metric_daily"]
    # The requirement results are carried forward with the metrics (Compliance screen); the
    # findings and their history are untouched.
    assert after.pop("compliance_snapshot") == 2 * before.pop("compliance_snapshot")
    assert after == before
    # The failed day carries the previous day's values forward: no gap, no false fix.
    with owner.connect() as conn:
        sql = text(
            "SELECT metric, dimension, value FROM metric_daily WHERE snapshot_date = :d "
            "AND connection_id = :c AND metric = 'findings.open_by_severity'"
        )
        today = set(conn.execute(sql, {"d": failing, "c": target.connection_id}).tuples())
        yesterday = set(
            conn.execute(
                sql, {"d": failing - timedelta(days=1), "c": target.connection_id}
            ).tuples()
        )
    assert today == yesterday != set()


def test_an_unsupported_prowler_version_is_refused(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prowler_adapter, "SUPPORTED_VERSIONS", frozenset({"9.9.9"}))
    outcome = run_tool(worker, store, make_demo(owner), "prowler", DAY)
    assert outcome.status == "failed" and "not supported" in (outcome.error or "")
    assert _count(owner, "SELECT count(*) FROM finding") == 0


def test_no_secret_value_reaches_the_finding_table(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    run_tool(worker, store, make_demo(owner), "prowler", DAY)
    with owner.connect() as conn:
        dump = " ".join(conn.execute(text("SELECT f::text FROM finding f")).scalars())
        dump += " ".join(conn.execute(text("SELECT c::text FROM finding_check_text c")).scalars())
    assert "pw-" not in dump


def test_each_finding_says_what_is_wrong_and_each_check_how_to_fix_it(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    run_tool(worker, store, make_demo(owner), "prowler", DAY)
    with owner.connect() as conn:
        missing = conn.execute(
            text("SELECT count(*) FROM finding WHERE detail IS NULL OR resource_name IS NULL")
        ).scalar_one()
        checks = conn.execute(text("SELECT * FROM finding_check_text")).all()
        unexplained = conn.execute(
            text(
                "SELECT count(*) FROM finding f WHERE NOT EXISTS (SELECT 1 "
                "FROM finding_check_text c WHERE c.tool = f.tool AND c.check_id = f.check_id)"
            )
        ).scalar_one()
    assert missing == 0 and unexplained == 0
    assert all(c.tool_version == "5.45.0" and c.description and c.risk for c in checks)
    assert all(link.startswith(("https://", "http://")) for c in checks for link in c.links)
    # The code comes from the findings CSV (the OCSF file has none).
    assert any(c.code_cli for c in checks) and any(c.code_terraform for c in checks)


def test_only_the_code_columns_of_the_findings_csv_are_read() -> None:
    """RESOURCE_DETAILS and the other columns can hold secret values: they are never read."""
    planted = "pw-0123456789ab"
    header = "CHECK_ID;RESOURCE_DETAILS;STATUS_EXTENDED;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER"
    rows = [
        f"s3_check;{planted};{planted};aws s3api get-bucket-acl --bucket b;",
        f"s3_check;{planted};x;a second row of the same check;",
    ]
    code = prowler_adapter._code("\r\n".join([header, *rows]) + "\r\n", quoted=False)
    assert code == {"s3_check": {"code_cli": "aws s3api get-bucket-acl --bucket b"}}
    assert planted not in repr(code)


def test_a_run_covering_any_region_resolves_findings_in_every_region(owner: Engine) -> None:
    """A real CloudFox run scans every enabled region without listing them (ANY_REGION)."""
    target = make_demo(owner)
    finding = FindingResult(
        finding_uid="cloudfox-any-region-test",
        check_id="cloudfox_env_var_secret",
        status="FAIL",
        muted=False,
        severity="high",
        region="ap-northeast-1",
        resource_uid="aws:arn:aws:lambda:ap-northeast-1:100000000010:function:f",
        title="A secret in an environment variable",
        remediation_text=None,
        remediation_url=None,
        compliance={},
    )
    with owner.begin() as conn:
        run_id = conn.execute(
            text(
                "INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source, "
                "snapshot_date, status, started_at, raw_path) VALUES (gen_random_uuid(), :c, "
                "'cloudfox', '2.0.5', 'aws', :d, 'complete', now(), 'x') RETURNING id"
            ),
            {"c": target.connection_id, "d": DAY},
        ).scalar_one()
        common = {
            "tool": "cloudfox",
            "complete": True,
            "connection_id": target.connection_id,
            "account_id": target.account_id,
            "scan_run_id": run_id,
        }
        load_tool_findings(
            conn,
            findings=[finding],
            executed=frozenset({(finding.check_id, ANY_REGION)}),
            day=DAY,
            **common,  # type: ignore[arg-type]
        )
        loaded = load_tool_findings(
            conn,
            findings=[],
            executed=frozenset({(finding.check_id, ANY_REGION)}),
            day=DAY + timedelta(days=1),
            **common,  # type: ignore[arg-type]
        )
    assert loaded["resolved"] == 1


def test_findings_read_from_compliance_items_are_removed_and_the_metrics_rebuilt(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Migration 0023: rows the adapter once read from compliance/*.ocsf.json go; a real
    finding whose uid extends another's (resource "alb" and "alb-2") stays."""
    target = make_demo(owner)
    run_tool(worker, store, target, "prowler", DAY)
    before = _counts(owner)
    open_total = (
        "SELECT sum(value) FROM metric_daily WHERE metric = 'findings.open_by_severity' "
        "AND connection_id = :c AND snapshot_date = :d"
    )
    with owner.begin() as conn:
        base = conn.execute(
            text("SELECT * FROM finding WHERE status = 'FAIL' AND NOT muted ORDER BY id LIMIT 1")
        ).one()
        clone = (
            "INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, "
            "resource_uid, severity, status, title, state, first_seen, last_seen) "
            "SELECT :uid, tool, :check, connection_id, region, resource_uid, severity, status, "
            ":title, state, first_seen, last_seen FROM finding WHERE id = :id RETURNING id"
        )
        rows = {
            "item": (f"{base.finding_uid}-1.1", base.check_id, "1.1"),
            "manual": ("manual-2.1", "manual", "2.1"),
            "sibling": (f"{base.finding_uid}-2", base.check_id, base.title),
        }
        ids = {}
        for name, (uid, check, title) in rows.items():
            ids[name] = conn.execute(
                text(clone), {"uid": uid, "check": check, "title": title, "id": base.id}
            ).scalar_one()
            conn.execute(
                text(
                    "INSERT INTO finding_snapshot (snapshot_date, finding_id, status, severity, "
                    "muted) SELECT snapshot_date, :f, status, severity, muted "
                    "FROM finding_snapshot WHERE finding_id = :base AND snapshot_date = :d"
                ),
                {"d": DAY, "f": ids[name], "base": base.id},
            )
        put_findings_metrics(conn, connection_id=target.connection_id, day=DAY)
        inflated = conn.execute(
            text(open_total), {"c": target.connection_id, "d": DAY}
        ).scalar_one()

    with owner.begin() as conn:
        assert remove_compliance_items(conn) == 2
        restored = conn.execute(
            text(open_total), {"c": target.connection_id, "d": DAY}
        ).scalar_one()
        left = set(conn.execute(text("SELECT id FROM finding")).scalars())
    assert ids["sibling"] in left and not {ids["item"], ids["manual"]} & left
    assert restored == inflated - 2
    after = _counts(owner)
    assert after["finding"] == before["finding"] + 1
    assert after["finding_snapshot"] == before["finding_snapshot"] + 1
