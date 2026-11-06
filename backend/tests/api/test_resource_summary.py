"""Investigate → Resources → Summary (owner's decisions 2026-11-06): every number is a stored
count, and the list filters its link sets reproduce it (design.md: "Each number opens the list
that holds it, filtered so the list reproduces it")."""

from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus import findings
from argus.collection import TOOL_ORDER, CollectTarget
from argus.core.rawstore import FilesystemRawStore
from argus.ingest import ingest_run, register_failed_run

pytestmark = pytest.mark.db
# What every summary number counts, as list filters: the current inventory's assets.
BASE: dict[str, Any] = {"assets": True, "limit": 1}


def _total(client: TestClient, **filters: Any) -> int:
    response = client.get("/api/v1/resources", params={**BASE, **filters})
    assert response.status_code == 200, response.text
    return int(response.json()["total"])


def _summary(client: TestClient, connection_id: int = 0) -> dict[str, Any]:
    response = client.get("/api/v1/resources/summary", params={"connection_id": connection_id})
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def _scan(
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    day: date,
    seed: int = 0,
    tools: tuple[str, ...] = tuple(TOOL_ORDER),
) -> CollectTarget:
    target = make_demo(owner, seed)
    for tool in tools:
        assert run_tool(worker, store, target, tool, day).status in ("complete", "partial")
    return target


def test_without_a_scan_every_number_is_null_not_zero(signed_in: TestClient) -> None:
    data = _summary(signed_in)
    assert data["data_through"] is None and data["assets"] is None
    assert data["by_type"] is None and data["by_region"] is None and data["by_account"] is None
    assert data["at_risk"] == {"critical_high": None, "reachable": None, "exploitable": None}
    assert data["last_30_days"] is None
    assert len(data["weeks"]) == 12 and all(w["added"] is None for w in data["weeks"])


def test_an_inventory_alone_has_no_risk_counts(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = _scan(owner, worker, store, datetime.now(UTC).date(), tools=("steampipe",))
    data = _summary(signed_in, target.connection_id)
    assert data["assets"]["total"] == _total(signed_in, connection_id=[target.connection_id]) > 0
    # No Prowler, CloudFox or vulnerabilities scan: "no scan yet", never 0.
    assert data["at_risk"] == {"critical_high": None, "reachable": None, "exploitable": None}


@pytest.mark.parametrize("scope", ["one", "all"], ids=["one-connection", "all-connections"])
def test_every_number_is_reproduced_by_the_list_it_opens(
    scope: str,
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
) -> None:
    today = datetime.now(UTC).date()
    first = _scan(owner, worker, store, today, seed=0).connection_id
    second = _scan(owner, worker, store, today, seed=1).connection_id
    cid = first if scope == "one" else 0
    scoped: dict[str, Any] = {"connection_id": [first]} if scope == "one" else {}
    data = _summary(signed_in, cid)
    assert data["data_through"] == today.isoformat()

    assets = data["assets"]
    assert assets["total"] == _total(signed_in, **scoped) > 20
    assert assets["total"] < _total(signed_in, **scoped, assets=False)  # parts are left out
    assert assets["accounts"] == (1 if scope == "one" else 2)

    at_risk = data["at_risk"]
    for key, filters in (
        ("critical_high", {"misconfigurations": "high"}),
        ("reachable", {"internet": True}),
        ("exploitable", {"vulnerabilities": "exploitable"}),
    ):
        assert at_risk[key]["as_of"] == today.isoformat(), key
        assert at_risk[key]["count"] == _total(signed_in, **filters, **scoped), key
    assert at_risk["critical_high"]["count"] > 0 and at_risk["exploitable"]["count"] > 0

    by_type = data["by_type"]
    assert sum(t["count"] for t in by_type) == assets["total"]
    assert [t["count"] for t in by_type] == sorted((t["count"] for t in by_type), reverse=True)
    for item in by_type[:3]:
        assert item["count"] == _total(signed_in, type=[item["type"]], **scoped), item
    regions = data["by_region"]
    assert assets["regions"] == len(regions["items"]) + regions["more"]
    for item in regions["items"][:3]:
        assert item["total"] == _total(signed_in, region=[item["value"]], **scoped), item

    if scope == "all":
        accounts = data["by_account"]["items"]
        assert {a["connection_id"] for a in accounts} == {first, second}
        for account in accounts:
            assert account["total"] == _total(signed_in, connection_id=[account["connection_id"]])
        assert assets["total"] == sum(a["total"] for a in accounts)
    else:
        assert data["by_account"] is None


def test_the_first_scan_is_a_baseline_and_later_scans_count_what_changed(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    today = datetime.now(UTC).date()
    earlier = today - timedelta(days=8)
    target = _scan(owner, worker, store, earlier, tools=("steampipe",))
    cid = target.connection_id
    first = _summary(signed_in, cid)
    assert first["last_30_days"] == {"added": 0, "removed": 0, "baseline": 1}
    baseline_weeks = [w for w in first["weeks"] if w["baseline"]]
    assert len(baseline_weeks) == 1
    week = date.fromisoformat(baseline_weeks[0]["week"])
    assert week <= earlier < week + timedelta(days=7)

    assert run_tool(worker, store, target, "steampipe", today).status in ("complete", "partial")
    with owner.connect() as conn:
        added, removed = conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE first_seen = :d), "
                "count(*) FILTER (WHERE deleted_on = :d) FROM resource "
                "WHERE connection_id = :c AND asset"
            ),
            {"d": today, "c": cid},
        ).one()
    data = _summary(signed_in, cid)
    assert data["last_30_days"] == {"added": added, "removed": removed, "baseline": 1}
    assert added + removed > 0  # the Demo estate changes between the two days
    day = {"connection_id": [cid]}
    # The bars' links: first seen, or removed, in the week.
    assert added == _total(
        signed_in, **day, first_seen_from=today, first_seen_to=today, include_deleted=True
    )
    assert removed == _total(signed_in, **day, deleted_from=today, deleted_to=today)


def test_a_clean_scanned_account_reads_zero_not_null(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    today = datetime.now(UTC).date()
    target = _scan(owner, worker, store, today)
    cid = target.connection_id
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE finding SET state = 'resolved', resolved_on = :d WHERE connection_id = :c"
            ),
            {"c": cid, "d": today},
        )
        findings.put_misconfiguration_metrics(conn, connection_id=cid, day=today)
        findings.put_vulnerability_metrics(conn, connection_id=cid, day=today)
    at_risk = _summary(signed_in, cid)["at_risk"]
    for key in ("critical_high", "reachable", "exploitable"):
        assert at_risk[key] == {"count": 0, "as_of": today.isoformat()}, key


def test_a_steampipe_run_recounts_the_exploitable_assets(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A removed asset leaves the exploitable count at the next Steampipe load, not at the next
    vulnerabilities run (ADR-0042 amended 2026-11-06)."""
    today = datetime.now(UTC).date()
    earlier = today - timedelta(days=3)
    target = _scan(owner, worker, store, earlier, tools=("steampipe", "vulnerabilities"))
    assert run_tool(worker, store, target, "steampipe", today).status in ("complete", "partial")
    exploitable = _summary(signed_in, target.connection_id)["at_risk"]["exploitable"]
    assert exploitable["as_of"] == today.isoformat()
    assert exploitable["count"] == _total(
        signed_in, connection_id=[target.connection_id], vulnerabilities="exploitable"
    )


def test_a_failed_steampipe_run_leaves_the_inventory_as_it_was(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    today = datetime.now(UTC).date()
    earlier = today - timedelta(days=5)
    target = _scan(owner, worker, store, earlier, tools=("steampipe",))
    before = _summary(signed_in, target.connection_id)
    before_all = _summary(signed_in)
    with worker.begin() as conn:
        failed = register_failed_run(
            conn,
            connection_id=target.connection_id,
            tool="steampipe",
            source="synthetic",
            day=today,
            run_uid=uuid4(),
            raw_path="",
            started_at=datetime.now(UTC),
            error="the export was killed",
        )
    assert ingest_run(worker, store=store, scan_run_id=failed, rules_dir=RULES_DIR).status == (
        "failed"
    )
    for cid, then in ((target.connection_id, before), (0, before_all)):
        after = _summary(signed_in, cid)
        assert after["data_through"] == earlier.isoformat(), cid  # the list's day too
        assert after["assets"] == then["assets"], cid
        assert after["by_type"] == then["by_type"], cid
        assert after["last_30_days"] == then["last_30_days"], cid  # nothing added or removed


def test_the_overview_reads_the_same_assets(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """The Overview's asset KPI and inventory read the rows the Resources summary reads, rolled
    up as one family (store.rollup_family on assets.total)."""
    today = datetime.now(UTC).date()
    _scan(owner, worker, store, today, seed=0, tools=("steampipe",))
    _scan(owner, worker, store, today, seed=1, tools=("steampipe",))
    overview = signed_in.get("/api/v1/overview").json()
    data = _summary(signed_in)
    assert overview["kpis"]["assets"]["value"] == data["assets"]["total"]
    assert {t["type"]: t["count"] for t in overview["inventory"]["by_type"]} == {
        t["type"]: t["count"] for t in data["by_type"]
    }
