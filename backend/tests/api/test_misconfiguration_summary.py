"""Investigate → Misconfigurations → Summary (owner's decision 2026-11-05): every number is a
stored count, and the list filters its link sets reproduce it (design.md: "Each number opens the
list that holds it, filtered so the list reproduces it")."""

from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import CollectTarget
from argus.core.rawstore import FilesystemRawStore

pytestmark = pytest.mark.db
SEVERITIES = ("critical", "high", "medium", "low", "informational")
# What every summary number counts, as list filters.
BASE: dict[str, Any] = {"state": "open", "status": "FAIL", "muted": "hide", "limit": 1}


def _total(client: TestClient, **filters: Any) -> int:
    response = client.get("/api/v1/findings", params={**BASE, **filters})
    assert response.status_code == 200, response.text
    return int(response.json()["total"])


def _summary(client: TestClient, connection_id: int = 0) -> dict[str, Any]:
    response = client.get("/api/v1/findings/summary", params={"connection_id": connection_id})
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def _scan(
    owner: Engine, worker: Engine, store: FilesystemRawStore, day: date, seed: int = 0
) -> int:
    target = make_demo(owner, seed)
    for tool in ("steampipe", "prowler", "cloudfox"):
        assert run_tool(worker, store, target, tool, day).status in ("complete", "partial")
    return target.connection_id


def test_without_a_scan_every_number_is_null_not_zero(signed_in: TestClient) -> None:
    data = _summary(signed_in)
    assert data["data_through"] is None
    assert data["open"] is None and data["by_category"] is None and data["by_age"] is None
    assert data["last_30_days"] is None
    assert len(data["weeks"]) == 12
    assert all(w["opened"] is None and w["resolved"] is None for w in data["weeks"])


def test_an_inventory_scan_alone_gives_no_summary(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", datetime.now(UTC).date())
    assert _summary(signed_in, target.connection_id)["open"] is None


@pytest.mark.parametrize("scope", ["one", "all"], ids=["one-connection", "all-connections"])
def test_every_number_is_reproduced_by_the_list_it_opens(
    scope: str,
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
) -> None:
    today = datetime.now(UTC).date()
    first = _scan(owner, worker, store, today, seed=0)
    second = _scan(owner, worker, store, today, seed=1)
    cid = first if scope == "one" else 0
    scoped: dict[str, Any] = {"connection_id": [first]} if scope == "one" else {}
    data = _summary(signed_in, cid)
    assert data["data_through"] == today.isoformat()

    open_ = data["open"]
    assert open_["total"] == _total(signed_in, **scoped) > 50
    for severity in SEVERITIES:
        assert open_["severities"][severity] == _total(signed_in, severity=severity, **scoped)
    for tool, n in open_["tools"].items():
        assert n == _total(signed_in, tool=tool, **scoped)
    assert open_["tools"]["cloudfox"] > 0  # both tools are counted

    for key, param in (
        ("by_category", "category"),
        ("by_service", "service"),
        ("by_region", "region"),
    ):
        breakdown = data[key]
        assert breakdown["items"], key
        for item in breakdown["items"][:3]:
            if item["value"]:  # "" (no category, no service) has no list filter
                assert item["total"] == _total(signed_in, **{param: item["value"]}, **scoped), (
                    key,
                    item["value"],
                )
    # Worst first: most critical, then high, then in all.
    ranks = [
        (-i["severities"]["critical"], -i["severities"]["high"], -i["total"])
        for i in data["by_service"]["items"]
    ]
    assert ranks == sorted(ranks)

    ages = data["by_age"]
    assert [a["key"] for a in ages] == [
        "under_30_days",
        "30_to_90_days",
        "90_to_180_days",
        "180_to_365_days",
        "over_a_year",
    ]
    assert sum(a["total"] for a in ages) == open_["total"]
    for age in ages:
        bounds = {k: age[k] for k in ("first_seen_from", "first_seen_to") if age[k] is not None}
        assert age["total"] == _total(signed_in, **bounds, **scoped), age["key"]

    for reach in data["reach"]:
        assert reach["total"] == _total(signed_in, reach=reach["value"], **scoped)

    if scope == "all":
        accounts = data["by_account"]["items"]
        assert {a["connection_id"] for a in accounts} == {first, second}
        for account in accounts:
            assert account["total"] == _total(signed_in, connection_id=[account["connection_id"]])
        assert open_["total"] == sum(a["total"] for a in accounts)
    else:
        assert data["by_account"] is None


def test_a_reach_change_after_a_steampipe_run_reaches_the_summary(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    today = datetime.now(UTC).date()
    cid = _scan(owner, worker, store, today)
    # Clearing every reach by hand stands for a change the next Steampipe run's check reverts:
    # the summary must follow that run, not keep the counts of the Prowler and CloudFox loads.
    with owner.begin() as conn:
        conn.execute(
            text("UPDATE finding SET reach = NULL, reach_reason = NULL WHERE connection_id = :c"),
            {"c": cid},
        )
    run_tool(worker, store, _demo_target(owner, cid), "steampipe", today)
    data = _summary(signed_in, cid)
    for reach in data["reach"]:
        assert reach["total"] == _total(signed_in, reach=reach["value"], connection_id=[cid])
    assert sum(r["total"] for r in data["reach"]) > 0


def _demo_target(owner: Engine, cid: int) -> CollectTarget:
    with owner.connect() as conn:
        account, seed = conn.execute(
            text("SELECT account_id, demo_seed FROM connection WHERE id = :c"), {"c": cid}
        ).one()
    return CollectTarget(cid, "demo", account, seed)


def test_the_weekly_flow_counts_opened_and_resolved(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    today = datetime.now(UTC).date()
    earlier = today - timedelta(days=8)
    target = make_demo(owner)
    run_tool(worker, store, target, "prowler", earlier)
    run_tool(worker, store, target, "prowler", today)
    with owner.connect() as conn:
        events = dict(
            conn.execute(
                text(
                    "SELECT e.event, count(*) FROM finding_event e "
                    "JOIN finding f ON f.id = e.finding_id "
                    "WHERE f.status = 'FAIL' AND NOT f.muted AND e.occurred_on >= :d "
                    "GROUP BY e.event"
                ),
                {"d": today - timedelta(days=29)},
            ).all()
        )
    data = _summary(signed_in, target.connection_id)
    recent = data["last_30_days"]
    assert recent == {
        "opened": events.get("opened", 0),
        "reopened": events.get("reopened", 0),
        "resolved": events.get("resolved", 0),
    }
    assert recent["opened"] > 0
    weeks = data["weeks"]
    assert weeks[-1]["partial"] and not any(w["partial"] for w in weeks[:-1])
    assert sum(w["opened"] or 0 for w in weeks) == recent["opened"]
    # Weeks before the first count have no data; weeks after it are numbers.
    first_week = earlier - timedelta(days=earlier.weekday())
    for week in weeks:
        known = date.fromisoformat(week["week"]) + timedelta(days=6) >= earlier
        assert (week["opened"] is not None) == known, week["week"]
    assert date.fromisoformat(weeks[-1]["week"]) >= first_week


def test_a_late_run_of_an_older_day_keeps_the_newest_counts_current(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A re-derive of an older load, or an older run ingested late, changes the findings as they
    stand now: the counts follow on the newest day, never on the older one alone."""
    today = datetime.now(UTC).date()
    target = make_demo(owner)
    run_tool(worker, store, target, "prowler", today)
    run_tool(worker, store, target, "cloudfox", today - timedelta(days=3))  # ingested after
    for cid in (target.connection_id, 0):
        data = _summary(signed_in, cid)
        assert data["data_through"] == today.isoformat()
        scoped = {"connection_id": [target.connection_id]}
        assert data["open"]["total"] == _total(signed_in, **scoped)
        assert data["open"]["tools"]["cloudfox"] == _total(signed_in, tool="cloudfox", **scoped) > 0
