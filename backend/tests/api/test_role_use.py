"""Resources → role use (owner's decisions 2026-11-17, palace decisions/156b6e38): each IAM
role's last use as AWS records it, kept apart from its configuration, and how many workloads run
as it. Missing data is null ("not covered"), never a zero, and a bad run never makes a role look
unused."""

import threading
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus import inventory
from argus.collection.synthetic.estate import SCENARIO_ROLE
from argus.core.rawstore import FilesystemRawStore
from argus.inventory.steampipe import _last_used as last_used_of
from argus.relationships import put_role_workloads

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)
ROLE = "aws_iam_role"


def _rows(engine: Engine, sql: str, **params: object) -> list[Any]:
    with engine.connect() as conn:
        return list(conn.execute(text(sql), params))


def _roles(client: TestClient, **filters: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    while True:
        response = client.get(
            "/api/v1/resources",
            params={"type": ROLE, "limit": 200, "offset": len(items), **filters},
        )
        assert response.status_code == 200, response.text
        page = response.json()
        items += page["items"]
        if len(items) >= page["total"]:
            return items


def test_before_any_scan_a_role_has_no_use_at_all(signed_in: TestClient) -> None:
    assert _roles(signed_in) == []
    assert _roles(signed_in, role_unused=90) == []


def test_a_roles_last_use_is_kept_apart_from_its_configuration(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    rows = _rows(
        owner,
        "SELECT r.id, r.config_id, rl.last_used_at, rl.last_used_region, rl.observed_on, "
        "rc.config FROM resource r JOIN resource_config rc ON rc.id = r.config_id "
        "LEFT JOIN role_last_used rl ON rl.resource_id = r.id WHERE r.type = :t",
        t=ROLE,
    )
    assert len(rows) > 10
    assert all(r.observed_on == DAY for r in rows)  # every role read
    assert any(r.last_used_at is None for r in rows) and any(r.last_used_at for r in rows)
    assert all((r.last_used_region is None) == (r.last_used_at is None) for r in rows)
    assert all("role_last_used_date" not in r.config for r in rows)

    # A role used every day gets a new reading, not a new configuration.
    later = DAY + timedelta(days=1)
    run_tool(worker, store, target, "steampipe", later)
    after = {
        r.id: r
        for r in _rows(
            owner,
            "SELECT r.id, r.config_id, rl.last_used_at, rl.observed_on FROM resource r "
            "JOIN role_last_used rl ON rl.resource_id = r.id WHERE r.type = :t",
            t=ROLE,
        )
    }
    moved = [r for r in rows if r.last_used_at and after[r.id].last_used_at != r.last_used_at]
    assert moved, "the synthetic estate has roles used daily"
    assert all(after[r.id].config_id == r.config_id for r in moved)
    assert all(a.observed_on == later for a in after.values())


def test_a_run_without_the_role_table_keeps_the_last_reading(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    role = _rows(
        owner,
        "SELECT r.id, r.resource_uid, rl.last_used_at FROM resource r "
        "JOIN role_last_used rl ON rl.resource_id = r.id "
        "WHERE r.type = :t AND rl.last_used_at IS NOT NULL LIMIT 1",
        t=ROLE,
    )[0]
    wiped = {role.resource_uid: (None, None)}

    def load(day: date, complete: frozenset[str]) -> None:
        batch = inventory.InventoryBatch(
            resources=[],
            tables_seen=frozenset({ROLE}),
            complete=False,
            complete_types=complete,
            carry_types=None,
            role_last_used=wiped,
        )
        with worker.begin() as conn:
            inventory.load_inventory(conn, batch=batch, connection_id=target.connection_id, day=day)

    # Failed, denied or throttled: the role table is not complete, so nothing is replaced.
    load(DAY + timedelta(days=5), frozenset())
    # A re-run of an older day never replaces a newer reading.
    load(DAY - timedelta(days=5), frozenset({ROLE}))
    kept = _rows(
        owner,
        "SELECT last_used_at, observed_on FROM role_last_used WHERE resource_id = :i",
        i=role.id,
    )[0]
    assert kept.last_used_at == role.last_used_at and kept.observed_on == DAY


def test_workloads_are_counted_at_each_rule_load(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    rows = {
        r.name: r
        for r in _rows(
            owner,
            "SELECT r.name, rw.workloads, rw.rule_day FROM resource r "
            "LEFT JOIN role_workload rw ON rw.resource_id = r.id "
            "WHERE r.type = :t AND r.deleted_on IS NULL",
            t=ROLE,
        )
    }
    assert all(r.rule_day == DAY for r in rows.values())  # every current role counted
    assert rows[SCENARIO_ROLE].workloads >= 1  # the scenario instance runs as it
    assert any(r.workloads == 0 for r in rows.values())
    # Equal to the role's RUNS_AS lines of that load.
    lines = _rows(
        owner,
        "SELECT count(DISTINCT e.source_uid) FROM edge e "
        "JOIN edge_snapshot es ON es.edge_id = e.id AND es.snapshot_date = :d "
        "JOIN resource r ON r.id = e.target_resource_id "
        "WHERE e.type = 'RUNS_AS' AND r.name = :n AND r.type = :t",
        d=DAY,
        n=SCENARIO_ROLE,
        t=ROLE,
    )[0][0]
    assert rows[SCENARIO_ROLE].workloads == lines

    # A later load exists: re-writing an older day changes nothing.
    run_tool(worker, store, target, "steampipe", DAY + timedelta(days=1))
    with worker.begin() as conn:
        assert put_role_workloads(conn, connection_id=target.connection_id, day=DAY) == 0
    days = _rows(owner, "SELECT DISTINCT rule_day FROM role_workload")
    assert [d.rule_day for d in days] == [DAY + timedelta(days=1)]


def test_the_list_shows_each_roles_use_and_filters_on_it(
    owner: Engine, worker: Engine, store: FilesystemRawStore, signed_in: TestClient
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    every = _roles(signed_in)
    assert every and all(r["role_use"] is not None for r in every)
    assert all(r["role_use"]["observed_on"] == DAY.isoformat() for r in every)
    assert all(r["role_use"]["tracking_days"] == 400 for r in every)
    assert all(isinstance(r["role_use"]["workloads"], int) for r in every)
    # Other types carry none.
    other = signed_in.get(
        "/api/v1/resources", params={"type": "aws_ec2_instance", "limit": 5}
    ).json()
    assert other["items"] and all(r["role_use"] is None for r in other["items"])

    def idle(r: dict[str, Any], days: int) -> bool:
        used = r["role_use"]["last_used_at"]
        return used is None or date.fromisoformat(used[:10]) < DAY - timedelta(days=days)

    for days in (90, 180, 365):
        listed = {r["id"] for r in _roles(signed_in, role_unused=days)}
        assert listed == {r["id"] for r in every if idle(r, days)}, days
    assert {r["id"] for r in _roles(signed_in, role_unused=90)} - {
        r["id"] for r in every if r["role_use"]["last_used_at"] is None
    }, "some roles were used, but not in the last 90 days"

    idle_roles = {r["id"] for r in _roles(signed_in, no_workload=True)}
    assert idle_roles == {r["id"] for r in every if r["role_use"]["workloads"] == 0}
    # Both filters together: the intersection.
    both = {r["id"] for r in _roles(signed_in, role_unused=90, no_workload=True)}
    assert both == idle_roles & {r["id"] for r in every if idle(r, 90)}

    one = every[0]
    detail = signed_in.get(f"/api/v1/resources/{one['id']}").json()
    assert detail["role_use"] == one["role_use"]


def test_a_role_unused_value_outside_the_choices_is_refused(signed_in: TestClient) -> None:
    for bad in ("30", "0", "never", "90.0"):
        response = signed_in.get("/api/v1/resources", params={"role_unused": bad})
        assert response.status_code == 422, bad


def test_a_role_not_read_yet_says_so(
    owner: Engine, worker: Engine, store: FilesystemRawStore, signed_in: TestClient
) -> None:
    """A role inventoried before migration 0053, or by a run whose role table failed: no
    reading, so the list says not collected, and no filter counts it as unused."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    with owner.begin() as conn:
        conn.execute(text("DELETE FROM role_last_used"))
        conn.execute(text("DELETE FROM role_workload"))
    every = _roles(signed_in)
    assert every and all(
        r["role_use"]["observed_on"] is None
        and r["role_use"]["last_used_at"] is None
        and r["role_use"]["workloads"] is None
        for r in every
    )
    assert _roles(signed_in, role_unused=365) == []
    assert _roles(signed_in, no_workload=True) == []


def test_two_rule_loads_of_one_account_rewrite_its_counts_in_turn(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Review 2026-11-18: two ingests of one account can run together on Kubernetes. Each
    rewrites the account's counts (delete, then insert); the second waits for the first instead
    of inserting on top of its rows and failing its rule load."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    failed: list[BaseException] = []

    def second() -> None:
        try:
            with worker.begin() as conn:
                put_role_workloads(conn, connection_id=target.connection_id, day=DAY)
        except BaseException as exc:  # reported by the test
            failed.append(exc)

    with worker.connect() as first:
        with first.begin():
            assert put_role_workloads(first, connection_id=target.connection_id, day=DAY) > 0
            thread = threading.Thread(target=second)
            thread.start()
            thread.join(timeout=1)
            assert thread.is_alive(), "the second rewrite did not wait for the first"
        thread.join(timeout=30)
    assert not thread.is_alive() and not failed, failed
    counted = _rows(
        owner, "SELECT count(*) FROM role_workload WHERE connection_id = :c", c=target.connection_id
    )[0][0]
    assert counted > 0


@pytest.mark.parametrize(
    ("row", "read"),
    [
        ({"role_last_used_date": None, "role_last_used_region": None}, (None, None)),
        (
            {"role_last_used_date": "2026-10-01T09:30:00Z", "role_last_used_region": "eu-west-1"},
            (datetime(2026, 10, 1, 9, 30, tzinfo=UTC), "eu-west-1"),
        ),
        ({"role_last_used_date": "yesterday"}, None),
        ({"role_last_used_date": "2026-10-01T09:30:00"}, None),  # no zone: not trusted
        ({}, None),  # the export left the column out: says nothing
    ],
    ids=["no-use", "used", "not-a-date", "no-zone", "column-missing"],
)
def test_a_role_rows_last_use_is_read_only_when_the_row_says_it(
    row: dict[str, Any], read: Any
) -> None:
    """Review 2026-11-18: a row without the column is not AWS saying "no use"; the role keeps
    its last value (None here means nothing is written)."""
    assert last_used_of(row) == read
