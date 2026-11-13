"""Risk (ADR-0049): named combinations of facts on one resource, recomputed after every ingest.

The Demo estate produces every combination across seeds 0 to 2, through the real pipeline. The
tests then change one stored fact at a time, as a later scan would, and refresh."""

from datetime import date, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus import risk
from argus.collection import TOOL_ORDER, CollectOptions, CollectTarget, FilesystemRawStore
from argus.ingest.rederive import refresh_stale_risk
from argus.risk.combinations import COMBINATIONS, Facts, matched, sort_key

pytestmark = pytest.mark.db
DAY = date(2026, 10, 9)
LATER = DAY + timedelta(days=15)


def _scan(owner: Engine, worker: Engine, store: FilesystemRawStore, seed: int) -> CollectTarget:
    target = make_demo(owner, seed)
    for tool in TOOL_ORDER:
        assert run_tool(worker, store, target, tool, DAY).status in ("complete", "partial")
    return target


def _rows(owner: Engine, connection_id: int) -> dict[int, dict[str, Any]]:
    with owner.connect() as conn:
        rows = conn.execute(
            text("SELECT * FROM resource_risk WHERE connection_id = :c"), {"c": connection_id}
        )
        return {r.resource_id: dict(r._mapping) for r in rows}


def _refresh(worker: Engine, connection_id: int, day: date = LATER) -> risk.Refreshed:
    with worker.begin() as conn:
        return risk.refresh(conn, connection_id=connection_id, day=day)


def _one(rows: dict[int, dict[str, Any]], combination: str) -> dict[str, Any]:
    return next(r for r in rows.values() if combination in r["combinations"])


def _counts(owner: Engine, connection_id: int) -> dict[str, float]:
    with owner.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT dimension, value FROM metric_daily
                WHERE metric = 'risk.resources' AND connection_id = :c
                  AND snapshot_date = (SELECT max(snapshot_date) FROM metric_daily
                                       WHERE metric = 'risk.resources' AND connection_id = :c
                                         AND dimension = 'total')
            """),
            {"c": connection_id},
        )
        return {d: float(v) for d, v in rows}


def test_the_demo_estate_produces_every_combination(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    seen: set[str] = set()
    for seed in (0, 1, 2):
        target = _scan(owner, worker, store, seed)
        rows = _rows(owner, target.connection_id)
        assert rows, f"seed {seed}: nothing at risk"
        for row in rows.values():
            seen.update(row["combinations"])
            assert row["first_seen"] == DAY
            assert row["tier"] == max(
                (c.tier for c in COMBINATIONS if c.id in row["combinations"]),
                key=risk.TIERS[::-1].index,
            )
    assert seen == {c.id for c in COMBINATIONS}


def test_counts_match_the_rows_and_a_second_refresh_writes_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = _scan(owner, worker, store, 0)
    rows = _rows(owner, target.connection_id)
    counts = _counts(owner, target.connection_id)
    assert counts["total"] == len(rows)
    for tier in risk.TIERS:
        assert counts[f"tier:{tier}"] == sum(r["tier"] == tier for r in rows.values())
    for c in COMBINATIONS:
        assert counts[f"combination:{c.id}"] == sum(
            c.id in r["combinations"] for r in rows.values()
        )
    again = _refresh(worker, target.connection_id, DAY)
    assert again.written == 0 and again.removed == 0 and again.at_risk == len(rows)


def test_the_list_is_worst_first(owner: Engine, worker: Engine, store: FilesystemRawStore) -> None:
    target = _scan(owner, worker, store, 0)
    with owner.connect() as conn:
        page, total = risk.list_risk(
            conn,
            filters=risk.RiskFilters(connection_ids=(target.connection_id,)),
            limit=200,
            offset=0,
        )
    assert total == len(page) == len(_rows(owner, target.connection_id))
    tiers = [risk.TIERS.index(r["tier"]) for r in page]
    assert tiers == sorted(tiers)
    assert page[0]["tier"] == "critical"


@pytest.mark.parametrize(
    "change",
    [
        "UPDATE finding SET state = 'resolved', resolved_on = last_seen WHERE id = ANY(:ids)",
        "UPDATE finding SET muted = true WHERE id = ANY(:ids)",
        "UPDATE finding SET state = 'accepted_risk', accepted_until = last_seen + 90 "
        "WHERE id = ANY(:ids)",
    ],
    ids=["resolved", "muted", "accepted-risk"],
)
def test_a_row_leaves_when_its_finding_stops_being_open(
    owner: Engine, worker: Engine, store: FilesystemRawStore, change: str
) -> None:
    target = _scan(owner, worker, store, 0)
    row = _one(_rows(owner, target.connection_id), "exploitable-fixable")
    with owner.begin() as conn:
        ids = (
            conn.execute(
                text("SELECT id FROM finding WHERE resource_id = :r AND tool = 'vulnerabilities'"),
                {"r": row["resource_id"]},
            )
            .scalars()
            .all()
        )
        conn.execute(text(change), {"ids": list(ids)})
    result = _refresh(worker, target.connection_id)
    assert result.removed >= 1
    assert row["resource_id"] not in _rows(owner, target.connection_id)


def test_a_removed_resource_leaves(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = _scan(owner, worker, store, 0)
    row = _one(_rows(owner, target.connection_id), "reachable-exploitable")
    with owner.begin() as conn:
        conn.execute(
            text("UPDATE resource SET deleted_on = :d WHERE id = :r"),
            {"d": LATER, "r": row["resource_id"]},
        )
    _refresh(worker, target.connection_id)
    assert row["resource_id"] not in _rows(owner, target.connection_id)


def _set_door(owner: Engine, resource_id: int, edge_type: str) -> None:
    with owner.begin() as conn:
        conn.execute(
            text("""
                UPDATE edge SET type = :t
                WHERE source_uid = 'internet' AND target_resource_id = :r
                  AND type IN ('ROUTES_TO', 'PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED')
            """),
            {"t": edge_type, "r": resource_id},
        )


def test_a_door_that_turns_unknown_is_held_not_dropped(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Missing data never removes a row (ADR-0049 section 5): the row stays with its first-seen
    day and counts, and says since when its reach was not re-checked."""
    target = _scan(owner, worker, store, 0)
    row = _one(_rows(owner, target.connection_id), "reachable-exploitable")
    before = _counts(owner, target.connection_id)
    _set_door(owner, row["resource_id"], "PUBLIC_UNVERIFIED")
    _refresh(worker, target.connection_id)
    held = _rows(owner, target.connection_id)[row["resource_id"]]
    assert held["combinations"] == row["combinations"]
    assert held["first_seen"] == DAY and held["door"] and held["door_held_since"] == LATER
    assert _counts(owner, target.connection_id) == before
    # Held again later: the day it was first held stays.
    _refresh(worker, target.connection_id, LATER + timedelta(days=15))
    assert _rows(owner, target.connection_id)[row["resource_id"]]["door_held_since"] == LATER
    # A load that covered the door and found it restricted: the door's combinations leave.
    _set_door(owner, row["resource_id"], "PUBLIC_RESTRICTED")
    _refresh(worker, target.connection_id)
    after = _rows(owner, target.connection_id).get(row["resource_id"])
    assert after is None or not {"reachable-exploitable"} & set(after["combinations"])
    if after is not None:  # its exploitable CVE has a fix: it is Medium now, not gone
        assert after["combinations"] == ["exploitable-fixable"] and not after["door"]


def test_rules_purged_by_retention_hold_the_edge_facts(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """An account scanned too long ago loses its rule loads to retention: its doors,
    administrators and credentials are unknown then, not gone, so its rows stay."""
    target = _scan(owner, worker, store, 0)
    before = _rows(owner, target.connection_id)
    with owner.begin() as conn:
        conn.execute(
            text("DELETE FROM edge_load WHERE connection_id = :c"), {"c": target.connection_id}
        )
    _refresh(worker, target.connection_id)
    after = _rows(owner, target.connection_id)
    assert set(after) == set(before)
    for rid, row in after.items():
        assert row["combinations"] == before[rid]["combinations"]
        assert row["admin"] == before[rid]["admin"]
        assert row["credential_kinds"] == before[rid]["credential_kinds"]
        assert (row["door_held_since"] is not None) == before[rid]["door"]


def test_a_new_resource_with_an_unknown_door_is_not_counted_as_open(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = _scan(owner, worker, store, 0)
    row = _one(_rows(owner, target.connection_id), "reachable-exploitable")
    with owner.begin() as conn:
        conn.execute(
            text("DELETE FROM resource_risk WHERE resource_id = :r"), {"r": row["resource_id"]}
        )
    _set_door(owner, row["resource_id"], "PUBLIC_UNVERIFIED")
    _refresh(worker, target.connection_id)
    after = _rows(owner, target.connection_id).get(row["resource_id"])
    assert after is None or not after["door"]


def test_a_start_refreshes_what_was_never_computed_or_computed_differently(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    scanned = _scan(owner, worker, store, 0)
    never_scanned = make_demo(owner, 1)
    with owner.begin() as conn:
        conn.execute(text("DELETE FROM risk_load"))
        conn.execute(text("DELETE FROM resource_risk"))
    with owner.connect() as conn:
        assert risk.stale_connections(conn) == [scanned.connection_id, never_scanned.connection_id]
    # The scanned one is computed on its data's day; the other stays "not computed yet".
    assert refresh_stale_risk(worker, today=LATER) == [scanned.connection_id]
    with owner.connect() as conn:
        assert risk.risk_scope(conn, connection_ids=(scanned.connection_id,)) == risk.RiskScope(
            True, DAY
        )
        assert risk.risk_scope(
            conn, connection_ids=(never_scanned.connection_id,)
        ) == risk.RiskScope(False, None)
        assert risk.stale_connections(conn) == [never_scanned.connection_id]
    assert _rows(owner, scanned.connection_id)
    # A release that changes the combination set refreshes it once more.
    with owner.begin() as conn:
        conn.execute(text("UPDATE risk_load SET combination_set = repeat('0', 64)"))
    with owner.connect() as conn:
        assert scanned.connection_id in risk.stale_connections(conn)


def test_a_disabled_connection_leaves_the_list(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = _scan(owner, worker, store, 0)
    with owner.begin() as conn:
        conn.execute(
            text("UPDATE connection SET enabled = false WHERE id = :c"), {"c": target.connection_id}
        )
    with owner.connect() as conn:
        assert risk.list_risk(conn, filters=risk.RiskFilters(), limit=10, offset=0) == ([], 0)
        assert risk.risk_scope(conn, connection_ids=()) == risk.RiskScope(False, None)


def _facts(**overrides: Any) -> Facts:
    base: dict[str, Any] = {
        "door": False,
        "admin": False,
        "credentials": (),
        "exploitable_cves": 0,
        "exploitable_fixable_cves": 0,
        "high_cves": 0,
        "max_epss": None,
        "high_misconfigurations": 0,
        "other_high_misconfigurations": 0,
        "worst_misconfiguration": None,
        "secret": False,
    }
    return Facts(**{**base, **overrides})


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        (_facts(door=True, exploitable_cves=1, high_cves=1), ("reachable-exploitable",)),
        (_facts(door=True, high_cves=2), ("reachable-critical-cve",)),
        (
            _facts(door=True, high_misconfigurations=1, other_high_misconfigurations=1),
            ("reachable-misconfigured",),
        ),
        # The exposure itself is no second fact.
        (_facts(door=True, high_misconfigurations=1), ()),
        (_facts(door=True, secret=True), ("reachable-secret",)),
        (_facts(admin=True, credentials=("access_key",)), ("admin-user-long-lived-credential",)),
        (_facts(exploitable_cves=1, exploitable_fixable_cves=1), ("exploitable-fixable",)),
        # One fact alone is no combination.
        (_facts(door=True), ()),
        (_facts(admin=True), ()),
        (_facts(credentials=("access_key",)), ()),
        (_facts(exploitable_cves=1), ()),
        (_facts(high_misconfigurations=3), ()),
        # A door turns an exploitable, fixable CVE into the Critical combination, not both.
        (
            _facts(door=True, exploitable_cves=1, exploitable_fixable_cves=1, high_cves=1),
            ("reachable-exploitable",),
        ),
    ],
    ids=[
        "door+exploit",
        "door+high-cve",
        "door+misconfig",
        "door+exposure-only",
        "door+secret",
        "admin+credential",
        "exploit+fix",
        "door-alone",
        "admin-alone",
        "credential-alone",
        "exploit-alone",
        "misconfig-alone",
        "door+exploit+fix",
    ],
)
def test_combinations(facts: Facts, expected: tuple[str, ...]) -> None:
    assert matched(facts) == expected


def test_the_order_puts_tier_first_then_more_combinations() -> None:
    critical = sort_key(("reachable-exploitable",), _facts(door=True, exploitable_cves=1))
    two_high = sort_key(
        ("reachable-misconfigured", "reachable-secret"),
        _facts(
            door=True,
            secret=True,
            high_misconfigurations=9,
            other_high_misconfigurations=9,
            worst_misconfiguration="critical",
        ),
    )
    one_high = sort_key(
        ("reachable-misconfigured",),
        _facts(
            door=True, high_misconfigurations=9999, max_epss=1.0, worst_misconfiguration="critical"
        ),
    )
    medium = sort_key(
        ("exploitable-fixable",),
        _facts(exploitable_cves=9999, exploitable_fixable_cves=9999, max_epss=1.0),
    )
    assert critical > two_high > one_high > medium


def test_a_partial_rescan_drops_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A real partial run through the pipeline (ADR-0049 section 5): the same day scanned again,
    throttled, so the tables it lost carry forward. Missing data never removes a row, nor
    changes when it first became at risk, nor the tiles."""
    target = _scan(owner, worker, store, 0)
    before = _rows(owner, target.connection_id)
    counts = _counts(owner, target.connection_id)
    throttled = CollectOptions(synthetic_throttle_share=1.0)
    for tool in ("steampipe", "vulnerabilities"):
        outcome = run_tool(worker, store, target, tool, DAY, throttled)
        assert outcome.status == "partial", tool
    after = _rows(owner, target.connection_id)
    assert set(after) == set(before)
    for rid, row in after.items():
        assert row["combinations"] == before[rid]["combinations"], row
        assert row["first_seen"] == before[rid]["first_seen"]
    assert _counts(owner, target.connection_id) == counts
