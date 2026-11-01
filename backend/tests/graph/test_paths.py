"""The attack-path search over the graph read model, across accounts (ADR-0044, round M2): a
path crosses accounts, belongs to its entry's, is resolved only when every account on it has
complete evidence and the evaluation that just ran no longer finds it, keeps an account's latest
scan however old, and the API can tell when the paths are behind the scans."""

from datetime import date, timedelta

import pytest
from sqlalchemy import Engine, text
from tests.conftest import Settle
from tests.graph.conftest import graph_write
from tests.ingest.conftest import make_demo, run_tool

from argus import attackpaths, graph
from argus.collection import TOOL_ORDER, CollectOptions, CollectTarget, FilesystemRawStore
from argus.collection.synthetic.estate import SCENARIO_INSTANCE, SCENARIO_ROLE

pytestmark = [pytest.mark.db, pytest.mark.graph]
DAY = date(2026, 10, 2)
PARTIAL = CollectOptions(synthetic_throttle_share=1.0)


def _scan(worker: Engine, store: FilesystemRawStore, target: CollectTarget, day: date) -> None:
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, day)


def _uid(owner: Engine, connection_id: int, name: str) -> str:
    with owner.connect() as conn:
        uid: str = conn.execute(
            text("SELECT resource_uid FROM resource WHERE connection_id = :c AND name = :n"),
            {"c": connection_id, "n": name},
        ).scalar_one()
    return uid


def _trust(owner: Engine, *, into: CollectTarget, source: str) -> tuple[int, str]:
    """A role in `into` that reaches its administrator now trusts `source`, another account's
    role: a rule edge of `into`'s connection, on its rule day. Returns the edge id and the
    administrator node it leads to."""
    admin = f"admin:{into.account_id}"
    with owner.begin() as conn:
        role = conn.execute(
            text(
                "SELECT min(source_uid) FROM edge WHERE connection_id = :c AND target_uid = :a "
                "AND source_uid LIKE :role"
            ),
            {"c": into.connection_id, "a": admin, "role": "%:role/%"},
        ).scalar_one()
        assert role, "the demo estate lost its role that reaches the administrator"
        edge_id = conn.execute(
            text("""
                WITH cross_edge AS (
                  INSERT INTO edge (edge_key, source_uid, target_uid, type, origin, attributes,
                                    first_seen, last_seen, connection_id)
                  VALUES (decode(md5('cross-' || :c), 'hex') || decode(md5('edge'), 'hex'),
                          :s, :t, 'CAN_ASSUME', 'rule:role-trust@1', '{}', :d, :d, :c)
                  RETURNING id)
                INSERT INTO edge_snapshot (snapshot_date, edge_id)
                SELECT :d, id FROM cross_edge RETURNING edge_id
            """),
            {"c": into.connection_id, "s": source, "t": role, "d": DAY},
        ).scalar_one()
    return int(edge_id), admin


def _crossing(owner: Engine, admin: str, edge_id: int) -> list[dict[str, object]]:
    """The paths to `admin` through the trust `edge_id` (the demo estates have other crossings
    of their own: an outsider both accounts trust)."""
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT id, connection_id, connection_ids, entry_uid, state, resolved_on "
                "FROM attack_path WHERE target_uid = :a AND :e = ANY(edge_ids)"
            ),
            {"a": admin, "e": edge_id},
        )
        return [dict(r._mapping) for r in rows]


@pytest.fixture
def two_accounts(
    owner: Engine, worker: Engine, store: FilesystemRawStore, settle: Settle
) -> tuple[CollectTarget, CollectTarget, int, str]:
    """prod (A) and another account (B) whose administrator A's scenario role may reach through
    a trust: internet -> A's instance -> A's role -> B's role -> B's administrator."""
    a, b = make_demo(owner, 0), make_demo(owner, 1)
    _scan(worker, store, a, DAY)
    _scan(worker, store, b, DAY)
    edge_id, admin = _trust(owner, into=b, source=_uid(owner, a.connection_id, SCENARIO_ROLE))
    settle(DAY)
    return a, b, edge_id, admin


def test_a_path_crosses_into_another_account_and_belongs_to_its_entry(
    owner: Engine, two_accounts: tuple[CollectTarget, CollectTarget, int, str]
) -> None:
    a, b, edge_id, admin = two_accounts
    instance = _uid(owner, a.connection_id, SCENARIO_INSTANCE)
    paths = [p for p in _crossing(owner, admin, edge_id) if p["entry_uid"] == instance]
    assert paths, "no path from A's internet entry to B's administrator"
    [path] = paths
    assert path["connection_id"] == a.connection_id  # counted once, where the attacker gets in
    assert path["connection_ids"] == [a.connection_id, b.connection_id]
    with owner.connect() as conn:
        entering = attackpaths.list_paths(
            conn,
            limit=200,
            offset=0,
            filters=attackpaths.PathFilters(connection_id=b.connection_id),
        )[0]
        passing = attackpaths.list_paths(
            conn,
            limit=200,
            offset=0,
            filters=attackpaths.PathFilters(connection_id=b.connection_id, passing_through=True),
        )[0]
    assert path["id"] not in {p["id"] for p in entering}
    assert path["id"] in {p["id"] for p in passing}
    assert all(b.connection_id in p["connection_ids"] for p in passing)


def test_an_outsider_entry_belongs_to_the_account_it_enters(
    owner: Engine, two_accounts: tuple[CollectTarget, CollectTarget, int, str]
) -> None:
    """The demo's outsider (an account neither connection scans) is trusted in both: its path to
    B's administrator enters B, so B owns it, whichever account's rules drew the outsider."""
    a, b, _edge, admin = two_accounts
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT connection_id, connection_ids FROM attack_path p "
                "WHERE target_uid = :a AND rule_id = 'internet-to-admin' "
                "AND node_uids[2] NOT IN (SELECT resource_uid FROM resource)"
            ),
            {"a": admin},
        ).all()
    assert rows, "the demo lost its outsider trusted by both accounts"
    # Inside B only: the outsider is no account Argus scans, and B's own rules saw it, so A
    # (whose rules saw it too) is not on the path.
    assert {(r.connection_id, tuple(r.connection_ids)) for r in rows} == {
        (b.connection_id, (b.connection_id,))
    }
    assert a.connection_id not in {r.connection_id for r in rows}


def test_each_accounts_wildcard_is_its_own_target(
    owner: Engine, two_accounts: tuple[CollectTarget, CollectTarget, int, str]
) -> None:
    """`any:s3` (every bucket, a role's wildcard grant) means one account's buckets. An outsider
    both accounts trust reaches each account's: two paths, not one per uid (found 2026-11-01)."""
    a, b, _edge, _admin = two_accounts
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT connection_id, node_uids FROM attack_path WHERE target_uid = 'any:s3' "
                "AND node_uids[2] NOT IN (SELECT resource_uid FROM resource)"
            )
        ).all()
    through = {r.node_uids[2] for r in rows}
    assert {r.connection_id for r in rows} == {a.connection_id, b.connection_id}
    assert {a.account_id, b.account_id} == {uid.split(":")[4] for uid in through}
    assert all(r.node_uids[-1] == "any:s3" for r in rows)  # Postgres's uid, not the graph's


def _break(owner: Engine, edge_id: int) -> None:
    """The trust is gone from B's evidence."""
    with owner.begin() as conn:
        conn.execute(text("DELETE FROM edge_snapshot WHERE edge_id = :e"), {"e": edge_id})


def test_no_resolve_while_an_account_on_the_path_has_a_partial_run(
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    settle: Settle,
    two_accounts: tuple[CollectTarget, CollectTarget, int, str],
) -> None:
    _a, b, edge_id, admin = two_accounts
    assert {p["state"] for p in _crossing(owner, admin, edge_id)} == {"open"}
    _break(owner, edge_id)
    run_tool(worker, store, b, "cloudfox", DAY + timedelta(days=1), PARTIAL)
    settle(DAY + timedelta(days=1))
    # B's evidence is partial: not found is not fixed.
    assert {p["state"] for p in _crossing(owner, admin, edge_id)} == {"open"}
    run_tool(worker, store, b, "cloudfox", DAY + timedelta(days=2))
    settle(DAY + timedelta(days=2))
    crossing = _crossing(owner, admin, edge_id)
    assert {(p["state"], p["resolved_on"]) for p in crossing} == {
        ("resolved", DAY + timedelta(days=2))
    }


def test_a_fix_resolves_the_same_day_after_another_accounts_evaluation(
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    settle: Settle,
    two_accounts: tuple[CollectTarget, CollectTarget, int, str],
) -> None:
    """One evaluation covers every account, so another account's scan earlier the same day must
    not hold a fix found later that day until the next day."""
    a, b, edge_id, admin = two_accounts
    run_tool(worker, store, a, "prowler", DAY)  # another account, the same day
    settle(DAY)
    assert {p["state"] for p in _crossing(owner, admin, edge_id)} == {"open"}
    _break(owner, edge_id)
    run_tool(worker, store, b, "cloudfox", DAY)  # B's rescan, complete
    settle(DAY)
    assert {(p["state"], p["resolved_on"]) for p in _crossing(owner, admin, edge_id)} == {
        ("resolved", DAY)
    }


def test_a_connection_cut_at_the_cap_resolves_nothing(
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    settle: Settle,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A path the cap cut was not found, not fixed."""
    target = make_demo(owner)
    _scan(worker, store, target, DAY)
    settle(DAY)
    with owner.connect() as conn:
        found = conn.execute(
            text("SELECT count(*) FROM attack_path WHERE state = 'open'")
        ).scalar_one()
    assert found > 2
    monkeypatch.setattr("argus.attackpaths.search.MAX_PATHS", 2)
    run_tool(worker, store, target, "cloudfox", DAY + timedelta(days=1))
    settle(DAY + timedelta(days=1))
    with owner.connect() as conn:
        states = dict(
            conn.execute(text("SELECT state, count(*) FROM attack_path GROUP BY 1")).all()
        )
    assert states == {"open": found}


def test_an_account_scanned_40_days_ago_keeps_its_graph_and_its_paths(
    owner: Engine, worker: Engine, store: FilesystemRawStore, settle: Settle
) -> None:
    """Scans may run every 30 days, so the read model holds each account's latest scan however
    old (owner, 2026-11-01): past the dated screens' 31-day window, nothing reads as fixed."""
    target = make_demo(owner)
    _scan(worker, store, target, DAY)
    settle(DAY)
    later = DAY + timedelta(days=40)
    for rebuilt in (False, True):
        if rebuilt:
            graph_write("MATCH (n) DETACH DELETE n")  # Memgraph restarted empty
        settle(later)
        with owner.connect() as conn:
            row = graph.status(conn)[target.connection_id]
            states = dict(
                conn.execute(text("SELECT state, count(*) FROM attack_path GROUP BY 1")).all()
            )
        assert (row["resource_day"], row["rule_day"], row["cloudfox_day"]) == (DAY, DAY, DAY)
        assert row["node_count"] > 0 and row["edge_count"] > 0
        assert set(states) == {"open"} and states["open"] > 0


def test_the_api_state_says_when_paths_are_behind_the_scans(
    owner: Engine, worker: Engine, store: FilesystemRawStore, settle: Settle
) -> None:
    target = make_demo(owner)
    with owner.connect() as conn:
        assert graph.paths_state(conn) == {"evaluated_at": None, "behind": False, "failed": False}
    _scan(worker, store, target, DAY)
    with owner.connect() as conn:
        never = graph.paths_state(conn, connection_id=target.connection_id)
    assert never == {"evaluated_at": None, "behind": True, "failed": False}
    settle(DAY)
    with owner.connect() as conn:
        current = graph.paths_state(conn, connection_id=target.connection_id)
    assert current["evaluated_at"] is not None
    assert (current["behind"], current["failed"]) == (False, False)
    run_tool(worker, store, target, "prowler", DAY + timedelta(days=1))  # not projected yet
    with owner.connect() as conn:
        catching_up = graph.paths_state(conn)
    assert (catching_up["behind"], catching_up["failed"]) == (True, False)
    with owner.begin() as conn:  # Memgraph down for an hour: nothing caught up, nothing failed
        conn.execute(text("UPDATE scan_run SET ingested_at = now() - interval '1 hour'"))
    with owner.connect() as conn:
        stalled = graph.paths_state(conn)
    assert (stalled["behind"], stalled["failed"]) == (True, True)
    with owner.begin() as conn:
        conn.execute(text("UPDATE scan_run SET ingested_at = now()"))
    with owner.begin() as conn:
        conn.execute(
            text("UPDATE graph_projection SET status = 'failed', error = 'test'"),
        )
    with owner.connect() as conn:
        failed = graph.paths_state(conn)
    assert failed["failed"] is True and failed["evaluated_at"] == current["evaluated_at"]
