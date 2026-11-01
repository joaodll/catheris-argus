"""The graph read model follows Postgres (ADR-0044): projected per connection, idempotent, a
failed run changes nothing, other connections' uids are stubs, and tampering is caught."""

from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import Engine, text
from tests.graph.conftest import graph_rows, graph_write
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus import graph
from argus.collection import TOOL_ORDER, FilesystemRawStore
from argus.graph.projection import EDGE_ATTRIBUTES
from argus.ingest import ingest_run, register_failed_run

pytestmark = [pytest.mark.db, pytest.mark.graph, pytest.mark.usefixtures("graph_clean")]
DAY = date(2026, 10, 2)
NODE_KEYS = {
    "uid",
    "conn",
    "provider",
    "account",
    "region",
    "type",
    "name",
    "reach",
    "exploitable",
    "failing_critical",
    "failing_high",
    "failing_medium",
    "failing_low",
}
EDGE_KEYS = {"id", "conn", "origin", "confidence", "attrs"}


def _scan(worker: Engine, store: FilesystemRawStore, target, day: date) -> None:  # type: ignore[no-untyped-def]
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, day)


def _row(engine: Engine, connection_id: int) -> dict[str, object]:
    with engine.connect() as conn:
        return graph.status(conn)[connection_id]


def _counts(connection_id: int) -> tuple[int, int]:
    nodes = graph_rows("MATCH (n:R {conn: $c}) RETURN count(n) AS n", c=connection_id)[0]["n"]
    edges = graph_rows("MATCH ()-[r {conn: $c}]->() RETURN count(r) AS n", c=connection_id)[0]
    return int(nodes), int(edges["n"])  # type: ignore[call-overload]


def test_a_connection_is_projected_once_and_again_only_when_it_changes(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _scan(worker, store, target, DAY)
    assert graph.reconcile(worker, today=DAY) == {"synced": 1, "failed": 0, "removed": 0}
    row = _row(owner, target.connection_id)
    assert row["status"] == "synced" and row["edge_count"] and row["node_count"]
    assert _counts(target.connection_id) == (row["node_count"], row["edge_count"])
    with owner.connect() as conn:
        present = conn.execute(
            text(
                "SELECT count(*) FROM resource_snapshot s JOIN resource r ON r.id = s.resource_id "
                "WHERE r.connection_id = :c AND s.snapshot_date = :d"
            ),
            {"c": target.connection_id, "d": DAY},
        ).scalar_one()
    assert row["node_count"] == present

    # Nothing changed: nothing to do.
    assert graph.reconcile(worker, today=DAY) == {"synced": 0, "failed": 0, "removed": 0}

    # Forcing a re-sync gives the same graph.
    with owner.begin() as conn:
        conn.execute(text("UPDATE graph_projection SET status = 'failed', error = 'test'"))
    assert graph.reconcile(worker, today=DAY)["synced"] == 1  # type: ignore[index]
    again = _row(owner, target.connection_id)
    assert again["checksum"] == row["checksum"]
    assert _counts(target.connection_id) == (row["node_count"], row["edge_count"])

    # A new day's run moves the marker.
    run_tool(worker, store, target, "prowler", DAY + timedelta(days=1))
    assert graph.reconcile(worker, today=DAY + timedelta(days=1))["synced"] == 1  # type: ignore[index]


def test_a_failed_run_changes_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _scan(worker, store, target, DAY)
    graph.reconcile(worker, today=DAY)
    before = _row(owner, target.connection_id)
    with worker.begin() as conn:
        run_id = register_failed_run(
            conn,
            connection_id=target.connection_id,
            tool="steampipe",
            source="synthetic",
            day=DAY,
            run_uid=uuid4(),
            raw_path="",
            started_at=datetime.now(UTC),
            error="test: collection failed",
        )
    ingest_run(worker, store=store, scan_run_id=run_id, rules_dir=RULES_DIR)
    assert graph.reconcile(worker, today=DAY) == {"synced": 0, "failed": 0, "removed": 0}
    assert _row(owner, target.connection_id)["checksum"] == before["checksum"]


def test_another_connections_uid_is_a_stub_until_its_owner_syncs(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    first, second = make_demo(owner, seed=1), make_demo(owner, seed=2)
    _scan(worker, store, first, DAY)
    _scan(worker, store, second, DAY)
    with owner.begin() as conn:
        role_of_first = conn.execute(
            text(
                "SELECT resource_uid FROM resource WHERE connection_id = :c "
                "AND type = 'aws_iam_role' ORDER BY id LIMIT 1"
            ),
            {"c": first.connection_id},
        ).scalar_one()
        role_of_second = conn.execute(
            text(
                "SELECT resource_uid FROM resource WHERE connection_id = :c "
                "AND type = 'aws_iam_role' ORDER BY id LIMIT 1"
            ),
            {"c": second.connection_id},
        ).scalar_one()
        # The second account trusts a role of the first: the rule reading the second account's
        # trust policy draws the edge, so it belongs to the second connection.
        edge_id = conn.execute(
            text(
                "INSERT INTO edge (edge_key, source_uid, target_uid, type, origin, first_seen, "
                "last_seen, connection_id) VALUES (sha256('cross'::bytea), :s, :t, 'CAN_ASSUME', "
                "'rule:role-trust@1', :d, :d, :c) RETURNING id"
            ),
            {"s": role_of_first, "t": role_of_second, "d": DAY, "c": second.connection_id},
        ).scalar_one()
        conn.execute(
            text("INSERT INTO edge_snapshot (snapshot_date, edge_id) VALUES (:d, :e)"),
            {"d": DAY, "e": edge_id},
        )
        conn.execute(
            text("UPDATE connection SET enabled = false WHERE id = :c"), {"c": first.connection_id}
        )
    graph.reconcile(worker, today=DAY)
    stub = graph_rows("MATCH (n:R {uid: $u}) RETURN properties(n) AS p", u=role_of_first)
    assert stub == [{"p": {"uid": role_of_first}}]
    crossing = graph_rows(
        "MATCH (a:R {uid: $s})-[r:CAN_ASSUME]->(b:R {uid: $t}) RETURN r.conn AS c",
        s=role_of_first,
        t=role_of_second,
    )
    assert crossing == [{"c": second.connection_id}]

    with owner.begin() as conn:
        conn.execute(
            text("UPDATE connection SET enabled = true WHERE id = :c"), {"c": first.connection_id}
        )
    graph.reconcile(worker, today=DAY)
    owned = graph_rows("MATCH (n:R {uid: $u}) RETURN n.conn AS c", u=role_of_first)
    assert owned == [{"c": first.connection_id}]


def test_disabling_a_connection_removes_its_projection(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _scan(worker, store, target, DAY)
    graph.reconcile(worker, today=DAY)
    with owner.begin() as conn:
        conn.execute(text("UPDATE connection SET enabled = false"))
    assert graph.reconcile(worker, today=DAY) == {"synced": 0, "failed": 0, "removed": 1}
    assert _counts(target.connection_id) == (0, 0)
    assert graph_rows("MATCH (n) RETURN count(n) AS n") == [{"n": 0}]
    with owner.connect() as conn:
        assert graph.status(conn) == {}


def test_the_integrity_check_catches_tampering_and_restores_the_graph(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _scan(worker, store, target, DAY)
    graph.reconcile(worker, today=DAY)
    before = _row(owner, target.connection_id)
    assert graph.verify(worker, today=DAY) == {"checked": 1, "drifted": 0}

    # Someone deletes an edge (hiding a path), adds one of an unknown connection, and dresses a
    # stub up as a resource.
    graph_write("MATCH ()-[r {conn: $c}]->() WITH r LIMIT 1 DELETE r", c=target.connection_id)
    graph_write("CREATE (:R {uid: 'x:fake', conn: 999})-[:IS_ADMIN {conn: 999}]->(:R {uid: 'y'})")
    graph_write("MATCH (n:R {uid: 'internet'}) SET n.name = 'not the internet'")
    assert graph.verify(worker, today=DAY) == {"checked": 1, "drifted": 1}

    assert _counts(target.connection_id) == (before["node_count"], before["edge_count"])
    assert graph_rows("MATCH (n:R {uid: 'x:fake'}) RETURN count(n) AS n") == [{"n": 0}]
    assert graph_rows("MATCH (n:R {uid: 'internet'}) RETURN properties(n) AS p") == [
        {"p": {"uid": "internet"}}
    ]
    assert _row(owner, target.connection_id)["status"] == "synced"
    with owner.connect() as conn:
        audited = (
            conn.execute(text("SELECT target_id FROM audit_log WHERE action = 'graph.drift'"))
            .scalars()
            .all()
        )
    assert audited == [str(target.connection_id)]


def test_the_graph_holds_no_configuration_and_no_secret(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Only the listed properties reach Memgraph: configurations and tool payloads, where
    secret-bearing values live, stay in Postgres (redacted there too)."""
    _scan(worker, store, make_demo(owner), DAY)
    graph.reconcile(worker, today=DAY)
    node_keys = {k for r in graph_rows("MATCH (n:R) RETURN keys(n) AS k") for k in r["k"]}  # type: ignore[attr-defined]
    assert node_keys <= NODE_KEYS
    edges = graph_rows("MATCH ()-[r]->() RETURN keys(r) AS k, r.attrs AS a")
    assert {k for r in edges for k in r["k"]} <= EDGE_KEYS  # type: ignore[attr-defined]
    assert {k for r in edges for k in (r["a"] or {})} <= set(EDGE_ATTRIBUTES)  # type: ignore[attr-defined]
