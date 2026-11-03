"""The projection: Postgres's current state of each connection, into Memgraph (ADR-0044).

reconcile() is the only writer. It runs in the Compose worker's graph thread and in the
graph-sync process on Kubernetes, never in a scan Job. For each enabled connection it compares
the marker the connection was projected from (graph_projection: its newest ingested run and the
rule set of its newest rule load) with today's, and re-projects the connection when they differ,
when the last sync failed, or when Memgraph's own marker is missing or different (an empty or
restarted Memgraph rebuilds this way, one connection at a time). A failed or partial run moves no
marker the projection reads (the effective days and LATEST_INGESTED_RUNS_SQL already exclude
it), so it changes nothing here.

A connection whose projection would write what Memgraph already holds is not rewritten (D7a): a
Prowler or Inspector run changes nothing in the graph, which holds no findings. The new run is
still recorded, so the attack paths are evaluated from it. A connection marked failed always
rewrites, so the integrity check's repair is never skipped.

One connection is replaced in one Memgraph transaction: its edges deleted, its nodes merged by
uid, its edges created between merged endpoints. A uid it references that it does not own
(another connection's resource, a pseudo-node such as `internet`) is a stub holding only its uid
until its owner syncs; a stub no edge touches any more is deleted. Postgres is read in one
REPEATABLE READ, read-only transaction, so a concurrent ingest never mixes two states.

verify() is the integrity check (mitigation 3): it reads every projected connection back
through the catalog, recomputes the checksum and compares it with graph_projection. Any drift,
or anything in Memgraph no projected connection owns, is audited (`graph.drift`) and re-synced.

Manual edges (origin `manual`, no connection) are not projected yet: none can be created until
the UI for them exists. That is the seam for them.

Pseudo-nodes: `internet` and `external:<host>` are one node for every connection, and
`admin:<account>` names its account. `any:<service>` (a wildcard grant: every resource of a
service, role-accesses) means that service in the account whose edge it is, but its uid names no
account; in one graph across accounts, two accounts' "any S3 bucket" would be one node, and the
search would keep one account's path to it where each account has its own (found 2026-11-01).
The graph holds it as `any:<service>@<account>` (graph_uid); Postgres keeps `any:<service>`, and
whoever reads a uid back for Postgres calls postgres_uid.
"""

import hashlib
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from neo4j import Session
from sqlalchemy import Connection, Engine, text

from argus import connections, ingest, inventory, relationships
from argus.attackpaths import edge_confidence
from argus.core import audit
from argus.core.redaction import redact_text
from argus.graph import client

log = logging.getLogger(__name__)

# Postgres connections held at once: the advisory lock, and one read transaction.
GRAPH_CONNECTIONS = 2
LOCK = "argus.graph"
BATCH = 10_000
# Edge attributes: only relationships.EDGE_ATTRIBUTES. Anything else stays in Postgres, read
# through the edge id: the graph holds no configuration.
_EDGE_TYPE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_ACCOUNT_SCOPED = "any:"  # pseudo-nodes that mean something in one account only
# The graph's shape. Bump it when the projection writes something differently: every connection
# projected in another format re-projects once, at the next reconcile, without reading as drift.
# 2: account-scoped wildcard pseudo-nodes (any:<service>@<account>), 2026-11-01.
# 3: a map `layer` on edges, no findings or reach on nodes (D6), 2026-11-02.
FORMAT = 3
_EMPTY_CHECKSUM = bytes(32)

_EDGES_SQL = f"""
  SELECT e.id, e.source_uid, e.target_uid, e.type, e.origin, e.attributes
  FROM ({relationships.EFFECTIVE_EDGES_SQL}) e WHERE e.origin <> 'manual'
"""  # noqa: S608 - exported SQL only
_CONNECTIONS_SQL = f"""
  SELECT c.id, c.provider, c.account_id, r.run_id
  FROM ({connections.DIRECTORY_SQL}) c
  JOIN ({ingest.LATEST_INGESTED_RUNS_SQL}) r ON r.connection_id = c.id
  WHERE c.enabled
"""  # noqa: S608 - exported SQL only

_SCHEMA = (
    "CREATE INDEX ON :R(uid)",
    "CREATE CONSTRAINT ON (n:R) ASSERT n.uid IS UNIQUE",
    "CREATE INDEX ON :R(conn)",
    "CREATE INDEX ON :Projection(conn)",
    "CREATE GLOBAL EDGE INDEX ON :(conn)",
)


@dataclass(frozen=True)
class Target:
    """What a connection should be projected from now."""

    connection_id: int
    provider: str
    account: str
    source_run_id: int
    ruleset: str


@dataclass
class Snapshot:
    target: Target
    days: dict[str, date | None]
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)

    @property
    def checksum(self) -> bytes:
        return checksum(self.nodes, self.edges)


def _clean(props: dict[str, Any]) -> dict[str, Any]:
    """Properties as Memgraph keeps them: a null is no property at all."""
    return {k: v for k, v in props.items() if v is not None}


def checksum(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> bytes:
    """One digest over a connection's nodes and edges, the same whether computed from what was
    written or from what Memgraph returns."""
    lines = [f"N\t{json.dumps(_clean(n), sort_keys=True, default=str)}" for n in nodes]
    lines += [
        "E\t"
        + json.dumps(
            [
                e["id"],
                e["source"],
                e["target"],
                e["type"],
                e["origin"],
                e["confidence"],
                e.get("layer"),
                e.get("attrs") or {},
            ],
            sort_keys=True,
            default=str,
        )
        for e in edges
    ]
    digest = hashlib.sha256()
    for line in sorted(lines):
        digest.update(line.encode())
        digest.update(b"\n")
    return digest.digest()


def graph_uid(uid: str, account: str) -> str:
    """The node a Postgres uid is in the graph: an account's wildcard pseudo-node gets its
    account (see the module docstring); every other uid is itself."""
    return f"{uid}@{account}" if uid.startswith(_ACCOUNT_SCOPED) else uid


def postgres_uid(uid: str) -> str:
    """The Postgres uid of a graph node: graph_uid undone."""
    return uid.rpartition("@")[0] if uid.startswith(_ACCOUNT_SCOPED) and "@" in uid else uid


def _attrs(attributes: dict[str, Any] | None) -> dict[str, Any] | None:
    # The attributes filters need (relationships.EDGE_ATTRIBUTES), the map's own.
    return relationships.plain_attributes(attributes) or None


def read_snapshot(conn: Connection, target: Target, *, today: date) -> Snapshot:
    """Everything the graph holds for one connection, from one consistent Postgres read: its
    latest scan state, however old (scans may be 60 days apart)."""
    c = target.connection_id
    days: dict[str, date | None] = {
        "resource_day": inventory.effective_day(conn, connection_id=c, day=today),
        **relationships.effective_days(conn, connection_id=c, day=today),
    }
    snap = Snapshot(target, days)
    params = {"connection_id": c, **days}
    if days["resource_day"] is not None:
        for r in conn.execute(text(inventory.RESOURCES_PRESENT_SQL), params):
            snap.nodes.append(
                _clean(
                    {
                        "uid": r.uid,
                        "conn": c,
                        "provider": r.provider,
                        "account": target.account,
                        "region": r.region,
                        "type": r.type,
                        "name": r.name,
                    }
                )
            )
    if days["rule_day"] is not None or days["cloudfox_day"] is not None:
        for e in conn.execute(text(_EDGES_SQL), params):
            if not _EDGE_TYPE.match(e.type):
                log.warning("edge type not projected", extra={"type": e.type, "edge": e.id})
                continue
            level, _why = edge_confidence(e.type, e.origin, e.attributes or {}, e.source_uid)
            snap.edges.append(
                {
                    "id": int(e.id),
                    "source": graph_uid(e.source_uid, target.account),
                    "target": graph_uid(e.target_uid, target.account),
                    "type": e.type,
                    "origin": e.origin,
                    "confidence": level,
                    "layer": relationships.layer_of(e.type, e.target_uid),
                    "attrs": _attrs(e.attributes),
                }
            )
    return snap


def _batches(rows: list[Any]) -> Any:
    for i in range(0, len(rows), BATCH):
        yield rows[i : i + BATCH]


def _detach(tx: Any, c: int) -> set[str]:
    """Delete the connection's edges and turn its nodes into stubs. Returns the uids that may
    now be stubs no edge touches."""
    ends = tx.run(
        "MATCH (a:R)-[r {conn: $c}]->(b:R) WITH a, b, r DELETE r "
        "RETURN collect(DISTINCT a.uid) + collect(DISTINCT b.uid) AS uids",
        c=c,
    ).single()
    owned = [r["uid"] for r in tx.run("MATCH (n:R {conn: $c}) RETURN n.uid AS uid", c=c)]
    for rows in _batches(owned):
        tx.run("UNWIND $u AS uid MATCH (n:R {uid: uid}) SET n = {uid: uid}", u=rows)
    return set(ends["uids"] if ends else []) | set(owned)


def _collect_stubs(tx: Any, candidates: set[str]) -> None:
    for rows in _batches(sorted(candidates)):
        tx.run(
            "UNWIND $u AS uid MATCH (n:R {uid: uid}) WHERE n.conn IS NULL "
            "OPTIONAL MATCH (n)-[r]-() WITH n, count(r) AS degree WHERE degree = 0 DELETE n",
            u=rows,
        )


def _write(session: Session, snap: Snapshot) -> None:
    c = snap.target.connection_id
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in snap.edges:
        by_type[e["type"]].append(
            {
                "s": e["source"],
                "t": e["target"],
                "p": _clean(
                    {
                        "id": e["id"],
                        "conn": c,
                        "origin": e["origin"],
                        "confidence": e["confidence"],
                        "layer": e["layer"],
                        "attrs": e["attrs"],
                    }
                ),
            }
        )
    with session.begin_transaction(timeout=client.timeout()) as tx:
        candidates = _detach(tx, c)
        for rows in _batches(snap.nodes):
            tx.run("UNWIND $n AS x MERGE (n:R {uid: x.uid}) SET n = x", n=rows)
        for edge_type, rows_all in sorted(by_type.items()):
            # The label is an edge type from our own rules or CloudFox's adapter, checked
            # against _EDGE_TYPE when read: never input.
            for rows in _batches(rows_all):
                tx.run(
                    "UNWIND $e AS x MERGE (a:R {uid: x.s}) MERGE (b:R {uid: x.t}) "
                    f"CREATE (a)-[r:{edge_type}]->(b) SET r = x.p",
                    e=rows,
                )
        _collect_stubs(tx, candidates)
        tx.run(
            "MERGE (p:Projection {conn: $c}) "
            "SET p.checksum = $h, p.source_run_id = $run, p.ruleset = $ruleset, "
            "p.format = $format",
            c=c,
            h=snap.checksum.hex(),
            run=snap.target.source_run_id,
            ruleset=snap.target.ruleset,
            format=FORMAT,
        )
        tx.commit()


def _note_run(session: Session, snap: Snapshot) -> None:
    """Nothing to write but the marker: the run this unchanged state was projected from."""
    with session.begin_transaction(timeout=client.timeout()) as tx:
        tx.run(
            "MATCH (p:Projection {conn: $c}) SET p.source_run_id = $run, p.ruleset = $ruleset",
            c=snap.target.connection_id,
            run=snap.target.source_run_id,
            ruleset=snap.target.ruleset,
        )
        tx.commit()


def _remove(session: Session, connection_id: int) -> None:
    with session.begin_transaction(timeout=client.timeout()) as tx:
        _collect_stubs(tx, _detach(tx, connection_id))
        tx.run("MATCH (p:Projection {conn: $c}) DELETE p", c=connection_id)
        tx.commit()


_UPSERT_SQL = """
  INSERT INTO graph_projection (connection_id, source_run_id, ruleset, rule_day, cloudfox_day,
                                resource_day, node_count, edge_count, checksum, status, error,
                                synced_at)
  VALUES (:c, :run, :ruleset, :rule_day, :cloudfox_day, :resource_day, :nodes, :edges, :sum,
          :status, :error, now())
  ON CONFLICT (connection_id) DO UPDATE SET
    source_run_id = EXCLUDED.source_run_id, ruleset = EXCLUDED.ruleset,
    rule_day = EXCLUDED.rule_day, cloudfox_day = EXCLUDED.cloudfox_day,
    resource_day = EXCLUDED.resource_day, node_count = EXCLUDED.node_count,
    edge_count = EXCLUDED.edge_count, checksum = EXCLUDED.checksum, status = EXCLUDED.status,
    error = EXCLUDED.error, synced_at = EXCLUDED.synced_at
"""


def sync_connection(
    engine: Engine, session: Session, target: Target, *, today: date, holds: bytes | None = None
) -> bool:
    """Re-project one connection. Returns whether it succeeded; a failure is recorded on the
    connection's row (status failed) and retried by the next reconcile. `holds` is the checksum
    Memgraph is known to hold for it: the same state is not written again."""
    c = target.connection_id
    try:
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            snap = read_snapshot(conn, target, today=today)
            conn.rollback()
        if snap.checksum == holds:
            _note_run(session, snap)
        else:
            _write(session, snap)
    except Exception as e:
        log.exception("graph sync failed", extra={"connection": c})
        with engine.begin() as conn:
            conn.execute(
                text(_UPSERT_SQL),
                {
                    "c": c,
                    "run": target.source_run_id,
                    "ruleset": target.ruleset,
                    "rule_day": None,
                    "cloudfox_day": None,
                    "resource_day": None,
                    "nodes": 0,
                    "edges": 0,
                    "sum": _EMPTY_CHECKSUM,
                    "status": "failed",
                    "error": redact_text(f"{type(e).__name__}: {e}")[:2000],
                },
            )
        return False
    with engine.begin() as conn:
        conn.execute(
            text(_UPSERT_SQL),
            {
                "c": c,
                "run": target.source_run_id,
                "ruleset": target.ruleset,
                **snap.days,
                "nodes": len(snap.nodes),
                "edges": len(snap.edges),
                "sum": snap.checksum,
                "status": "synced",
                "error": None,
            },
        )
    log.info(
        "graph synced",
        extra={"connection": c, "nodes": len(snap.nodes), "edges": len(snap.edges)},
    )
    return True


def status(conn: Connection) -> dict[int, dict[str, Any]]:
    rows = conn.execute(text("SELECT * FROM graph_projection ORDER BY connection_id"))
    return {r.connection_id: dict(r._mapping) for r in rows}


def _targets(conn: Connection, *, today: date) -> dict[int, Target]:
    rules = relationships.latest_rule_loads(conn, day=today)
    return {
        r.id: Target(
            connection_id=r.id,
            provider=r.provider,
            account=r.account_id,
            source_run_id=int(r.run_id),
            ruleset=(rules.get(r.id, (None, None))[1] or ""),
        )
        for r in conn.execute(text(_CONNECTIONS_SQL))
    }


_schema_ready: set[str] = set()  # holds "done" once this process created the schema


def ensure_schema(session: Session) -> None:
    """Indexes and the uid constraint, once per process. Re-creating an existing one is
    refused by Memgraph, which is the expected answer after the first process."""
    if _schema_ready:
        return
    for statement in _SCHEMA:
        try:
            session.run(statement).consume()
        except Exception as e:  # "already exists" is the steady state
            if "exist" not in str(e).lower():
                raise
    _schema_ready.add("done")


def try_lock(engine: Engine) -> Connection | None:
    lock = engine.connect()
    if lock.execute(text("SELECT pg_try_advisory_lock(hashtext(:k))"), {"k": LOCK}).scalar():
        return lock
    lock.close()
    return None


def unlock(lock: Connection) -> None:
    try:
        lock.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": LOCK})
    finally:
        lock.close()


def reconcile(engine: Engine, *, today: date | None = None) -> dict[str, int] | None:
    """Bring Memgraph to Postgres's current state. Returns what it did, or None when another
    process holds the graph lock."""
    today = today or datetime.now(UTC).date()
    lock = try_lock(engine)
    if lock is None:
        return None
    try:
        with engine.connect() as conn:
            targets = _targets(conn, today=today)
            rows = status(conn)
        with client.write_session() as session:
            ensure_schema(session)
            markers = {
                int(m["conn"]): (m["checksum"], m["format"])
                for m in client.read("projection_markers")
            }
            synced = failed = 0
            for c, target in sorted(targets.items()):
                row = rows.get(c)
                current = (
                    row is not None
                    and row["status"] == "synced"
                    and (row["source_run_id"], row["ruleset"])
                    == (target.source_run_id, target.ruleset)
                    and markers.get(c) == (bytes(row["checksum"]).hex(), FORMAT)
                )
                if current:
                    continue
                # Only a healthy row may vouch for what Memgraph holds: a failed one, the
                # integrity check's mark among them, always rewrites.
                holds = (
                    bytes(row["checksum"])
                    if row is not None
                    and row["status"] == "synced"
                    and markers.get(c) == (bytes(row["checksum"]).hex(), FORMAT)
                    else None
                )
                if sync_connection(engine, session, target, today=today, holds=holds):
                    synced += 1
                else:
                    failed += 1
            gone = (set(rows) | set(markers)) - set(targets)
            for c in sorted(gone):
                _remove(session, c)
                with engine.begin() as conn:
                    conn.execute(
                        text("DELETE FROM graph_projection WHERE connection_id = :c"), {"c": c}
                    )
        return {"synced": synced, "failed": failed, "removed": len(gone)}
    finally:
        unlock(lock)


def _read_back(connection_id: int) -> bytes:
    nodes = [
        {**(r["props"] or {}), "uid": r["uid"]}
        for r in client.read("connection_nodes", conn=connection_id)
    ]
    edges = client.read("connection_edges", conn=connection_id)
    return checksum(nodes, edges)


def verify(engine: Engine, *, today: date | None = None) -> dict[str, int] | None:
    """The integrity check. Returns how many connections drifted, or None when another
    process holds the graph lock. Drift is audited, marked failed and re-synced."""
    lock = try_lock(engine)
    if lock is None:
        return None
    drifted: dict[int, str] = {}
    try:
        with engine.connect() as conn:
            every = status(conn)
        known = sorted(every)
        rows = {c: r for c, r in every.items() if r["status"] == "synced"}
        foreign = client.read("foreign_elements", conns=known)[0]
        for c, row in rows.items():
            if _read_back(c) != bytes(row["checksum"]):
                drifted[c] = "checksum"
        if foreign["edges"] or foreign["nodes"]:
            # Something no projected connection owns: re-project everything.
            drifted.update({c: drifted.get(c, "foreign elements") for c in rows})
        if drifted:
            with engine.begin() as conn:
                for c, why in sorted(drifted.items()):
                    audit.record(
                        conn,
                        actor="system",
                        action="graph.drift",
                        target_type="connection",
                        target_id=str(c),
                        detail={
                            "reason": why,
                            "foreign_edges": foreign["edges"],
                            "foreign_nodes": foreign["nodes"],
                        },
                    )
                    conn.execute(
                        text(
                            "UPDATE graph_projection SET status = 'failed', error = :e "
                            "WHERE connection_id = :c"
                        ),
                        {"c": c, "e": f"integrity check: {why}"},
                    )
            if foreign["edges"] or foreign["nodes"]:
                with client.write_session() as session:
                    session.run(
                        "MATCH ()-[r]->() WHERE r.conn IS NULL OR NOT r.conn IN $conns DELETE r",
                        conns=known,
                    ).consume()
                    session.run(
                        "MATCH (n) WHERE (n:R AND n.conn IS NOT NULL AND NOT n.conn IN $conns) "
                        "OR (NOT n:R AND NOT n:Projection) DETACH DELETE n",
                        conns=known,
                    ).consume()
                    session.run(
                        "MATCH (n:R) WHERE n.conn IS NULL AND size(keys(n)) > 1 "
                        "SET n = {uid: n.uid}"
                    ).consume()
            log.warning("graph drift", extra={"connections": sorted(drifted)})
    finally:
        unlock(lock)
    if drifted:
        reconcile(engine, today=today)
    return {"checked": len(rows), "drifted": len(drifted)}
