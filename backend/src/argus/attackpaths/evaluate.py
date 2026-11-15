"""One evaluation: read every account's standing state, walk, write the routes (ADR-0052 §1).

The caller (scheduling) opens one REPEATABLE READ transaction and passes the newest runs read in
it, so the walk sees one snapshot and every write lands together or not at all (§9 M2).
`route_evaluation` records each evaluation in its own short transactions: when, against which
loads, and how it ended.

An evaluation is due when its inputs changed: the loads digest covers every connection's latest
edge loads (with the rule set that derived them), its newest runs of each tool, and the kinds'
versions, so an ingest, a re-derive, a run turning complete or a new release each make one.
Ingests that land while one runs make the next one due, never more than one (§9 M3).
"""

import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path

from sqlalchemy import Connection, text

from argus import connections, findings, inventory, relationships
from argus.attackpaths.kinds import RouteKind, kind_targets, load_kinds
from argus.attackpaths.routes import (
    EXPOSURE_CHECKS,
    IMDS_CHECK,
    Evidence,
    collect,
    targets_for,
)
from argus.attackpaths.store import Runs, Written, write
from argus.attackpaths.walk import EDGE_TYPES, JUDGED_ATTRIBUTES, PUBLIC_WRITE_CHECKS, build, chains
from argus.attackpaths.walk import graph as make_graph
from argus.core.redaction import redact_text

log = logging.getLogger(__name__)

# A failed evaluation is tried again after this, or as soon as its inputs change.
RETRY_AFTER = timedelta(minutes=15)
# An evaluation still running after this was stopped (killed, out of memory): the next can start.
ABANDONED_AFTER = timedelta(hours=1)


def loads_digest(conn: Connection, kinds: list[RouteKind]) -> bytes:
    """What an evaluation reads, as one hash: argus_route_inputs() (migration 0052: each
    connection's enabled flag, latest edge loads with their rule set, newest ingested runs),
    then the kinds' versions. The scheduler computes it as well, reading no scan data."""
    inputs = conn.execute(text("SELECT argus_route_inputs()")).scalar_one()
    h = hashlib.sha256(bytes(inputs))
    for k in kinds:
        h.update(f"K{k.id}@{k.version};".encode())
    return h.digest()


@dataclass(frozen=True)
class LastEvaluation:
    id: int
    started_at: datetime
    finished_at: datetime | None
    status: str
    loads_digest: bytes | None
    newest_load_at: datetime | None


def last_evaluation(conn: Connection) -> LastEvaluation | None:
    row = conn.execute(
        text("""
        SELECT id, started_at, finished_at, status, loads_digest, newest_load_at
        FROM route_evaluation ORDER BY started_at DESC, id DESC LIMIT 1
    """)
    ).first()
    if row is None:
        return None
    digest = bytes(row.loads_digest) if row.loads_digest is not None else None
    return LastEvaluation(
        row.id, row.started_at, row.finished_at, row.status, digest, row.newest_load_at
    )


def due(last: LastEvaluation | None, digest: bytes, now: datetime) -> bool:
    """Whether an evaluation should start now."""
    if last is None:
        return True
    if last.status == "running":
        return now - last.started_at > ABANDONED_AFTER
    if last.loads_digest != digest:
        return True
    return last.status == "failed" and now - (last.finished_at or now) > RETRY_AFTER


def start(conn: Connection, *, digest: bytes, newest_load_at: datetime | None) -> int:
    """Record an evaluation starting (commit before the walk), first closing any left running."""
    conn.execute(
        text("""
        UPDATE route_evaluation SET status = 'failed', finished_at = now(),
          error = 'stopped before it finished'
        WHERE status = 'running'
    """)
    )
    evaluation_id: int = conn.execute(
        text("""
        INSERT INTO route_evaluation (loads_digest, newest_load_at) VALUES (:d, :n) RETURNING id
    """),
        {"d": digest, "n": newest_load_at},
    ).scalar_one()
    return evaluation_id


def finish(conn: Connection, evaluation_id: int, written: Written) -> None:
    conn.execute(
        text("""
        UPDATE route_evaluation SET status = 'complete', finished_at = now(), routes = :r,
          opened = :o, resolved = :x
        WHERE id = :id
    """),
        {"id": evaluation_id, "r": written.routes, "o": written.opened, "x": written.resolved},
    )


def fail(conn: Connection, evaluation_id: int, error: str) -> None:
    conn.execute(
        text("""
        UPDATE route_evaluation SET status = 'failed', finished_at = now(), error = :e
        WHERE id = :id
    """),
        {"id": evaluation_id, "e": redact_text(error)[:2000]},
    )


def purge_evaluations(conn: Connection, *, before: datetime) -> int:
    """Retention: evaluations older than the history kept, never the newest."""
    deleted: int = conn.execute(
        text("""
        DELETE FROM route_evaluation
        WHERE started_at < :b
          AND id <> (SELECT id FROM route_evaluation ORDER BY started_at DESC, id DESC LIMIT 1)
    """),
        {"b": before},
    ).rowcount
    return deleted


def evaluate(conn: Connection, *, rules_dir: Path, runs: Runs, today: date) -> Written:
    """Walk every enabled connection's standing state and write the routes, in the caller's
    transaction."""
    kinds = load_kinds(rules_dir)
    scanned = connections.enabled_accounts(conn)
    enabled = set(scanned.values())
    loads = [ld for ld in relationships.latest_loads(conn) if ld.connection_id in enabled]
    days: dict[int, dict[str, date]] = {}
    for ld in loads:
        days.setdefault(ld.connection_id, {})[ld.family] = ld.day
    inventory_days = inventory.latest_days(conn)

    failing = findings.failing_resources(conn, (IMDS_CHECK, *EXPOSURE_CHECKS, *PUBLIC_WRITE_CHECKS))
    public_write = set().union(*(failing[c] for c in PUBLIC_WRITE_CHECKS))
    rows = relationships.standing_edges(
        conn, loads=loads, types=EDGE_TYPES, attributes_of=JUDGED_ATTRIBUTES
    )
    exposed = set().union(*(failing[c] for c in EXPOSURE_CHECKS))
    steps, cross = build(rows, scanned=scanned, public_write=public_write, exposed=exposed)
    del rows
    ids = {i for s in steps for i in (s.source_id, s.target_id) if i is not None}
    by_id = inventory.resource_types(conn, sorted(ids))
    types = {}
    for s in steps:
        for uid, rid in ((s.source, s.source_id), (s.target, s.target_id)):
            if rid is not None and rid in by_id:
                types[uid] = by_id[rid]
    evidence = Evidence(
        exploitable=findings.exploitable_resources(conn),
        imds_v1=failing[IMDS_CHECK],
        exposed=exposed,
        types=types,
    )

    found: dict[str, set[str]] = {k.id: set() for k in kinds}
    for c in sorted(enabled):
        d = days.get(c, {})
        per_kind = kind_targets(
            conn,
            kinds,
            connection_id=c,
            resource_day=inventory_days.get(c),
            rule_day=d.get("rule"),
            cloudfox_day=d.get("cloudfox"),
        )
        for k, uids in per_kind.items():
            found[k] |= uids

    g = make_graph(steps, cross, types)
    by_kind: Mapping[str, RouteKind] = {k.id: k for k in kinds}
    routes = collect(by_kind, chains(g, targets_for(kinds, found, evidence)), evidence)
    written = write(
        conn, routes, kinds=by_kind, runs=runs, today=today,
        existing=connections.connection_ids(conn),
    )  # fmt: skip
    log.info(
        "attack routes evaluated",
        extra={
            "routes": written.routes,
            "opened": written.opened,
            "changed": written.changed,
            "resolved": written.resolved,
            "seeds": len(g.seeds),
        },
    )
    return written
