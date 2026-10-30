"""Derive again after a rule upgrade (ADR-0035, fifth amendment, point 6).

Edges are derived when a Steampipe run is ingested, and attack paths after CloudFox. So after
an upgrade, a connection kept the old rules' edges and paths until its next runs. When the
worker starts, before its run threads, each enabled connection whose latest rule load was
derived with another rule set (edge_load.ruleset, migration 0026; none before it) is derived
again on that load's day: its edges, flows, reach checks and attack paths. A re-derive never
resolves anything: it re-reads the same day's inventory with newer rules, it is not a scan.
"""

import logging
from datetime import date
from pathlib import Path

from sqlalchemy import Engine, text

from argus import connections
from argus.attackpaths import evaluate_paths
from argus.ingest.pipeline import REDERIVE_LOCK, check_reach, paths_day, rule_set
from argus.relationships import latest_rule_loads, write_edges, write_flows

log = logging.getLogger(__name__)
# Two re-derives starting together (two workers, a Job and a worker) do it once.
REDERIVE_ONCE_LOCK = "argus.rederive.once"
# Re-derive holds its locks on one connection and runs its transactions on another.
REDERIVE_CONNECTIONS = 2


def stale_connections(engine: Engine, *, ruleset: str, today: date) -> dict[int, date]:
    """Each enabled connection whose latest rule load still standing was derived with another
    rule set, and that load's day."""
    with engine.connect() as conn:
        enabled = {c.id for c in connections.enabled(conn)}
        loads = latest_rule_loads(conn, day=today)
    return {
        cid: day
        for cid, (day, derived_with) in sorted(loads.items())
        if cid in enabled and derived_with != ruleset
    }


def rederive_connection(engine: Engine, *, rules_dir: Path, connection_id: int, day: date) -> None:
    ruleset = rule_set(rules_dir)
    edges = write_edges(
        engine, rules_dir=rules_dir, connection_id=connection_id, day=day, ruleset=ruleset
    )
    flows = write_flows(engine, connection_id=connection_id, day=day)
    with engine.begin() as conn:
        reach = check_reach(conn, connection_id=connection_id, day=day)
        # Paths read both edge families: on a later CloudFox day, evaluate there, so the paths
        # keep CloudFox's newest evidence (the rule edges re-derived on `day` still stand).
        on = paths_day(conn, connection_id=connection_id, day=day)
    paths = evaluate_paths(
        engine, rules_dir=rules_dir, connection_id=connection_id, day=on, resolve=False
    )
    log.info(
        "re-derived after a rule upgrade",
        extra={
            "connection_id": connection_id,
            "day": day.isoformat(),
            "edges": edges,
            "flows": flows,
            "reach_checked": reach,
            "paths": paths["paths"],
            "paths_day": on.isoformat(),
        },
    )


def rederive_stale(engine: Engine, *, rules_dir: Path, today: date) -> list[int]:
    """Re-derives every stale connection, once however many processes start it together, and
    only after the ingests running now end: it takes the re-derive lock exclusive, which every
    ingest holds shared. One connection's failure is logged and does not stop the others: its
    edges stay as they were, and its next Steampipe run derives them anyway. Returns the
    connections re-derived."""
    ruleset = rule_set(rules_dir)
    with engine.connect() as lock:
        if not lock.execute(
            text("SELECT pg_try_advisory_lock(hashtext(:k))"), {"k": REDERIVE_ONCE_LOCK}
        ).scalar_one():
            log.info("re-derive skipped: another worker is running it")
            return []
        lock.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), {"k": REDERIVE_LOCK})
        lock.commit()
        try:
            stale = stale_connections(engine, ruleset=ruleset, today=today)
            done = []
            for connection_id, day in stale.items():
                try:
                    rederive_connection(
                        engine, rules_dir=rules_dir, connection_id=connection_id, day=day
                    )
                    done.append(connection_id)
                except Exception:
                    log.exception(
                        "re-derive failed",
                        extra={"connection_id": connection_id, "day": day.isoformat()},
                    )
            log.info(
                "rule set checked",
                extra={"ruleset": ruleset[:12], "stale": len(stale), "re_derived": len(done)},
            )
            return done
        finally:
            lock.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": REDERIVE_LOCK})
            lock.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": REDERIVE_ONCE_LOCK})
            lock.commit()
