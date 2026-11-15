"""Working out attack routes (ADR-0052 §1): one evaluation at a time, when its inputs changed.

The same code runs in the Compose worker's paths thread and in the Kubernetes `paths` Job.
- A session advisory lock lets only one evaluation run at once (§9 M3); a second caller returns
  without waiting.
- The evaluation reads and writes in one REPEATABLE READ transaction, so a failure before its
  commit writes nothing (§9 M2); route_evaluation records the start, the end or the error in
  short transactions of their own.
"""

import logging
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Connection, Engine, text

from argus import attackpaths, ingest

log = logging.getLogger("argus.paths")
PATHS_LOCK = "argus.paths"
# The lock's session, plus one transaction at a time.
PATHS_CONNECTIONS = 2


def _runs(conn: Connection) -> tuple[attackpaths.Runs, datetime | None]:
    newest = ingest.newest_runs(conn)
    runs = {key: (r.run_id, r.status) for key, r in newest.items()}
    latest = max((r.ingested_at for r in newest.values()), default=None)
    return runs, latest


def due(engine: Engine, *, rules_dir: Path, now: datetime) -> bool:
    """Whether an evaluation should start: its inputs changed, a failed one may be retried, or
    the last was left running. Read-only: the scheduler asks this on Kubernetes."""
    with engine.connect() as conn:
        digest = attackpaths.loads_digest(conn, attackpaths.load_kinds(rules_dir))
        return attackpaths.due(attackpaths.last_evaluation(conn), digest, now)


def run_pending(engine: Engine, *, rules_dir: Path, now: datetime | None = None) -> bool:
    """One evaluation if one is due and none is running. True when one ran (or failed)."""
    now = now or datetime.now(UTC)
    with engine.connect() as session:
        locked = session.execute(
            text("SELECT pg_try_advisory_lock(hashtext(:k))"), {"k": PATHS_LOCK}
        ).scalar_one()
        session.commit()
        if not locked:
            return False
        try:
            return _evaluate(engine, rules_dir=rules_dir, now=now)
        finally:
            session.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": PATHS_LOCK})
            session.commit()


def _evaluate(engine: Engine, *, rules_dir: Path, now: datetime) -> bool:
    kinds = attackpaths.load_kinds(rules_dir)
    with engine.begin() as conn:
        _, latest = _runs(conn)
        digest = attackpaths.loads_digest(conn, kinds)
        if not attackpaths.due(attackpaths.last_evaluation(conn), digest, now):
            return False
        evaluation_id = attackpaths.start(conn, digest=digest, newest_load_at=latest)
    try:
        with (
            engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn,
            conn.begin(),
        ):
            runs, _ = _runs(conn)
            written = attackpaths.evaluate(conn, rules_dir=rules_dir, runs=runs, today=now.date())
    except Exception as exc:
        log.exception("attack route evaluation failed", extra={"evaluation_id": evaluation_id})
        with engine.begin() as conn:
            attackpaths.fail(conn, evaluation_id, f"{type(exc).__name__}: {exc}")
        return True
    with engine.begin() as conn:
        attackpaths.finish(conn, evaluation_id, written)
    log.info(
        "attack routes written",
        extra={
            "evaluation_id": evaluation_id,
            "routes": written.routes,
            "opened": written.opened,
            "changed": written.changed,
            "resolved": written.resolved,
        },
    )
    return True
