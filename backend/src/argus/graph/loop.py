"""The graph sync loop (ADR-0044): the Compose worker runs it in a thread, the graph-sync
process on Kubernetes runs it alone. Same code, same cadence.

Each tick reconciles Memgraph with Postgres, then evaluates the attack paths when Memgraph
changed (a connection synced or removed, or the integrity check re-synced one), when the last
evaluation failed, and once at start (round M2). The integrity check runs before every
evaluation, so paths are computed only from a verified graph (ADR-0044, accepted residual
risk), and at least every VERIFY_EVERY_SECONDS otherwise."""

import logging
import threading
import time
from collections.abc import Callable

from sqlalchemy import Engine

from argus.graph import client
from argus.graph.paths import evaluate_paths
from argus.graph.projection import reconcile, verify

log = logging.getLogger("argus.graph")
# A new ingested run reaches the graph, and its paths, within one tick.
RECONCILE_EVERY_SECONDS = 15
# The integrity check (mitigation 3): the longest a tampered graph goes unnoticed.
VERIFY_EVERY_SECONDS = 600


def _changed(done: dict[str, int] | None) -> bool:
    return bool(done and (done.get("synced") or done.get("removed") or done.get("drifted")))


def run(engine: Engine, stop: threading.Event, *, alive: Callable[[], None] | None = None) -> None:
    """Reconcile every tick, evaluate the paths when needed, and verify every
    VERIFY_EVERY_SECONDS until `stop` is set. An error is logged and retried on the next tick:
    Postgres stays the record either way."""
    verified_at = 0.0
    paths_due = True  # once at start: the paths may predate this process's graph
    try:
        while not stop.is_set():
            try:
                paths_due |= _changed(reconcile(engine))
                if paths_due or time.monotonic() - verified_at >= VERIFY_EVERY_SECONDS:
                    paths_due |= _changed(verify(engine))
                    verified_at = time.monotonic()
                if paths_due and evaluate_paths(engine) is not None:
                    paths_due = False
            except Exception:
                log.exception("graph sync loop error")
            if alive is not None:
                alive()
            stop.wait(RECONCILE_EVERY_SECONDS)
    finally:
        client.close()
