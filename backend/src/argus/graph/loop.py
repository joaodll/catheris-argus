"""The graph sync loop (ADR-0044): the Compose worker runs it in a thread, the graph-sync
process on Kubernetes runs it alone. Same code, same cadence."""

import logging
import threading
import time
from collections.abc import Callable

from sqlalchemy import Engine

from argus.graph import client
from argus.graph.projection import reconcile, verify

log = logging.getLogger("argus.graph")
# A new ingested run reaches the graph within one tick.
RECONCILE_EVERY_SECONDS = 15
# The integrity check (mitigation 3): the longest a tampered graph goes unnoticed.
VERIFY_EVERY_SECONDS = 600


def run(engine: Engine, stop: threading.Event, *, alive: Callable[[], None] | None = None) -> None:
    """Reconcile every tick and verify every VERIFY_EVERY_SECONDS until `stop` is set. An
    error is logged and retried on the next tick: Postgres stays the record either way."""
    verified_at = 0.0
    try:
        while not stop.is_set():
            try:
                reconcile(engine)
                if time.monotonic() - verified_at >= VERIFY_EVERY_SECONDS:
                    verify(engine)
                    verified_at = time.monotonic()
            except Exception:
                log.exception("graph sync loop error")
            if alive is not None:
                alive()
            stop.wait(RECONCILE_EVERY_SECONDS)
    finally:
        client.close()
