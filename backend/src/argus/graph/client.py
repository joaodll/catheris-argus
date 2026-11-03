"""The Memgraph client (ADR-0044): one driver per process, reads by name only.

`read` runs a query of catalog.READ_QUERIES in a read transaction; Memgraph refuses a write in
one ("Accessor type READ and query type WRITE are misaligned"). `write_session` is for
projection.py alone (a guard test enforces it). Every transaction is bounded by
ARGUS_GRAPH_TIMEOUT_SECONDS unless a read asks for less (the map's 5 s), on top of the server's
own ceiling. The pool is capped as the process's database pool is: a request holds one of each.
"""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from neo4j import Driver, GraphDatabase, ManagedTransaction, Session, unit_of_work
from neo4j.exceptions import ServiceUnavailable

from argus.core.config import get_settings
from argus.graph.catalog import READ_QUERIES

CONNECT_TIMEOUT_S = 5.0
WAIT_POLL_SECONDS = 2.0
_lock = threading.Lock()
_drivers: dict[str, Driver] = {}  # one per process, under "default"


class GraphNotConfigured(RuntimeError):
    """This process has no graph login (ARGUS_GRAPH_PASSWORD unset)."""


def driver() -> Driver:
    with _lock:
        if "default" not in _drivers:
            s = get_settings()
            if s.graph_password is None:
                raise GraphNotConfigured("ARGUS_GRAPH_PASSWORD is not set")
            _drivers["default"] = GraphDatabase.driver(
                s.graph_uri,
                auth=(s.graph_user, s.graph_password.get_secret_value()),
                connection_timeout=CONNECT_TIMEOUT_S,
                connection_acquisition_timeout=CONNECT_TIMEOUT_S,
                max_connection_pool_size=s.db_pool_max,
                max_transaction_retry_time=0,
            )
        return _drivers["default"]


def close() -> None:
    with _lock:
        found = _drivers.pop("default", None)
        if found is not None:
            found.close()


def timeout() -> float:
    return get_settings().graph_timeout_seconds


def wait_until_ready(timeout_seconds: float) -> bool:
    """Whether Memgraph answered this login within the timeout. Only "not reachable yet" is waited
    out: it can start long after this process, while a wrong login raises at once, because
    waiting can't fix it."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            driver().verify_connectivity()
        except ServiceUnavailable:
            if time.monotonic() >= deadline:
                return False
        else:
            return True
        time.sleep(WAIT_POLL_SECONDS)


def read(name: str, *, within: float | None = None, **params: Any) -> list[dict[str, Any]]:
    """The rows of one named query, in `within` seconds at most. An unknown name is refused:
    there is no other way in."""
    cypher = READ_QUERIES.get(name)
    if cypher is None:
        raise KeyError(f"no graph query named {name!r}")

    @unit_of_work(timeout=within if within is not None else timeout())
    def work(tx: ManagedTransaction) -> list[dict[str, Any]]:
        # Cypher from our catalog only, never from a caller. Plain values: Record.data() walks
        # every nested value to convert graph types, and no read returns one.
        result = tx.run(cypher, params)
        keys = result.keys()
        return [dict(zip(keys, record.values(), strict=True)) for record in result]

    with driver().session() as session:
        rows: list[dict[str, Any]] = session.execute_read(work)
        return rows


@contextmanager
def write_session() -> Iterator[Session]:
    """A session for projection.py, which runs its own explicit transactions."""
    with driver().session() as session:
        yield session
