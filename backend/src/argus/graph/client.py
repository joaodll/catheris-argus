"""The Memgraph client (ADR-0044): one driver per process, reads by name only.

`read` runs a query of catalog.READ_QUERIES in a read transaction; Memgraph refuses a write in
one ("Accessor type READ and query type WRITE are misaligned"). `write_session` is for
projection.py alone (a guard test enforces it). Every transaction is bounded by
ARGUS_GRAPH_TIMEOUT_SECONDS, on top of the server's own ceiling.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from neo4j import Driver, GraphDatabase, ManagedTransaction, Session, unit_of_work

from argus.core.config import get_settings
from argus.graph.catalog import READ_QUERIES

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
                connection_timeout=10,
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


def read(name: str, **params: Any) -> list[dict[str, Any]]:
    """The rows of one named query. An unknown name is refused: there is no other way in."""
    cypher = READ_QUERIES.get(name)
    if cypher is None:
        raise KeyError(f"no graph query named {name!r}")

    @unit_of_work(timeout=timeout())
    def work(tx: ManagedTransaction) -> list[dict[str, Any]]:
        # Cypher from our catalog only, never from a caller.
        return [record.data() for record in tx.run(cypher, params)]

    with driver().session() as session:
        rows: list[dict[str, Any]] = session.execute_read(work)
        return rows


@contextmanager
def write_session() -> Iterator[Session]:
    """A session for projection.py, which runs its own explicit transactions."""
    with driver().session() as session:
        yield session
