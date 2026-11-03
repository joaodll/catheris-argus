"""What round M3 relies on in Memgraph Community 3.13.2 (ADR-0044, M3 amendment): the Resource
map reads Memgraph at click time, so each map read must be bounded in memory and in time, and
must not wait for the projection's large write transaction. Checked on 2026-11-01; these tests
keep checking it, so an image upgrade that changes any of it fails here first.

    QUERY MEMORY LIMIT     aborts a query that allocates past it, inside a read transaction too
    transaction timeout    the Bolt per-transaction timeout (client.read's unit_of_work) aborts
    snapshot isolation     a read during another session's uncommitted write sees the state
                           before it and does not block

Both aborts are TransientErrors, which the driver retries inside execute_read unless
max_transaction_retry_time is 0: graph/client.py sets 0, and the timeout test holds it there.
"""

import time
from collections.abc import Iterator
from typing import Any

import pytest
from neo4j import Driver, GraphDatabase, ManagedTransaction, unit_of_work
from neo4j.exceptions import Neo4jError, TransientError
from tests.graph.conftest import graph_write

from argus.core.config import get_settings
from argus.graph import client

pytestmark = [pytest.mark.db, pytest.mark.graph, pytest.mark.usefixtures("graph_clean")]

# About 5,000,000 integers in one list: a few hundred MiB, far past a 1 MB limit.
_LARGE = "UNWIND range(1, 5000000) AS i WITH collect(i) AS xs RETURN size(xs) AS n"
# 400,000,000 rows from two small lists: seconds of work and almost no memory (one large range()
# would build its whole list in memory first).
_SLOW = (
    "UNWIND range(1, 20000) AS a UNWIND range(1, 20000) AS b "
    "WITH a, b WHERE a * b = -1 RETURN count(*) AS n"
)


def _read(driver: Driver, cypher: str, *, timeout: float | None = None) -> list[dict[str, Any]]:
    @unit_of_work(timeout=timeout)
    def work(tx: ManagedTransaction) -> list[dict[str, Any]]:
        return [r.data() for r in tx.run(cypher)]

    with driver.session() as session:
        rows: list[dict[str, Any]] = session.execute_read(work)
        return rows


@pytest.fixture
def second_driver() -> Iterator[Driver]:
    """Another client of its own: the reader in the isolation test must not share a
    connection with the writer."""
    s = get_settings()
    assert s.graph_password is not None
    other = GraphDatabase.driver(
        s.graph_uri,
        auth=(s.graph_user, s.graph_password.get_secret_value()),
        max_transaction_retry_time=0,
    )
    yield other
    other.close()


def test_a_query_memory_limit_aborts_the_query_in_a_read_transaction() -> None:
    assert _read(client.driver(), _LARGE) == [{"n": 5000000}]
    with pytest.raises(TransientError, match="Memory limit exceeded"):
        _read(client.driver(), _LARGE + " QUERY MEMORY LIMIT 1 MB")


def test_the_transaction_timeout_aborts_a_read() -> None:
    started = time.perf_counter()
    with pytest.raises(TransientError, match="transaction timeout"):
        _read(client.driver(), _SLOW, timeout=1)
    # Aborted at the timeout, not at the server's 600 s ceiling. Through the application's own
    # driver, so it also proves that driver does not retry it (the default would for 30 s): a
    # timed-out map read must fail at once.
    assert time.perf_counter() - started < 10


def test_a_read_during_an_uncommitted_write_sees_the_old_state_without_waiting(
    second_driver: Driver,
) -> None:
    graph_write("CREATE (:R {uid: 'probe', x: 1})")
    with client.driver().session() as writer:
        tx = writer.begin_transaction()
        tx.run("MATCH (n:R {uid: 'probe'}) SET n.x = 2").consume()
        started = time.perf_counter()
        during = _read(second_driver, "MATCH (n:R {uid: 'probe'}) RETURN n.x AS x", timeout=5)
        waited = time.perf_counter() - started
        tx.commit()
    after = _read(second_driver, "MATCH (n:R {uid: 'probe'}) RETURN n.x AS x", timeout=5)
    assert during == [{"x": 1}]
    assert waited < 2
    assert after == [{"x": 2}]


@pytest.mark.parametrize(
    "cypher",
    [
        "LOAD CSV FROM '/etc/passwd' NO HEADER AS row RETURN row LIMIT 1",
        "CALL mg.create_module_file('not_ours.py', 'import mgp') YIELD path RETURN path",
    ],
    ids=["read-a-file", "write-a-python-module"],
)
def test_the_login_stays_inside_the_graph(cypher: str) -> None:
    """Community's one login can do everything, and the API holds it (ADR-0044, M-2). The server's
    flags and a read-only module directory, set in compose.yaml and the chart, take away what would
    reach past the graph: reading its files, and running Python inside it."""
    with client.driver().session() as session, pytest.raises(Neo4jError):
        session.run(cypher).consume()
