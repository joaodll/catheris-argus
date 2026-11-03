"""Graph tests run against the `memgraph-test` service (compose `test`), emptied before each."""

from collections.abc import Iterator

import pytest

from argus.graph import client


@pytest.fixture
def graph_clean() -> Iterator[None]:
    with client.write_session() as session:
        session.run("MATCH (n) DETACH DELETE n").consume()
    yield


def graph_rows(cypher: str, **params: object) -> list[dict[str, object]]:
    """Test-only reads of the whole graph (the catalog is for the application)."""
    with client.write_session() as session:
        return [r.data() for r in session.run(cypher, params)]


def graph_write(cypher: str, **params: object) -> None:
    with client.write_session() as session:
        session.run(cypher, params).consume()
