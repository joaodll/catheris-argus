"""Mitigation 1 of ADR-0044: reads reach Memgraph only by name, every named query is
read-only, and only the projection writes. No database needed for the static checks."""

import re
from pathlib import Path

import pytest
from tests.graph.conftest import graph_rows

from argus.graph import client
from argus.graph.catalog import READ_QUERIES

SRC = Path(__file__).resolve().parents[2] / "src" / "argus"
WRITES = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|LOAD|FOREACH|CALL|ALTER|GRANT|REVOKE)\b",
    re.IGNORECASE,
)


@pytest.mark.parametrize("name", sorted(READ_QUERIES))
def test_every_named_query_is_read_only(name: str) -> None:
    assert not WRITES.search(READ_QUERIES[name]), READ_QUERIES[name]


def test_only_the_projection_opens_a_write_session() -> None:
    users = sorted(
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if "write_session" in p.read_text() and p.name != "client.py"
    )
    assert users == ["graph/projection.py"]


def test_outside_the_graph_module_only_its_interface_is_imported() -> None:
    """client.driver() could open a writing session: no other module may reach it."""
    internal = re.compile(
        r"argus\.graph\.(client|projection|catalog)\b|from argus\.graph import client"
    )
    users = sorted(
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if not p.is_relative_to(SRC / "graph") and internal.search(p.read_text())
    )
    assert users == []


def test_a_query_not_in_the_catalog_is_refused() -> None:
    with pytest.raises(KeyError):
        client.read("MATCH (n) DETACH DELETE n")


@pytest.mark.db
@pytest.mark.graph
@pytest.mark.usefixtures("graph_clean")
def test_memgraph_refuses_a_write_in_a_read_transaction() -> None:
    def write(tx):  # type: ignore[no-untyped-def]
        return tx.run("CREATE (:Probe) RETURN 1").values()

    with client.driver().session() as session, pytest.raises(Exception, match="misaligned"):
        session.execute_read(write)
    assert graph_rows("MATCH (n:Probe) RETURN count(n) AS n") == [{"n": 0}]
