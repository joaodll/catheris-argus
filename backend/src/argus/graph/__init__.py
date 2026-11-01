"""The graph read model (ADR-0044): every connection's current state, in Memgraph.

Postgres is the system of record. This module projects what Postgres holds now (each enabled
connection's effective edges, its inventory on the effective day, and the facts the graph
questions filter on) into one Memgraph graph across connections and providers, and checks that
Memgraph still holds what was projected. Nothing in Memgraph is unique: it is rebuilt from
Postgres whenever it is empty, stale or tampered with.

Owns the `graph_projection` table (one row per projected connection: the marker it was projected
from, counts, checksum, status).

Interface:
    reconcile(engine)        sync every connection whose marker changed, drop the ones that
                             left; the only entry point that writes to Memgraph
    verify(engine)           the integrity check: re-read each connection, compare checksums,
                             re-sync and audit on drift
    status(conn)             graph_projection rows, for "as of" and the UI
    read(name, **params)     run one named query of the catalog, in a read transaction
    GRAPH_CONNECTIONS        the most Postgres connections reconcile/verify hold at once

Only projection.py writes to Memgraph. Every read goes through catalog.READ_QUERIES by name; a
client never sends Cypher.
"""

from argus.graph.client import read
from argus.graph.projection import GRAPH_CONNECTIONS, reconcile, status, verify

__all__ = ["GRAPH_CONNECTIONS", "read", "reconcile", "status", "verify"]
