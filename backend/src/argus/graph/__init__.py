"""The graph read model (ADR-0044): every connection's current state, in Memgraph.

Postgres is the system of record. This module projects what Postgres holds now (each enabled
connection's effective edges and its inventory on the effective day) into one Memgraph graph
across connections and providers, and checks that Memgraph still holds what was projected. Nothing
in Memgraph is unique: it is rebuilt from Postgres whenever it is empty, stale or tampered with.

Owns the `graph_projection` table (one row per projected connection: the marker it was projected
from, counts, checksum, status).

Interface:
    reconcile(engine)        sync every connection whose marker changed, drop the ones that
                             left; the only entry point that writes to Memgraph
    verify(engine)           the integrity check: re-read each connection, compare checksums,
                             re-sync and audit on drift
    evaluate_paths(engine)   the attack-path search over every connection, across accounts
                             (round M2): upserts, resolves and counts attack_path rows
    paths_state(conn)        whether the stored paths are behind the scans (the API's note)
    neighbourhood(), group_members(), map_state(), GraphUnavailable
                             the Resource map's reads (round M3b), and how current they are
    status(conn)             graph_projection rows, for "as of" and the UI
    read(name, **params)     run one named query of the catalog, in a read transaction
    GRAPH_CONNECTIONS        the most Postgres connections reconcile/verify/evaluate hold at once

Only projection.py writes to Memgraph. Every read goes through catalog.READ_QUERIES by name; a
client never sends Cypher.
"""

from argus.graph.client import read
from argus.graph.paths import evaluate_paths, paths_state
from argus.graph.projection import GRAPH_CONNECTIONS, reconcile, status, verify
from argus.graph.resource_map import GraphUnavailable, group_members, map_state, neighbourhood

__all__ = [
    "GRAPH_CONNECTIONS",
    "GraphUnavailable",
    "evaluate_paths",
    "group_members",
    "map_state",
    "neighbourhood",
    "paths_state",
    "read",
    "reconcile",
    "status",
    "verify",
]
