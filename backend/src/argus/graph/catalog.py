"""The named read queries of the graph (ADR-0044, mitigation 1).

A read reaches Memgraph only through a name in READ_QUERIES, with parameters; a client never
sends Cypher. Every query here is read-only: tests/graph/test_catalog_guard.py fails on any
clause that writes or calls a procedure, and the client runs them in read transactions, which
Memgraph refuses to use for a write. Plain openCypher where possible, so a move to another
engine rewrites this file.

Graph shape (projection.py writes it):
    (:R {uid, conn, provider, account, region, type, name, reach,
         failing_critical, failing_high, failing_medium, failing_low, exploitable})
        a resource; a stub (a uid another connection owns, or a pseudo-node such as
        `internet` or `admin:<account>`) has only `uid`. An account's wildcard pseudo-node is
        `any:<service>@<account>` here, `any:<service>` in Postgres (projection.graph_uid)
    -[:<EDGE_TYPE> {id, conn, origin, confidence, attrs}]->
        an effective edge of the connection `conn`, `id` being Postgres's edge.id
    (:Projection {conn, checksum, source_run_id, ruleset, format})
        the marker of each projected connection (format: projection.FORMAT, the graph's shape)

The attack-path search (ADR-0044, M2) reads the internet edges, a breadth-first walk from the
seeds over the move types (at most MAX_DEPTH moves, never through `internet`), the moves into
the reached nodes and the security groups of the entries. The edge types are attackpaths'
constants, written into the text here: never a caller's input.
"""

from argus.attackpaths import ENTRY_TYPES, INTERNET, MAX_DEPTH, MOVE_TYPES, RULE_ENTRY_TYPES

_MOVES = "|".join(MOVE_TYPES)
_ENTRY_LIST = ", ".join(f"'{t}'" for t in (*ENTRY_TYPES, *RULE_ENTRY_TYPES))
_STEP = """r.id AS id, a.uid AS source, b.uid AS target, type(r) AS type, r.origin AS origin,
           r.confidence AS confidence, r.conn AS conn"""

READ_QUERIES: dict[str, str] = {
    # The attack-path search: the edges leaving the internet, with their target's connection.
    "internet_edges": f"""
        MATCH (a:R {{uid: '{INTERNET}'}})-[r]->(b:R)
        WHERE type(r) IN [{_ENTRY_LIST}]
        RETURN {_STEP}, b.conn AS target_conn
    """,
    # From each seed, every node it reaches with its fewest moves and its connection.
    "reached_from": f"""
        UNWIND $seeds AS seed
        MATCH (s:R {{uid: seed}})
        MATCH p = (s)-[:{_MOVES} *BFS ..{MAX_DEPTH} (r, n | n.uid <> '{INTERNET}')]->(t:R)
        RETURN seed, collect([t.uid, size(relationships(p)), t.conn]) AS reached
    """,
    # The moves into the given nodes, from anything but the internet.
    "moves_into": f"""
        UNWIND $nodes AS node
        MATCH (a:R)-[r:{_MOVES}]->(b:R {{uid: node}})
        WHERE a.uid <> '{INTERNET}'
        RETURN {_STEP}
    """,
    # The security groups of the entries: a failing check on the group is the door's.
    "member_groups": """
        UNWIND $entries AS entry
        MATCH (a:R {uid: entry})-[:MEMBER_OF]->(g:R)
        RETURN DISTINCT a.uid AS entry, g.uid AS grp
    """,
    # The integrity check (projection.verify) reads each connection back.
    "projection_markers": """
        MATCH (p:Projection) RETURN p.conn AS conn, p.checksum AS checksum, p.format AS format
    """,
    "connection_edges": """
        MATCH (a:R)-[r {conn: $conn}]->(b:R)
        RETURN r.id AS id, a.uid AS source, b.uid AS target, type(r) AS type,
               r.origin AS origin, r.confidence AS confidence, r.attrs AS attrs
    """,
    "connection_nodes": """
        MATCH (n:R {conn: $conn})
        RETURN n.uid AS uid, properties(n) AS props
    """,
    # What no projected connection owns: anything counted here was not written by the
    # projection (an edge or a node of an unknown connection, a stub holding more than its uid,
    # or a node of an unknown label).
    "foreign_elements": """
        OPTIONAL MATCH ()-[r]->() WHERE r.conn IS NULL OR NOT r.conn IN $conns
        WITH count(r) AS edges
        OPTIONAL MATCH (n)
        WHERE (n:R AND n.conn IS NOT NULL AND NOT n.conn IN $conns)
           OR (n:R AND n.conn IS NULL AND size(keys(n)) > 1)
           OR (NOT n:R AND NOT n:Projection)
        RETURN edges, count(n) AS nodes
    """,
}
