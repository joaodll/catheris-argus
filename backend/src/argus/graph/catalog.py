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
        `internet` or `admin:<account>`) has only `uid`
    -[:<EDGE_TYPE> {id, conn, origin, confidence, attrs}]->
        an effective edge of the connection `conn`, `id` being Postgres's edge.id
    (:Projection {conn, checksum, source_run_id, ruleset})
        the marker of each projected connection
"""

READ_QUERIES: dict[str, str] = {
    # The integrity check (projection.verify) reads each connection back.
    "projection_markers": """
        MATCH (p:Projection) RETURN p.conn AS conn, p.checksum AS checksum
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
