"""Relationships: edges between resources, derived by our own versioned rules (ADR-0006).

Owns edge, edge_snapshot and edge_load. Public interface:
    load_rules()      the rule files in <rules dir>/relationships/*.toml
    derive_edges()    runs every rule for one connection and day, read-only
    load_edges()      writes derived edges and that day's edge snapshot
    write_edges()     derive + load, the call ingest makes after inventory
    owners_of_hosts() which resource holds a host name or address (the host index `h`)
    effective_days()  each edge family's snapshot that stands for a day
    latest_rule_loads()   each connection's latest rule load and the rule set it was derived
                      with (the worker's re-derive after an upgrade)
    latest_load_day() the latest day either edge family has a load for (where paths are
                      evaluated after a run)
    internet_reach()  what the internet rules say about each resource facing the internet,
                      and why (InternetReach, Door)
    edges_at()        a resource's edges as they stood on a day
    EFFECTIVE_EDGES_SQL   the edges view attack-path rules read
    HOSTS_SQL         the host index `h` the rules read beside `r` (ADR-0033)
    RULE_VIEWS_SQL    every view the rules read beside `r`: `h`, `g` (security group
                      ingress), `rt` and `na` (routes, network ACLs), `p` (internet
                      exposure, ADR-0035), `pa` and `ps` (each role's and user's attached
                      policies and Allow statements, its groups' included; ADR-0037)
    NO_JIT            the setting rule transactions run with (JIT off)
    edges_by_ids()    edges by id, an attack path's steps or a map's (graph.py)
    layer_of(), LAYER_TYPES, kind_of(), group_id(), MapScope, the map's limits   what the Resource
                      map's reads in argus.graph share (ADR-0033; ADR-0044, M3b)
    EDGE_ATTRIBUTES, plain_attributes()   what a map edge and the graph read model keep of an
                      edge's attributes
    delete_loads_before()   retention's cleanup of edge_load
"""

from argus.relationships.engine import (
    HOSTS_SQL,
    NO_JIT,
    RULE_VIEWS_SQL,
    DerivedEdge,
    Rule,
    derive_edges,
    load_edges,
    load_rules,
    owners_of_hosts,
    write_edges,
)
from argus.relationships.graph import (
    DEFAULT_LAYERS,
    EDGE_ATTRIBUTES,
    GROUP_OVER,
    LAYER_TYPES,
    MAX_DEPTH,
    MAX_NODES,
    ORIGINS,
    Direction,
    Layer,
    MapScope,
    Origin,
    edges_by_ids,
    group_id,
    kind_of,
    layer_of,
    plain_attributes,
)
from argus.relationships.queries import (
    EFFECTIVE_EDGES_SQL,
    Door,
    InternetReach,
    delete_loads_before,
    edges_at,
    effective_days,
    internet_reach,
    latest_load_day,
    latest_rule_loads,
)

__all__ = [
    "DEFAULT_LAYERS",
    "EDGE_ATTRIBUTES",
    "EFFECTIVE_EDGES_SQL",
    "GROUP_OVER",
    "HOSTS_SQL",
    "LAYER_TYPES",
    "MAX_DEPTH",
    "MAX_NODES",
    "NO_JIT",
    "ORIGINS",
    "RULE_VIEWS_SQL",
    "DerivedEdge",
    "Direction",
    "Door",
    "InternetReach",
    "Layer",
    "MapScope",
    "Origin",
    "Rule",
    "delete_loads_before",
    "derive_edges",
    "edges_at",
    "edges_by_ids",
    "effective_days",
    "group_id",
    "internet_reach",
    "kind_of",
    "latest_load_day",
    "latest_rule_loads",
    "layer_of",
    "load_edges",
    "load_rules",
    "owners_of_hosts",
    "plain_attributes",
    "write_edges",
]
