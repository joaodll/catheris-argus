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
    internet_reach()  what the internet rules say about each resource facing the internet,
                      and why (InternetReach, Door)
    edges_at()        a resource's edges as they stood on a day
    neighbourhood(), group_members(), map_edges_at()   the Resource Map's and the Security
                      Map's reads (graph.py, ADR-0051): up to MAX_DEPTH hops around a focus, a
                      group's members and a panel's edges, for a MapScope and a Map; Layer,
                      Origin, DEFAULT_LAYERS and ORIGINS name what a client may ask for;
                      SECURITY_EDGE_TYPES are the Security Map's own lines (on_map());
                      EDGE_ATTRIBUTES is all a map edge shows of its attributes
    HOSTS_SQL         the host index `h` the rules read beside `r` (ADR-0033)
    RULE_VIEWS_SQL    every view the rules read beside `r`: `h`, `g` (security group
                      ingress), `rt` and `na` (routes, network ACLs), `p` (internet
                      exposure, ADR-0035), `pa` and `ps` (each role's and user's attached
                      policies and Allow statements, its groups' included; ADR-0037)
    NO_JIT            the setting rule transactions run with (JIT off)
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
    MAX_DEPTH,
    ORIGINS,
    SECURITY_EDGE_TYPES,
    Layer,
    Map,
    MapScope,
    Origin,
    group_members,
    map_edges_at,
    neighbourhood,
    on_map,
)
from argus.relationships.queries import (
    Door,
    InternetReach,
    delete_loads_before,
    edges_at,
    effective_days,
    internet_reach,
    latest_rule_loads,
)

__all__ = [
    "DEFAULT_LAYERS",
    "EDGE_ATTRIBUTES",
    "HOSTS_SQL",
    "MAX_DEPTH",
    "NO_JIT",
    "ORIGINS",
    "RULE_VIEWS_SQL",
    "SECURITY_EDGE_TYPES",
    "DerivedEdge",
    "Door",
    "InternetReach",
    "Layer",
    "Map",
    "MapScope",
    "Origin",
    "Rule",
    "delete_loads_before",
    "derive_edges",
    "edges_at",
    "effective_days",
    "group_members",
    "internet_reach",
    "latest_rule_loads",
    "load_edges",
    "load_rules",
    "map_edges_at",
    "neighbourhood",
    "on_map",
    "owners_of_hosts",
    "write_edges",
]
