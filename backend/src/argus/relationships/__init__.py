"""Relationships: edges between resources, derived by our own versioned rules (ADR-0006).

Owns edge, edge_snapshot, edge_load and the flow tables (flow, flow_shape, flow_step,
flow_chip, flow_snapshot). Public interface:
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
    neighbourhood(), group_members(), front_doors(), edges_by_ids()   the Resource map's
                      reads (graph.py, ADR-0033)
    delete_loads_before()   retention's cleanup of edge_load
    write_flows(), flow_detail()   Flow mode (flows.py, ADR-0036)
    delete_orphan_flow_shapes()   retention's cleanup of flow shapes
    walk()            the bounded walk over edges (recursive SQL): Flow mode and the attack-path
                      search (ADR-0037)
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
from argus.relationships.flows import (
    delete_orphan_flow_shapes,
    flow_detail,
    write_flows,
)
from argus.relationships.graph import (
    DEFAULT_LAYERS,
    GROUP_OVER,
    MAX_DEPTH,
    MAX_NODES,
    ORIGINS,
    REACHES,
    Direction,
    Layer,
    MapScope,
    Origin,
    Reach,
    edges_by_ids,
    front_doors,
    group_members,
    kind_of,
    neighbourhood,
    node_views,
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
from argus.relationships.walk import walk

__all__ = [
    "DEFAULT_LAYERS",
    "EFFECTIVE_EDGES_SQL",
    "GROUP_OVER",
    "HOSTS_SQL",
    "MAX_DEPTH",
    "MAX_NODES",
    "NO_JIT",
    "ORIGINS",
    "REACHES",
    "RULE_VIEWS_SQL",
    "DerivedEdge",
    "Direction",
    "Door",
    "InternetReach",
    "Layer",
    "MapScope",
    "Origin",
    "Reach",
    "Rule",
    "delete_loads_before",
    "delete_orphan_flow_shapes",
    "derive_edges",
    "edges_at",
    "edges_by_ids",
    "effective_days",
    "flow_detail",
    "front_doors",
    "group_members",
    "internet_reach",
    "kind_of",
    "latest_load_day",
    "latest_rule_loads",
    "load_edges",
    "load_rules",
    "neighbourhood",
    "node_views",
    "owners_of_hosts",
    "walk",
    "write_edges",
    "write_flows",
]
