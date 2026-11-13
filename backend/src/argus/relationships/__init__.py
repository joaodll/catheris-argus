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
    principal_facts() who is an administrator, and each IAM user's credentials that work
                      from anywhere, as plain values (PrincipalFacts; Risk, ADR-0049)
    edges_at()        a resource's edges as they stood on a day
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
from argus.relationships.queries import (
    Door,
    InternetReach,
    PrincipalFacts,
    delete_loads_before,
    edges_at,
    effective_days,
    internet_reach,
    latest_rule_loads,
    principal_facts,
)

__all__ = [
    "HOSTS_SQL",
    "NO_JIT",
    "RULE_VIEWS_SQL",
    "DerivedEdge",
    "Door",
    "InternetReach",
    "PrincipalFacts",
    "Rule",
    "delete_loads_before",
    "derive_edges",
    "edges_at",
    "effective_days",
    "internet_reach",
    "latest_rule_loads",
    "load_edges",
    "load_rules",
    "owners_of_hosts",
    "principal_facts",
    "write_edges",
]
