"""Risk: the resources where facts from different tools add up, worst first (ADR-0049).

Owns resource_risk and risk_load. Reads the other modules only through what they export:
findings (each resource's open CVEs and misconfigurations), relationships (internet doors,
administrators, credentials), inventory (current assets) and connections (the directory).
Public interface:
    refresh()           recompute one connection's rows after it changed (ingest, re-derive)
    stale_connections() enabled connections never refreshed, or with another combination set
    list_risk(), risk_scope(), risk_types()   the read side (the Risk screen)
    COMBINATIONS        the named combinations, each with its tier and plain-words description
    combination_set()   the SHA-256 of every combination's id and version
"""

from argus.risk.combinations import COMBINATIONS, TIERS, Combination, combination_set
from argus.risk.queries import RiskFilters, RiskScope, list_risk, risk_scope, risk_types
from argus.risk.refresh import Refreshed, refresh, stale_connections

__all__ = [
    "COMBINATIONS",
    "TIERS",
    "Combination",
    "Refreshed",
    "RiskFilters",
    "RiskScope",
    "combination_set",
    "list_risk",
    "refresh",
    "risk_scope",
    "risk_types",
    "stale_connections",
]
