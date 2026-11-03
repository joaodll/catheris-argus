"""Attack paths: the attacker view (CloudFox) and paths that chain all three tools.

Owns attack_path. Public interface:
    parse_cloudfox()   the CloudFox adapter: one run's raw files -> CloudFoxBatch (pure)
    load_cloudfox()    edges (origin "cloudfox") and attacker-view findings for a day
    PUBLIC_ENDPOINT_CHECK   the check of CloudFox's public endpoints, which ingest checks
                       against Argus's internet rules (ADR-0035)
    the search (ADR-0037), pure, fed by the graph read model (ADR-0044, M2):
        MOVE_TYPES, ENTRY_TYPES, RULE_ENTRY_TYPES, MAX_DEPTH   what it walks
        Step, Chain, step(), entries(), incoming(), rebuild()
    the evaluation's Postgres side, which argus.graph calls once per evaluation:
        kind_targets()     each kind's target uids over every connection
        failing_nodes()    which path nodes have a failing finding now
        assess()           severity and ownership of each chain -> FoundPath
        stored_path_ids(), cap()   which paths found keep a row, and what is cut
        store_paths()      changed paths only, resolve what is gone, path metrics (attack_paths.*)
    list_paths(), get_path(), path_facets(), not_listed(), PathFilters, kinds_by_id()   the read
                       side
                       (Attack paths list and path page, ADR-0033)
    edge_confidence(), source_label(), LEVELS   how sure each step is, and where it is from
    DOORS_SQL          the doors view `d` the path kinds read (ports, admin_port)
"""

from argus.attackpaths.cloudfox import (
    PUBLIC_ENDPOINT_CHECK,
    SUPPORTED_VERSIONS,
    CloudFoxBatch,
    parse_cloudfox,
)
from argus.attackpaths.confidence import LEVELS, Confidence, edge_confidence, source_label
from argus.attackpaths.doors import DOORS_SQL
from argus.attackpaths.engine import (
    PATH_METRICS,
    FoundPath,
    PathKind,
    assess,
    cap,
    failing_nodes,
    kind_targets,
    kinds_by_id,
    load_path_kinds,
    not_listed,
    store_paths,
    stored_path_ids,
)
from argus.attackpaths.load import load_cloudfox
from argus.attackpaths.queries import PathFilters, get_path, list_paths, path_facets
from argus.attackpaths.search import (
    ENTRY_TYPES,
    INTERNET,
    MAX_DEPTH,
    MOVE_TYPES,
    RULE_ENTRY_TYPES,
    Chain,
    Step,
    Targets,
    entries,
    incoming,
    rebuild,
    step,
)

__all__ = [
    "DOORS_SQL",
    "ENTRY_TYPES",
    "INTERNET",
    "LEVELS",
    "MAX_DEPTH",
    "MOVE_TYPES",
    "PATH_METRICS",
    "PUBLIC_ENDPOINT_CHECK",
    "RULE_ENTRY_TYPES",
    "SUPPORTED_VERSIONS",
    "Chain",
    "CloudFoxBatch",
    "Confidence",
    "FoundPath",
    "PathFilters",
    "PathKind",
    "Step",
    "Targets",
    "assess",
    "cap",
    "edge_confidence",
    "entries",
    "failing_nodes",
    "get_path",
    "incoming",
    "kind_targets",
    "kinds_by_id",
    "list_paths",
    "load_cloudfox",
    "load_path_kinds",
    "not_listed",
    "parse_cloudfox",
    "path_facets",
    "rebuild",
    "source_label",
    "step",
    "store_paths",
    "stored_path_ids",
]
