"""Attack paths: the attacker view (CloudFox) and paths that chain all three tools.

Owns attack_path. Public interface:
    parse_cloudfox()   the CloudFox adapter: one run's raw files -> CloudFoxBatch (pure)
    load_cloudfox()    edges (origin "cloudfox") and attacker-view findings for a day
    PUBLIC_ENDPOINT_CHECK   the check of CloudFox's public endpoints, which ingest checks
                       against Argus's internet rules (ADR-0035)
    evaluate_paths()   searches every path kind for one connection and day (ADR-0037)
    put_path_metrics() attack_paths.* rows in metric_daily
    list_paths(), get_path(), path_facets(), PathFilters, kinds_by_id()   the read side
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
    PathKind,
    evaluate_paths,
    kinds_by_id,
    load_path_kinds,
    put_path_metrics,
)
from argus.attackpaths.load import load_cloudfox
from argus.attackpaths.queries import PathFilters, get_path, list_paths, path_facets

__all__ = [
    "DOORS_SQL",
    "LEVELS",
    "PUBLIC_ENDPOINT_CHECK",
    "SUPPORTED_VERSIONS",
    "CloudFoxBatch",
    "Confidence",
    "PathFilters",
    "PathKind",
    "edge_confidence",
    "evaluate_paths",
    "get_path",
    "kinds_by_id",
    "list_paths",
    "load_cloudfox",
    "load_path_kinds",
    "parse_cloudfox",
    "path_facets",
    "put_path_metrics",
    "source_label",
]
