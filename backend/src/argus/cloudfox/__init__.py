"""CloudFox: the attacker view. Owns no table: it writes edges through argus.relationships and
findings through argus.findings. Public interface:
    parse_cloudfox()   the adapter: one run's raw files -> CloudFoxBatch (pure)
    load_cloudfox()    edges (origin "cloudfox") and attacker-view findings for a day
    PUBLIC_ENDPOINT_CHECK   the check of CloudFox's public endpoints, which ingest checks
                       against Argus's internet rules (ADR-0035)
"""

from argus.cloudfox.load import load_cloudfox
from argus.cloudfox.parse import (
    PUBLIC_ENDPOINT_CHECK,
    SUPPORTED_VERSIONS,
    CloudFoxBatch,
    parse_cloudfox,
)

__all__ = [
    "PUBLIC_ENDPOINT_CHECK",
    "SUPPORTED_VERSIONS",
    "CloudFoxBatch",
    "load_cloudfox",
    "parse_cloudfox",
]
