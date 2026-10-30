"""Ingest: turning one committed raw run into canonical rows (design: "Ingestion, snapshots
and attack paths").

    register_run()         records a committed run in scan_run, from its manifest
    register_failed_run()  records a request that failed before it had a manifest to register
    ingest_run()           adapter -> load -> derived steps, for one scan_run
    rederive_stale()       at worker start: edges, flows, reach and paths again for each
                           connection whose rules were upgraded (ADR-0035, fifth amendment)

A failed run is recorded and resolves nothing. A raw run that cannot be read (no manifest,
files that do not match it, an unsupported tool version) marks the scan_run failed with the
reason, instead of being skipped silently.
"""

from argus.ingest.pipeline import IngestOutcome, ingest_run, register_failed_run, register_run
from argus.ingest.queries import data_through, last_runs, list_runs, synthetic_raw_paths_before
from argus.ingest.rederive import REDERIVE_CONNECTIONS, rederive_stale

__all__ = [
    "REDERIVE_CONNECTIONS",
    "IngestOutcome",
    "data_through",
    "ingest_run",
    "last_runs",
    "list_runs",
    "rederive_stale",
    "register_failed_run",
    "register_run",
    "synthetic_raw_paths_before",
]
