"""Collection: producing one run's raw output and its manifest, for one tool and account.

Public interface:
    collect()          run a source into the raw store; the manifest is written last
    Cancelled          what collect() raises for a run asked to stop (CollectOptions.cancel)
    read_run()         open a committed run, verifying its manifest and file hashes
    Manifest           the one definition of manifest.json
    TOOL_ORDER         the order tools run against one account (throttling layer 1)
    steampipe_tables() the versioned Steampipe table list
    prowler_checks(), prowler_services(), prowler_frameworks()
                       the pinned Prowler's AWS checks, their services and its frameworks
    source_for()       the source a connection kind collects with
    access_for()       how an AWS run reaches its account (credentials are made in collect())
    missing_tools()    the tools whose binary this image does not carry (ADR-0046)
    store_for()        the raw store a connection kind writes to (local volume or S3)

Everything downstream (ingest) reads raw files through read_run() only, whatever the source.
"""

from argus.collection.aws import AwsAccess, access_for, missing_tools
from argus.collection.collect import (
    TOOL_ORDER,
    Cancelled,
    CollectOptions,
    CollectTarget,
    collect,
)
from argus.collection.prowler_lists import prowler_checks, prowler_frameworks, prowler_services
from argus.collection.sources import source_for
from argus.collection.stores import RawStorageNotConfiguredError, store_for
from argus.collection.tables import steampipe_tables
from argus.core.manifest import Manifest, ManifestFile
from argus.core.rawstore import FilesystemRawStore, RawRun, RawStore, read_run

__all__ = [
    "TOOL_ORDER",
    "AwsAccess",
    "Cancelled",
    "CollectOptions",
    "CollectTarget",
    "FilesystemRawStore",
    "Manifest",
    "ManifestFile",
    "RawRun",
    "RawStorageNotConfiguredError",
    "RawStore",
    "access_for",
    "collect",
    "missing_tools",
    "prowler_checks",
    "prowler_frameworks",
    "prowler_services",
    "read_run",
    "source_for",
    "steampipe_tables",
    "store_for",
]
