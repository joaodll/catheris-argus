"""Collection: producing one run's raw output and its manifest, for one tool and account.

Public interface:
    collect()          run a source into the raw store; the manifest is written last
    read_run()         open a committed run, verifying its manifest and file hashes
    Manifest           the one definition of manifest.json
    TOOL_ORDER         the order tools run against one account (throttling layer 1)
    steampipe_tables() the versioned Steampipe table list
    source_for()       the source a connection kind collects with
    access_for()       how an AWS run reaches its account (credentials are made in collect())
    store_for()        the raw store a connection kind writes to (local volume or S3)

Everything downstream (ingest) reads raw files through read_run() only, whatever the source.
"""

from argus.collection.aws import AwsAccess, access_for
from argus.collection.collect import TOOL_ORDER, CollectOptions, CollectTarget, collect
from argus.collection.sources import source_for
from argus.collection.stores import RawStorageNotConfiguredError, store_for
from argus.collection.tables import steampipe_tables
from argus.core.manifest import Manifest, ManifestFile
from argus.core.rawstore import FilesystemRawStore, RawRun, RawStore, read_run

__all__ = [
    "TOOL_ORDER",
    "AwsAccess",
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
    "read_run",
    "source_for",
    "steampipe_tables",
    "store_for",
]
