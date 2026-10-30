"""Which raw store a run writes to. Demo connections use the local volume: synthetic output is
regenerable and pruned within days. AWS connections use the S3 bucket set in the UI, and
cannot run while none is set, so a real account's output never lands on the local volume.

Read per run, never cached: a change in Settings applies from the next claim.
"""

from typing import Literal

from sqlalchemy import Connection

from argus.core import aws
from argus.core.config import get_settings
from argus.core.rawstore import FilesystemRawStore, RawStore, S3Location, S3RawStore
from argus.settings import read_identity_credentials, read_raw_storage


class RawStorageNotConfiguredError(RuntimeError):
    """An AWS run with no bucket set in Settings -> Raw output storage."""


def store_for(
    conn: Connection, kind: Literal["demo", "aws"], *, local: FilesystemRawStore
) -> RawStore:
    if kind == "demo":
        return local
    storage = read_raw_storage(conn)
    if storage.bucket is None or storage.region is None:
        raise RawStorageNotConfiguredError(
            "AWS runs need raw output storage: set a bucket in Settings -> Raw output storage"
        )
    credentials = read_identity_credentials(conn)
    client = aws.s3_client(region=storage.region, credentials=credentials)
    return S3RawStore(
        client,
        S3Location(storage.bucket, storage.prefixes.model_dump()),
        get_settings().raw_staging_root,
    )
