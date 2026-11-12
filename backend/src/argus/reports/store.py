"""Where report files live (ADR-0047). One interface, two stores:

- LocalReportStore, Docker Compose: a local volume the worker writes and the API reads only. The
  path check is the raw store's own: a key that resolves outside the root is refused.
- S3ReportStore, Kubernetes: the reports/ folder of the raw-output bucket. The report Job writes
  with one PUT and the API reads, each with its own IRSA role (core.aws.web_identity_s3_client).
  Argus never deletes there: a lifecycle rule on reports/ does (docs/aws-policies.md).

Every key has one shape, reports/<id>-<32 hex>.<format>, checked here and by the table's CHECK.
A download is served only when the stored file is the one the build recorded: its size, and on
S3 its SHA-256 as S3 computed it on upload (review SA-5). The checks run before the first byte.
"""

import base64
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError

from argus.core.rawstore import FilesystemRawStore, RawRunError
from argus.reports.model import MAX_REPORT_BYTES, ClaimedReport, ReportFormat

FOLDER = "reports"
# The one shape a key may have; the table's CHECK holds the same pattern.
_KEY = re.compile(r"^reports/[0-9]+-[0-9a-f]{32}\.(csv|pdf)$")
CHUNK_BYTES = 1 << 20
_MEDIA_TYPES = {"csv": "text/csv; charset=utf-8", "pdf": "application/pdf"}


class ReportStoreError(Exception):
    """A key that is not a report's, a path outside the store, or a file that is missing or not
    the one the build recorded."""


class ReportFileChangedError(ReportStoreError):
    """The stored file is not the one the build recorded: another size or another SHA-256."""


class ReportStoreUnavailableError(Exception):
    """The store can't be reached now (no identity, S3 out of reach): try again later."""


def new_key(report_id: int, fmt: ReportFormat) -> str:
    return f"{FOLDER}/{report_id}-{uuid4().hex}.{fmt}"


def check_key(key: str) -> str:
    if not _KEY.fullmatch(key):
        raise ReportStoreError("not a report key")
    return key


class ReportStore(Protocol):
    # A local store takes Demo connections only (ADR-0032); S3 takes every connection.
    local: bool

    def temp_path(self, key: str) -> Path:
        """Where a build writes the file before it is complete."""
        ...

    def publish(self, temp: Path, key: str, *, sha256: str) -> None:
        """Makes the written file the report's, whole, and removes the temporary one."""
        ...

    def delete(self, key: str) -> bool:
        """Removes a file Argus may delete; False when it did not (gone, or not Argus's to
        delete)."""
        ...

    def open(self, key: str, *, size_bytes: int, sha256: str) -> Iterator[bytes]:
        """The file's bytes in chunks, once its size (and on S3 its SHA-256) matched what the
        build recorded. The checks raise before the first chunk."""
        ...


# Which store a claimed report is built into: one for every report on Compose; on Kubernetes
# the bucket recorded on the report.
StoreFor = Callable[[ClaimedReport], ReportStore]


class LocalReportStore:
    local = True

    def __init__(self, root: Path) -> None:
        self._files = FilesystemRawStore(root)

    def path(self, key: str) -> Path:
        """The file of a key, checked twice: the key's shape, then that it stays in the root."""
        check_key(key)
        try:
            return self._files.open(key)
        except RawRunError as exc:  # the resolved path escapes the root
            raise ReportStoreError("report path escapes the store") from exc

    def temp_path(self, key: str) -> Path:
        """Beside the final file, hidden, so a rename publishes it whole."""
        final = self.path(key)
        final.parent.mkdir(mode=0o700, exist_ok=True)
        return final.with_name(f".{final.name}.part")

    def publish(self, temp: Path, key: str, *, sha256: str) -> None:
        target = self.path(key)
        with temp.open("rb") as f:
            os.fsync(f.fileno())
        os.replace(temp, target)

    def sweep(self, kept: set[str]) -> int:
        """Removes every file in the reports folder that no report names: a partial file a
        stopped build left, or one published just before its report could be recorded. Run
        only while nothing builds (the worker's report thread, as it starts). Returns how many
        files were removed."""
        folder = self._files.open(FOLDER)
        if not folder.is_dir():
            return 0
        removed = 0
        for entry in folder.iterdir():
            if f"{FOLDER}/{entry.name}" in kept or not entry.is_file() or entry.is_symlink():
                continue
            entry.unlink(missing_ok=True)
            removed += 1
        return removed

    def delete(self, key: str) -> bool:
        try:
            self.path(key).unlink()
        except FileNotFoundError:
            return False
        return True

    def open(self, key: str, *, size_bytes: int, sha256: str) -> Iterator[bytes]:
        # The volume is written by the worker alone; its size is checked, its hash is not
        # (reading the file twice for every download buys nothing there).
        path = self.path(key)
        try:
            f = path.open("rb")
        except FileNotFoundError:
            raise ReportStoreError("report file missing") from None
        if os.fstat(f.fileno()).st_size != size_bytes or path.is_symlink():
            f.close()
            raise ReportFileChangedError("report file is not the one recorded")
        return _Chunks(lambda: f.read(CHUNK_BYTES), f.close)


class _Chunks:
    """A file's bytes in chunks that closes the file at the end, on an error, or when the
    caller closes it before reading (a refused response never leaves a handle open)."""

    def __init__(self, read: Callable[[], bytes], close: Callable[[], None]) -> None:
        self._read = read
        self._close = close
        self._closed = False

    def __iter__(self) -> "_Chunks":
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration
        try:
            chunk = self._read()
        except BaseException:
            self.close()
            raise
        if not chunk:
            self.close()
            raise StopIteration
        return chunk

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._close()


def _b64(sha256_hex: str) -> str:
    return base64.b64encode(bytes.fromhex(sha256_hex)).decode()


class S3ReportStore:
    """The reports/ folder of one bucket. The client is the pod's own IRSA role: the report
    Job's may only put there, the API's may only get there (docs/aws-policies.md)."""

    local = False

    def __init__(self, client: Any, bucket: str, scratch: Path | None = None) -> None:
        self._client = client
        self._bucket = bucket
        self._scratch = scratch

    def temp_path(self, key: str) -> Path:
        """In the Job's scratch volume, owner-only; deleted with the pod in any case."""
        check_key(key)
        if self._scratch is None:
            raise ReportStoreError("this store only reads")
        self._scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        return self._scratch / f".{key.replace('/', '-')}.part"

    def publish(self, temp: Path, key: str, *, sha256: str) -> None:
        """One PUT, never a multipart upload. S3 checks the SHA-256 sent with it, so a file
        changed on the way is refused, and keeps it for the download's check."""
        check_key(key)
        try:
            size = temp.stat().st_size
            if size > MAX_REPORT_BYTES:
                raise ReportStoreError("report file larger than the cap")
            with temp.open("rb") as body:
                self._client.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=body,
                    ContentLength=size,
                    ContentType=_MEDIA_TYPES[key.rsplit(".", 1)[1]],
                    ChecksumSHA256=_b64(sha256),
                )
        except (BotoCoreError, ClientError) as exc:
            raise ReportStoreUnavailableError(_aws_reason(exc)) from exc
        finally:
            temp.unlink(missing_ok=True)

    def delete(self, key: str) -> bool:
        # Argus holds no s3:DeleteObject: the lifecycle rule on reports/ removes files.
        return False

    def open(self, key: str, *, size_bytes: int, sha256: str) -> Iterator[bytes]:
        check_key(key)
        try:
            answer = self._client.get_object(Bucket=self._bucket, Key=key, ChecksumMode="ENABLED")
        except ClientError as exc:
            if _code(exc) in ("NoSuchKey", "404"):
                raise ReportStoreError("report file missing") from None
            raise ReportStoreUnavailableError(_aws_reason(exc)) from exc
        except BotoCoreError as exc:
            raise ReportStoreUnavailableError(_aws_reason(exc)) from exc
        body = answer["Body"]
        length = answer.get("ContentLength")
        stored = answer.get("ChecksumSHA256")
        if length != size_bytes or length > MAX_REPORT_BYTES or stored != _b64(sha256):
            body.close()
            raise ReportFileChangedError("report file is not the one recorded")
        return _Chunks(lambda: body.read(CHUNK_BYTES), body.close)


def _code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def _aws_reason(exc: Exception) -> str:
    """What to log: the error's class and AWS's code, never its message (it can name the
    bucket's owner account or the role)."""
    if isinstance(exc, ClientError):
        return f"{type(exc).__name__}: {_code(exc)}"
    return type(exc).__name__
