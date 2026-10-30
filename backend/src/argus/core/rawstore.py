"""The raw archive: one directory per run, laid out as the design specifies,

    <root>/raw/<tool>/<provider>/<account>/<YYYY>/<MM>/<DD>/<run uid>/

with manifest.json written last and atomically. Two backends implement one protocol
(ADR-0003): the filesystem serves Demo connections in Compose, and S3 holds the output of
real AWS runs, under a key prefix per tool set in the UI (Settings -> Raw output storage).
"""

import gzip
import hashlib
import os
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from errno import ENOSPC
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from uuid import UUID

from botocore.exceptions import BotoCoreError, ClientError

from argus.core.manifest import MANIFEST_NAME, Manifest, ManifestFile, Tool


class RawRunError(ValueError):
    """A run directory that must not be ingested: no manifest, or files that do not match it."""


class RawStoreError(RuntimeError):
    """The archive refused a run's files: the run cannot be kept, so it is failed."""


@dataclass(frozen=True)
class RawRun:
    manifest: Manifest
    root: Path  # the run directory

    def path(self, relative: str) -> Path:
        return self.root / relative


def run_key(prefix: str, account_id: str, day: date, run_uid: UUID) -> str:
    """A run's folder under a tool's prefix: <prefix>/aws/<account>/<YYYY>/<MM>/<DD>/<run_uid>.
    Runs archived before 2026-10-06 used one <YYYY-MM-DD> folder; scan_run.raw_path keeps
    each run's own location, so they are still found."""
    return str(
        PurePosixPath(
            prefix, "aws", account_id, f"{day:%Y}", f"{day:%m}", f"{day:%d}", str(run_uid)
        )
    )


def raw_path(tool: Tool, account_id: str, day: date, run_uid: UUID) -> str:
    """The run's location relative to the store root, as recorded in scan_run.raw_path."""
    return run_key(f"raw/{tool}", account_id, day, run_uid)


class RawStore(Protocol):
    def path_for(self, tool: Tool, account_id: str, day: date, run_uid: UUID) -> str: ...
    def staging_dir(self, path: str) -> Path: ...
    def commit(self, path: str, manifest: Manifest) -> Manifest:
        """Archive the run, manifest last. Returns the manifest as committed: a store may add
        what it learned while archiving (S3: the encryption of the objects)."""
        ...

    def open(self, path: str) -> Path: ...
    def release(self, path: str) -> None: ...


def _write_manifest(run_dir: Path, manifest: Manifest) -> None:
    tmp = run_dir / f".{MANIFEST_NAME}.tmp"
    tmp.write_text(manifest.model_dump_json(indent=2))
    os.replace(tmp, run_dir / MANIFEST_NAME)


class FilesystemRawStore:
    """Demo runs on a local volume (Docker Compose): the volume is the archive itself, and
    retention prunes it."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _resolve(self, path: str) -> Path:
        target = (self.root / path).resolve()
        if not target.is_relative_to(self.root.resolve()):
            raise RawRunError(f"raw path escapes the store: {path}")
        return target

    def path_for(self, tool: Tool, account_id: str, day: date, run_uid: UUID) -> str:
        return raw_path(tool, account_id, day, run_uid)

    def staging_dir(self, path: str) -> Path:
        target = self._resolve(path)
        target.mkdir(parents=True, exist_ok=False)
        return target

    def commit(self, path: str, manifest: Manifest) -> Manifest:
        _write_manifest(self._resolve(path), manifest)
        return manifest

    def open(self, path: str) -> Path:
        return self._resolve(path)

    def release(self, path: str) -> None:
        """Nothing to release: the filesystem is the archive itself."""


# Server-side encryption values S3 reports, strongest first. KMS keeps a key policy and a
# decrypt audit trail in CloudTrail; AES256 (SSE-S3) encrypts at rest with neither.
KMS_ENCRYPTION = ("aws:kms:dsse", "aws:kms")
_ENCRYPTION_RANK = (*KMS_ENCRYPTION, "AES256")


def weakest_encryption(values: set[str]) -> str:
    """The weakest of a run's object encryptions; an unknown value counts as the weakest."""
    unknown = sorted(v for v in values if v not in _ENCRYPTION_RANK)
    if unknown:
        return unknown[0]
    return max(values, key=_ENCRYPTION_RANK.index)


class S3Client(Protocol):
    """The one boto3 S3 call Argus makes."""

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class S3Location:
    bucket: str
    prefixes: Mapping[str, str]  # tool -> key prefix, without slashes at either end


class S3RawStore:
    """Raw output in the bucket set in the UI. A run is staged on a tmpfs, then every file is
    uploaded gzip-compressed as <path>.gz, manifest.json last and plain, so a run without a
    manifest in S3 is incomplete.

    Encryption is the bucket's default and the operator's choice (ADR-0031). Argus sends no
    key and refuses nothing: it records the weakest encryption S3 reported for the run's
    objects in the manifest (raw_encryption), and the UI flags runs stored without KMS, since
    raw output can hold secret values.

    Ingest reads the staged copy, so Argus never reads back from S3: the platform identity
    needs s3:PutObject on the bucket and the KMS permissions of its default key, nothing more.
    Replaying a run from S3 is not supported yet."""

    def __init__(self, client: S3Client, location: S3Location, staging_root: Path) -> None:
        self.client = client
        self.location = location
        self.staging_root = staging_root

    def path_for(self, tool: Tool, account_id: str, day: date, run_uid: UUID) -> str:
        key = run_key(self.location.prefixes[tool], account_id, day, run_uid)
        return f"s3://{self.location.bucket}/{key}"

    def _key(self, path: str) -> str:
        head = f"s3://{self.location.bucket}/"
        if not path.startswith(head):
            raise RawRunError(f"not in this store's bucket: {path}")
        return path.removeprefix(head)

    def _staged(self, path: str) -> Path:
        run_uid = UUID(PurePosixPath(self._key(path)).name)  # also refuses a crafted path
        return self.staging_root / str(run_uid)

    def staging_dir(self, path: str) -> Path:
        target = self._staged(path)
        target.mkdir(mode=0o700, parents=True, exist_ok=False)
        return target

    def _put(self, key: str, file: Path, **extra: str) -> str:
        """Uploads one object; returns the encryption S3 reports for it ("none" if none)."""
        try:
            with file.open("rb") as body:
                answer = self.client.put_object(
                    Bucket=self.location.bucket,
                    Key=key,
                    Body=body,
                    ChecksumAlgorithm="SHA256",
                    **extra,
                )
        except (BotoCoreError, ClientError) as exc:
            raise RawStoreError(f"upload of {key} failed: {exc}") from exc
        return str(answer.get("ServerSideEncryption") or "none")

    def _put_compressed(self, key: str, file: Path) -> str:
        """Uploads one output file gzip-compressed as <key>.gz (argus_v8). It is compressed into
        a temporary file next to the staged runs, one file at a time, so staging never holds
        more than the run plus its largest file. The archive's bytes are reproducible: no name
        and no time in the gzip header."""
        with tempfile.NamedTemporaryFile(dir=self.staging_root, suffix=".gz") as packed:
            with (
                file.open("rb") as source,
                gzip.GzipFile(
                    filename="", mode="wb", fileobj=packed, mtime=0, compresslevel=6
                ) as zipped,
            ):
                shutil.copyfileobj(source, zipped, length=1024 * 1024)
            packed.flush()
            return self._put(f"{key}.gz", Path(packed.name), ContentType="application/gzip")

    def commit(self, path: str, manifest: Manifest) -> Manifest:
        run_dir = self._staged(path)
        key = self._key(path)
        try:
            seen = {
                self._put_compressed(f"{key}/{file.path}", run_dir / file.path)
                for file in manifest.files
            }
            if seen:
                manifest = manifest.model_copy(
                    update={"raw_encryption": weakest_encryption(seen), "raw_compression": "gzip"}
                )
            _write_manifest(run_dir, manifest)  # ingest reads the staged copy
        except OSError as exc:  # staging, not S3: full, or a file gone. No manifest is uploaded.
            reason = f"raw staging is full: {self.staging_root}" if exc.errno == ENOSPC else exc
            raise RawStoreError(f"staged output unreadable or unwritable: {reason}") from exc
        self._put(f"{key}/{MANIFEST_NAME}", run_dir / MANIFEST_NAME)
        return manifest

    def open(self, path: str) -> Path:
        run_dir = self._staged(path)
        if not run_dir.is_dir():
            raise RawRunError(f"{path}: not staged here; replay from S3 is not supported yet")
        return run_dir

    def release(self, path: str) -> None:
        shutil.rmtree(self._staged(path), ignore_errors=True)


def sweep_staging(staging_root: Path) -> int:
    """Empties the staging root when the worker starts; returns how many runs were removed.
    A worker that stopped mid-run never deleted what it staged. Its claims are requeued with
    new run ids, so nothing here belongs to a live run (ADR-0032)."""
    if not staging_root.is_dir():
        return 0
    removed = 0
    for entry in staging_root.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            entry.unlink(missing_ok=True)
        removed += 1
    return removed


def describe_files(run_dir: Path) -> list[ManifestFile]:
    files = []
    for file in sorted(p for p in run_dir.rglob("*") if p.is_file()):
        rel = file.relative_to(run_dir).as_posix()
        if rel == MANIFEST_NAME or rel.startswith("."):
            continue
        data = file.read_bytes()
        files.append(
            ManifestFile(path=rel, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        )
    return files


def read_run(store: RawStore, path: str) -> RawRun:
    """Opens a committed run. Raises RawRunError if it has no manifest or its files differ."""
    run_dir = store.open(path)
    manifest_file = run_dir / MANIFEST_NAME
    if not manifest_file.exists():
        raise RawRunError(f"{path}: no {MANIFEST_NAME}; the run is incomplete")
    manifest = Manifest.model_validate_json(manifest_file.read_text())
    if describe_files(run_dir) != manifest.files:
        raise RawRunError(f"{path}: files do not match the manifest")
    return RawRun(manifest=manifest, root=run_dir)
