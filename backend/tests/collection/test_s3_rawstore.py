"""Raw output of AWS runs goes to the operator's bucket: every file gzip-compressed, then
manifest.json last and plain.
The bucket's default encryption is recorded, not enforced (ADR-0031). An upload the archive
refuses fails the run. S3 is stubbed (botocore's Stubber): the requests are checked, nothing
leaves the test."""

import errno
import gzip
import hashlib
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any
from uuid import UUID

import boto3
import pytest
from botocore.stub import ANY, Stubber

from argus.collection import (
    CollectOptions,
    CollectTarget,
    FilesystemRawStore,
    collect,
    read_run,
    source_for,
)
from argus.core import rawstore
from argus.core.manifest import MANIFEST_NAME, Manifest
from argus.core.rawstore import RawRunError, S3Location, S3RawStore, weakest_encryption

DAY = date(2026, 10, 2)
RUN_UID = UUID(int=7)
TARGET = CollectTarget(1, "demo", "100000000010", demo_seed=0)
QUIET = CollectOptions(synthetic_throttle_share=0.0)
LOCATION = S3Location(
    "argus-raw-example",
    {"steampipe": "raw/steampipe", "prowler": "scans/prowler", "cloudfox": "raw/cloudfox"},
)
# <prefix>/aws/<account>/<YYYY>/<MM>/<DD>/<run_uid>
PREFIX = "scans/prowler/aws/100000000010/2026/10/02/00000000-0000-0000-0000-000000000007"


@pytest.fixture
def s3() -> Iterator[tuple[S3RawStore, Stubber]]:
    client = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name="eu-west-1"
    ).client("s3")
    with Stubber(client) as stubber:
        yield S3RawStore(client, LOCATION, Path("/nonexistent")), stubber


def _expect_put(stubber: Stubber, key: str, encryption: str = "aws:kms") -> None:
    """One object: an output file (compressed, <path>.gz) or the manifest (plain)."""
    params = {"Bucket": LOCATION.bucket, "Key": key, "Body": ANY, "ChecksumAlgorithm": "SHA256"}
    if key.endswith(".gz"):
        params["ContentType"] = "application/gzip"
    stubber.add_response("put_object", {"ServerSideEncryption": encryption}, params)


def _collect(store: S3RawStore, staging: Path) -> tuple[str, Manifest]:
    store.staging_root = staging
    return collect(
        source_for("demo"),
        store,
        target=TARGET,
        tool="prowler",
        day=DAY,
        run_uid=RUN_UID,
        options=QUIET,
    )


def _files(tmp_path: Path) -> list[str]:
    """The files the synthetic Prowler source writes, in upload order (local run, same day)."""
    _, manifest = collect(
        source_for("demo"),
        FilesystemRawStore(tmp_path / "local"),
        target=TARGET,
        tool="prowler",
        day=DAY,
        run_uid=RUN_UID,
        options=QUIET,
    )
    return [f.path for f in manifest.files]


def test_files_go_under_the_tool_prefix_with_the_manifest_last(
    s3: tuple[S3RawStore, Stubber], tmp_path: Path
) -> None:
    store, stubber = s3
    for name in _files(tmp_path):
        _expect_put(stubber, f"{PREFIX}/{name}.gz")
    _expect_put(stubber, f"{PREFIX}/{MANIFEST_NAME}")
    path, manifest = _collect(store, tmp_path / "staging")
    stubber.assert_no_pending_responses()
    assert path == f"s3://{LOCATION.bucket}/{PREFIX}"
    assert manifest.status == "complete"
    assert manifest.raw_encryption == "aws:kms"
    assert manifest.raw_compression == "gzip"
    # Ingest reads the staged copy; release removes it.
    assert read_run(store, path).manifest == manifest
    store.release(path)
    with pytest.raises(RawRunError, match="replay from S3"):
        store.open(path)


def test_a_bucket_without_kms_is_recorded_not_refused(
    s3: tuple[S3RawStore, Stubber], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store, stubber = s3
    names = _files(tmp_path)
    for i, name in enumerate(names):  # one object under SSE-S3 makes the run's value AES256
        _expect_put(stubber, f"{PREFIX}/{name}.gz", encryption="AES256" if i == 1 else "aws:kms")
    _expect_put(stubber, f"{PREFIX}/{MANIFEST_NAME}", encryption="AES256")
    path, manifest = _collect(store, tmp_path / "staging")
    stubber.assert_no_pending_responses()
    assert manifest.status == "complete"
    assert manifest.raw_encryption == "AES256"
    assert read_run(store, path).manifest.raw_encryption == "AES256"  # in the manifest itself
    assert "raw output stored without KMS" in caplog.text


class _Recorder:
    """Keeps what each put_object sent, so the bytes can be checked."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        self.objects[kwargs["Key"]] = kwargs["Body"].read()
        return {"ServerSideEncryption": "aws:kms"}


def test_each_object_decompresses_to_what_the_manifest_lists(tmp_path: Path) -> None:
    client = _Recorder()
    store = S3RawStore(client, LOCATION, tmp_path / "staging")  # type: ignore[arg-type]
    _, manifest = _collect(store, tmp_path / "staging")
    assert manifest.status == "complete" and manifest.files
    for file in manifest.files:
        packed = client.objects.pop(f"{PREFIX}/{file.path}.gz")
        content = gzip.decompress(packed)
        assert len(content) == file.bytes
        assert hashlib.sha256(content).hexdigest() == file.sha256
        assert packed[4:8] == b"\0\0\0\0"  # no time in the header: reproducible bytes
    uploaded = Manifest.model_validate_json(client.objects.pop(f"{PREFIX}/{MANIFEST_NAME}"))
    assert uploaded.raw_compression == "gzip"
    assert client.objects == {}  # nothing else, and no temporary file left in staging
    assert [p.name for p in (tmp_path / "staging").iterdir()] == [str(RUN_UID)]


@pytest.mark.parametrize(
    ("seen", "weakest"),
    [
        ({"aws:kms"}, "aws:kms"),
        ({"aws:kms", "aws:kms:dsse"}, "aws:kms"),
        ({"aws:kms", "AES256"}, "AES256"),
        ({"AES256", "none"}, "none"),
    ],
    ids=["kms", "kms-and-dsse", "kms-and-sse-s3", "unencrypted"],
)
def test_the_weakest_encryption_is_reported(seen: set[str], weakest: str) -> None:
    assert weakest_encryption(seen) == weakest


def test_a_refused_upload_fails_the_run(s3: tuple[S3RawStore, Stubber], tmp_path: Path) -> None:
    store, stubber = s3
    stubber.add_client_error("put_object", "AccessDenied", "Access Denied", 403)
    path, manifest = _collect(store, tmp_path / "staging")
    assert manifest.status == "failed"
    assert "AccessDenied" in manifest.log_tail
    store.release(path)  # the runner's finally
    assert list((tmp_path / "staging").iterdir()) == []


def test_full_staging_fails_the_run_without_a_manifest_in_s3(
    s3: tuple[S3RawStore, Stubber], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, stubber = s3
    for name in _files(tmp_path):
        _expect_put(stubber, f"{PREFIX}/{name}.gz")

    def full(*_: object) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(rawstore, "_write_manifest", full)
    path, manifest = _collect(store, tmp_path / "staging")
    stubber.assert_no_pending_responses()  # every file, but no manifest.json: never ingested
    assert manifest.status == "failed"
    assert "raw staging is full" in manifest.log_tail
    store.release(path)
    assert list((tmp_path / "staging").iterdir()) == []


def test_an_error_after_staging_deletes_the_staged_output(
    s3: tuple[S3RawStore, Stubber], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = s3

    def broken(*_: object, **__: object) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(store, "commit", broken)
    with pytest.raises(RuntimeError, match="unexpected"):
        _collect(store, tmp_path / "staging")
    assert list((tmp_path / "staging").iterdir()) == []


def test_the_sweep_empties_staging_and_nothing_else(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    (staging / "run-a" / "json").mkdir(parents=True)
    (staging / "run-a" / "json" / "env-vars.json").write_text("[]")
    (staging / "stray.tmp").write_text("x")
    outside = tmp_path / "keep"
    outside.mkdir()
    (staging / "link").symlink_to(outside, target_is_directory=True)
    assert rawstore.sweep_staging(staging) == 3
    assert list(staging.iterdir()) == []
    assert outside.is_dir()  # a link is removed, never followed
    assert rawstore.sweep_staging(tmp_path / "missing") == 0


def test_a_path_outside_the_bucket_is_refused(s3: tuple[S3RawStore, Stubber]) -> None:
    store, _ = s3
    with pytest.raises(RawRunError, match="not in this store's bucket"):
        store.open(f"s3://another-bucket/{PREFIX}")
    with pytest.raises(ValueError):
        store.open(f"s3://{LOCATION.bucket}/raw/prowler/aws/1/2026/10/02/not-a-uuid")
