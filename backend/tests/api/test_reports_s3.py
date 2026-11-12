"""Reports on Kubernetes (ADR-0047 round 5): the report Job builds as argus_reports into the
reports/ folder of the bucket recorded on the report, in one PUT; the API reads it back with its
own role, and serves it only when it is the file the build recorded. S3 is stubbed (botocore's
Stubber): the requests are checked, nothing leaves the test. IRSA and KMS are not run here."""

import base64
import hashlib
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import ANY, Stubber
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError
from tests.api.conftest import csrf
from tests.ingest.conftest import make_aws, make_demo, run_tool

from argus import reports
from argus.api.routes import reports as report_routes
from argus.collection import FilesystemRawStore
from argus.core import aws
from argus.core.config import get_settings
from argus.reports import s3 as report_s3
from argus.reports import store as report_store
from argus.reports.model import STALE_AFTER_SECONDS, STALE_ERROR
from argus.scheduling import job
from argus.settings import write_topic

pytestmark = pytest.mark.db

DAY = date(2026, 10, 2)
BUCKET = "argus-raw-example"
REGION = "eu-west-1"
KEY = "reports/7-" + "a" * 32 + ".csv"


def _client() -> Any:
    return boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    ).client("s3")


def _b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


class _Body:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.closed = False

    def read(self, amount: int) -> bytes:
        chunk, self.data = self.data[:amount], self.data[amount:]
        return chunk

    def close(self) -> None:
        self.closed = True


def _get(stubber: Stubber, data: bytes, *, checksum: str | None = None, key: str = KEY) -> _Body:
    body = _Body(data)
    stubber.add_response(
        "get_object",
        {"Body": body, "ContentLength": len(data), "ChecksumSHA256": checksum or _b64(data)},
        {"Bucket": BUCKET, "Key": key, "ChecksumMode": "ENABLED"},
    )
    return body


# --- The S3 store, alone -------------------------------------------------------------------


def test_a_report_goes_up_in_one_put_with_its_sha256(tmp_path: Path) -> None:
    client = _client()
    store = report_store.S3ReportStore(client, BUCKET, tmp_path)
    temp = store.temp_path(KEY)
    temp.write_bytes(b"a,b\n1,2\n")
    digest = hashlib.sha256(b"a,b\n1,2\n").hexdigest()
    with Stubber(client) as stubber:
        stubber.add_response(
            "put_object",
            {},
            {
                "Bucket": BUCKET,
                "Key": KEY,
                "Body": ANY,
                "ContentLength": 8,
                "ContentType": "text/csv; charset=utf-8",
                "ChecksumSHA256": _b64(b"a,b\n1,2\n"),
            },
        )
        store.publish(temp, KEY, sha256=digest)
        stubber.assert_no_pending_responses()
    assert not temp.exists()
    assert temp.parent == tmp_path and oct(tmp_path.stat().st_mode & 0o777) == "0o700"


def test_an_upload_refused_by_s3_leaves_nothing_behind(tmp_path: Path) -> None:
    client = _client()
    store = report_store.S3ReportStore(client, BUCKET, tmp_path)
    temp = store.temp_path(KEY)
    temp.write_bytes(b"x")
    with Stubber(client) as stubber:
        stubber.add_client_error("put_object", "AccessDenied", http_status_code=403)
        with pytest.raises(reports.ReportStoreUnavailableError, match="AccessDenied"):
            store.publish(temp, KEY, sha256=hashlib.sha256(b"x").hexdigest())
    assert not temp.exists()


def test_a_file_over_the_cap_is_never_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(report_store, "MAX_REPORT_BYTES", 4)
    client = _client()
    store = report_store.S3ReportStore(client, BUCKET, tmp_path)
    temp = store.temp_path(KEY)
    temp.write_bytes(b"12345")
    with Stubber(client), pytest.raises(reports.ReportStoreError, match="cap"):
        store.publish(temp, KEY, sha256="0" * 64)  # the Stubber fails any call it did not expect


def test_a_download_is_the_recorded_file_or_nothing() -> None:
    data = b"col\n" * 1000
    digest = hashlib.sha256(data).hexdigest()
    client = _client()
    store = report_store.S3ReportStore(client, BUCKET)
    with Stubber(client) as stubber:
        _get(stubber, data)
        assert b"".join(store.open(KEY, size_bytes=len(data), sha256=digest)) == data
        # Another file under the same key: refused before any byte, and the body is closed.
        body = _get(stubber, b"other", checksum=_b64(b"other"))
        with pytest.raises(reports.ReportFileChangedError):
            store.open(KEY, size_bytes=5, sha256=digest)
        assert body.closed
        body = _get(stubber, data)
        with pytest.raises(reports.ReportFileChangedError):
            store.open(KEY, size_bytes=len(data) + 1, sha256=digest)
        assert body.closed
        stubber.add_client_error("get_object", "NoSuchKey", http_status_code=404)
        with pytest.raises(reports.ReportStoreError) as missing:
            store.open(KEY, size_bytes=1, sha256=digest)
        assert not isinstance(missing.value, reports.ReportFileChangedError)
        stubber.add_client_error("get_object", "AccessDenied", http_status_code=403)
        with pytest.raises(reports.ReportStoreUnavailableError):
            store.open(KEY, size_bytes=1, sha256=digest)


@pytest.mark.parametrize(
    "key",
    ["raw/prowler/aws/1/x.json.gz", "reports/../raw/x.csv", "reports/7-abc.csv", "reports/7.exe"],
    ids=["raw-output", "dot-dot", "short", "extension"],
)
def test_only_a_report_key_is_ever_asked_for(key: str, tmp_path: Path) -> None:
    client = _client()
    store = report_store.S3ReportStore(client, BUCKET, tmp_path)
    with Stubber(client):  # any call would fail the test
        with pytest.raises(reports.ReportStoreError):
            store.open(key, size_bytes=1, sha256="0" * 64)
        with pytest.raises(reports.ReportStoreError):
            store.temp_path(key)


def test_argus_never_deletes_from_the_bucket() -> None:
    client = _client()
    with Stubber(client):
        assert report_store.S3ReportStore(client, BUCKET).delete(KEY) is False


def test_the_local_store_serves_only_the_recorded_size(tmp_path: Path) -> None:
    local = reports.LocalReportStore(tmp_path)
    temp = local.temp_path(KEY)
    temp.write_bytes(b"abc")
    local.publish(temp, KEY, sha256=hashlib.sha256(b"abc").hexdigest())
    assert b"".join(local.open(KEY, size_bytes=3, sha256="")) == b"abc"
    with pytest.raises(reports.ReportFileChangedError):
        local.open(KEY, size_bytes=4, sha256="")
    local.delete(KEY)
    with pytest.raises(reports.ReportStoreError):
        local.open(KEY, size_bytes=3, sha256="")


# --- The reports client: web identity only -------------------------------------------------


def test_a_pod_without_irsa_gets_no_reports_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Never the default chain: a key in the environment or the node's role is not used."""
    aws.web_identity_s3_client.cache_clear()
    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEEXAMPLE00")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x" * 40)
    with pytest.raises(aws.NoWebIdentityError):
        aws.web_identity_s3_client(REGION)
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::111111111111:role/argus-api")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(tmp_path / "missing"))
    assert not aws.web_identity_available()
    token = tmp_path / "token"
    token.write_text("not-a-real-token")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token))
    assert aws.web_identity_available()
    client = aws.web_identity_s3_client(REGION)
    credentials = client._request_signer._credentials  # no STS call yet
    assert credentials.method == aws.WEB_IDENTITY_METHOD
    aws.web_identity_s3_client.cache_clear()


# --- Through the API and the report Job ----------------------------------------------------


@pytest.fixture
def s3_install(
    monkeypatch: pytest.MonkeyPatch, owner: Engine, tmp_path: Path
) -> Iterator[tuple[Any, Stubber]]:
    """A Kubernetes install with IRSA: reports in S3, the bucket set in Raw output storage."""
    monkeypatch.delenv("ARGUS_REPORTS_ROOT", raising=False)
    monkeypatch.setenv("ARGUS_REPORTS_STORE", "s3")
    get_settings.cache_clear()
    client = _client()
    monkeypatch.setattr(report_routes, "web_identity_available", lambda: True)
    monkeypatch.setattr(report_routes, "web_identity_s3_client", lambda _region: client)
    monkeypatch.setattr(report_s3, "web_identity_s3_client", lambda _region: client)
    with owner.begin() as conn:
        write_topic(
            conn, topic="raw_storage", values={"bucket": BUCKET, "region": REGION}, actor="t"
        )
    with Stubber(client) as stubber:
        yield client, stubber
    get_settings.cache_clear()


def _ask(client: TestClient, kind: str = "misconfigurations", **filters: Any) -> Any:
    return client.post(
        "/api/v1/reports", json={"kind": kind, "filters": filters}, headers=csrf(client)
    )


def test_on_s3_a_real_aws_account_may_be_reported_and_the_bucket_is_recorded(
    signed_in: TestClient, owner: Engine, s3_install: tuple[Any, Stubber]
) -> None:
    make_aws(owner)
    assert signed_in.get("/api/v1/reports").json()["storage"] == "s3"
    asked = _ask(signed_in)
    assert asked.status_code == 202, asked.text
    with owner.connect() as conn:
        bucket, region = conn.execute(
            text("SELECT storage_bucket, storage_region FROM report_request")
        ).one()
    assert (bucket, region) == (BUCKET, REGION)


def test_on_s3_the_screen_says_why_a_report_cannot_be_asked_for(
    signed_in: TestClient,
    owner: Engine,
    s3_install: tuple[Any, Stubber],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_aws(owner)
    with owner.begin() as conn:
        write_topic(conn, topic="raw_storage", values={}, actor="t")
    assert signed_in.get("/api/v1/reports").json()["storage"] == "no_bucket"
    assert _ask(signed_in).json()["detail"] == report_routes.UNAVAILABLE["no_bucket"]
    monkeypatch.setattr(report_routes, "web_identity_available", lambda: False)
    assert signed_in.get("/api/v1/reports").json()["storage"] == "no_identity"
    assert _ask(signed_in).json()["detail"] == report_routes.UNAVAILABLE["no_identity"]


@pytest.fixture
def scanned(owner: Engine, worker: Engine, store: FilesystemRawStore) -> int:
    """A Demo connection with findings (on S3 any connection may be reported on)."""
    target = make_demo(owner)
    for tool in ("steampipe", "prowler"):
        run_tool(worker, store, target, tool, DAY)
    return target.connection_id


@pytest.mark.usefixtures("scanned")
def test_the_report_job_builds_into_s3_and_the_api_serves_the_same_file(
    signed_in: TestClient,
    owner: Engine,
    api_engine: Engine,
    reports_role: Engine,
    s3_install: tuple[Any, Stubber],
    tmp_path: Path,
) -> None:
    """Built as argus_reports: its grants are enough for a whole report."""
    report_id = _ask(signed_in).json()["id"]
    client, stubber = s3_install
    sent: dict[str, Any] = {}

    def put_object(**params: Any) -> dict[str, Any]:  # what S3 would receive
        sent.update(params, data=params["Body"].read())
        return {}

    client.put_object = put_object
    done = job.run_job(
        reports_role,
        work=job.REPORT,
        store=FilesystemRawStore(tmp_path / "raw"),
        rules_dir=Path("/nonexistent"),
        worker_id="pod-1",
        max_runs=1,
        scratch=tmp_path / "scratch",
    )
    assert done == "report"
    data: bytes = sent["data"]
    assert sent["ChecksumSHA256"] == _b64(data) and sent["ContentLength"] == len(data)
    assert sent["Key"].startswith(f"reports/{report_id}-")
    assert not any((tmp_path / "scratch").iterdir())  # nothing stays in the pod
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["status"] == "ready" and report["size_bytes"] == len(data)

    _get(stubber, data, key=sent["Key"])
    # S3 is asked with no pooled connection held: a slow or unreachable store never holds a slot.
    held: list[int] = []
    real_get = client.get_object

    def get_object(**params: Any) -> Any:
        held.append(api_engine.pool.checkedout())  # type: ignore[attr-defined]
        return real_get(**params)

    client.get_object = get_object
    got = signed_in.get(f"/api/v1/reports/{report_id}/download")
    assert held == [0]
    assert got.status_code == 200 and got.content == data
    assert got.headers["cache-control"] == "no-store"
    assert "attachment" in got.headers["content-disposition"]

    _get(stubber, b"planted", key=sent["Key"])
    refused = signed_in.get(f"/api/v1/reports/{report_id}/download")
    assert refused.status_code == 410
    with owner.connect() as conn:
        reasons = conn.execute(
            text(
                "SELECT action, detail->>'reason' FROM audit_log "
                "WHERE action LIKE 'report.%' ORDER BY id"
            )
        ).all()
    assert [tuple(r) for r in reasons][-2:] == [
        ("report.downloaded", None),
        ("report.refused", "file_changed"),
    ]


def test_a_report_requested_for_the_local_store_is_failed_by_a_report_job(
    owner: Engine, reports_role: Engine, tmp_path: Path
) -> None:
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by) "
                "VALUES ('misconfigurations', 'csv', '{}', ARRAY[1], 'alice')"
            )
        )
    built = reports.build_pending(reports_role, store_for=report_s3.s3_store_for(tmp_path))
    assert built
    with owner.connect() as conn:
        status, error = conn.execute(text("SELECT status, error FROM report_request")).one()
    assert status == "failed" and error == report_s3.NOT_ON_S3


# --- Abandoned builds ----------------------------------------------------------------------


def test_an_abandoned_build_shows_failed_frees_its_slot_and_a_job_ends_it(
    signed_in: TestClient, owner: Engine, reports_role: Engine, s3_install: tuple[Any, Stubber]
) -> None:
    make_aws(owner)
    report_id = _ask(signed_in).json()["id"]
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE report_request SET status = 'building', "
                "started_at = now() - make_interval(secs => :s) WHERE id = :i"
            ),
            {"s": STALE_AFTER_SECONDS + 1, "i": report_id},
        )
    shown = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert shown["status"] == "failed" and shown["error"] == STALE_ERROR
    for _ in range(reports.MAX_OPEN_PER_USER):  # the abandoned one is not open any more
        assert _ask(signed_in).status_code == 202
    with reports_role.begin() as conn:
        assert reports.fail_stale(conn) == 1
    with owner.connect() as conn:
        assert (
            conn.execute(
                text("SELECT status FROM report_request WHERE id = :i"), {"i": report_id}
            ).scalar_one()
            == "failed"
        )


def test_a_build_in_progress_is_not_abandoned(owner: Engine, reports_role: Engine) -> None:
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by, "
                "status, started_at) VALUES ('misconfigurations', 'csv', '{}', ARRAY[1], 'a', "
                "'building', now() - interval '50 minutes')"
            )
        )
    with reports_role.begin() as conn:
        assert reports.fail_stale(conn) == 0


# --- What each role may do -----------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT secret_ciphertext FROM connection",
        "SELECT external_id FROM connection",
        "SELECT value FROM platform_setting",
        "SELECT count(*) FROM audit_log",
        "SELECT count(*) FROM app_user",
        "SELECT config_id FROM resource",
        "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by) "
        "VALUES ('misconfigurations', 'csv', '{}', ARRAY[1], 'x')",
        "UPDATE report_request SET connection_ids = ARRAY[2]",
        "UPDATE report_request SET storage_bucket = 'elsewhere'",
        "DELETE FROM report_request",
        "UPDATE finding SET title = title",
    ],
    ids=[
        "sealed-secret",
        "external-id",
        "settings",
        "audit",
        "users",
        "configuration",
        "request",
        "scope",
        "bucket",
        "delete",
        "findings",
    ],
)
def test_the_report_role_reads_only_what_a_report_reads(
    reports_role: Engine, statement: str
) -> None:
    with reports_role.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(text(statement))


def test_a_report_job_refuses_to_start_without_the_renderer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reports, "renderer_present", lambda: False)
    with pytest.raises(job.WorkError, match="PDF renderer"):
        job.check_work(job.REPORT)
