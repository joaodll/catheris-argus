"""Test connection end to end (ADR-0024, amended 2026-10-07): the API queues as argus_api, the
worker answers as argus_worker, and AWS is replaced by fakes, so no test reaches a cloud."""

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError
from tests.api.conftest import csrf
from tests.ingest.conftest import make_aws, make_demo

from argus.core.aws import SessionCredentials
from argus.scheduling import connection_checks, maintenance
from argus.settings import write_topic

pytestmark = pytest.mark.db
ACCOUNT = "210987654321"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/ArgusScanner"


def _assumed(**_: object) -> SessionCredentials:
    return SessionCredentials("ASIA" + "F" * 16, "fake-secret-" + "f" * 30, "fake-token")


def _identity(account: str) -> Any:
    def answer(_credentials: object) -> tuple[str, str]:
        return account, f"arn:aws:sts::{account}:assumed-role/ArgusScanner/argus-test-1"

    return answer


def _result(client: TestClient, test_id: int) -> dict[str, Any]:
    response = client.get(f"/api/v1/connection-tests/{test_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def test_a_connection_that_reaches_its_account_passes(
    signed_in: TestClient, owner: Engine, worker: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    cid = make_aws(owner)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        "argus.collection.aws.access.aws.assume_role",
        lambda **kw: calls.append(kw) or _assumed(),
    )
    monkeypatch.setattr(connection_checks.aws, "caller_identity", _identity(ACCOUNT))

    assert signed_in.post(f"/api/v1/connections/{cid}/test").status_code == 403  # CSRF
    queued = signed_in.post(f"/api/v1/connections/{cid}/test", headers=csrf(signed_in))
    assert queued.status_code == 202, queued.text
    test_id = queued.json()["id"]
    again = signed_in.post(f"/api/v1/connections/{cid}/test", headers=csrf(signed_in))
    assert again.json()["id"] == test_id  # one open test per target
    assert _result(signed_in, test_id)["status"] == "queued"

    assert connection_checks.run_pending(worker) is True
    assert connection_checks.run_pending(worker) is False
    result = _result(signed_in, test_id)
    assert result["status"] == "passed", result
    assert result["message"] == f"Signed in to account {ACCOUNT} with the role."
    assert result["caller_arn"].startswith(f"arn:aws:sts::{ACCOUNT}:assumed-role/")
    assert calls[0]["role_arn"] == ROLE and calls[0]["external_id"] == "test-external-id-0001"
    with owner.connect() as conn:
        audited = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE action = 'connection.test'")
        ).scalar_one()
    assert audited == 1


def test_a_role_in_another_account_fails(
    signed_in: TestClient, owner: Engine, worker: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    cid = make_aws(owner)
    monkeypatch.setattr("argus.collection.aws.access.aws.assume_role", _assumed)
    monkeypatch.setattr(connection_checks.aws, "caller_identity", _identity("123456789012"))
    test_id = signed_in.post(f"/api/v1/connections/{cid}/test", headers=csrf(signed_in)).json()[
        "id"
    ]
    connection_checks.run_pending(worker)
    result = _result(signed_in, test_id)
    assert result["status"] == "failed"
    assert "not the connection's 210987654321" in result["message"]


def test_a_refused_role_fails_with_what_aws_said(
    signed_in: TestClient, owner: Engine, worker: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    cid = make_aws(owner)

    def refuse(**_: object) -> None:
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "not authorized to perform sts:AssumeRole",
                }
            },
            "AssumeRole",
        )

    monkeypatch.setattr("argus.collection.aws.access.aws.assume_role", refuse)
    test_id = signed_in.post(f"/api/v1/connections/{cid}/test", headers=csrf(signed_in)).json()[
        "id"
    ]
    connection_checks.run_pending(worker)
    result = _result(signed_in, test_id)
    assert result["status"] == "failed"
    assert result["message"] == (
        "Could not assume the role: AccessDenied: not authorized to perform sts:AssumeRole"
    )


def test_a_demo_connection_has_nothing_to_test(signed_in: TestClient, owner: Engine) -> None:
    demo = make_demo(owner)
    response = signed_in.post(
        f"/api/v1/connections/{demo.connection_id}/test", headers=csrf(signed_in)
    )
    assert response.status_code == 422
    missing = signed_in.post("/api/v1/connections/999999/test", headers=csrf(signed_in))
    assert missing.status_code == 404


class _Bucket:
    def __init__(self) -> None:
        self.keys: list[str] = []

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        self.keys.append(kwargs["Key"])
        return {"ServerSideEncryption": "AES256"}


def test_the_identity_signs_in_and_writes_to_each_raw_folder(
    signed_in: TestClient, owner: Engine, worker: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    bucket = _Bucket()
    monkeypatch.setattr(connection_checks.aws, "caller_identity", _identity(ACCOUNT))
    monkeypatch.setattr(connection_checks.aws, "s3_client", lambda **_: bucket)
    queued = signed_in.post("/api/v1/settings/identity/test", headers=csrf(signed_in))
    connection_checks.run_pending(worker)
    first = _result(signed_in, queued.json()["id"])
    assert first["status"] == "passed"
    assert "No raw output bucket is set" in first["message"] and bucket.keys == []

    with owner.begin() as conn:
        write_topic(
            conn,
            topic="raw_storage",
            values={"bucket": "argus-raw-example", "region": "eu-west-1"},
            actor="admin",
        )
    queued = signed_in.post("/api/v1/settings/identity/test", headers=csrf(signed_in))
    connection_checks.run_pending(worker)
    second = _result(signed_in, queued.json()["id"])
    assert second["status"] == "passed"
    assert sorted(bucket.keys) == [
        f"raw/{tool}/{connection_checks.MARKER}"
        for tool in ("cloudfox", "prowler", "steampipe", "vulnerabilities")
    ]
    assert "encryption: AES256; SSE-KMS is recommended" in second["message"]


def test_a_test_the_worker_never_finished_fails(
    signed_in: TestClient, owner: Engine, worker: Engine
) -> None:
    test_id = signed_in.post("/api/v1/settings/identity/test", headers=csrf(signed_in)).json()["id"]
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE connection_test SET requested_at = now() - interval '3 minutes' "
                "WHERE id = :i"
            ),
            {"i": test_id},
        )
    maintenance.maintain(worker, now=datetime.now(UTC))  # expires it
    assert connection_checks.run_pending(worker) is False  # expired, not run
    result = _result(signed_in, test_id)
    assert result["status"] == "failed" and "did not finish" in result["message"]


def test_the_api_cannot_record_a_result(api_engine: Engine) -> None:
    """Only the worker writes a result: the API role may insert a request, nothing more."""
    with api_engine.connect() as conn, pytest.raises(ProgrammingError):
        conn.execute(
            text(
                "INSERT INTO connection_test (target, requested_by, status, finished_at) "
                "VALUES ('identity', 'x', 'passed', now())"
            )
        )
