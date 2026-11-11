"""Operate -> Reports (ADR-0047): queued by the API as argus_api, built by the worker as
argus_worker, served by the API from the reports store. Demo connections only on this store."""

import csv
import io
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError
from tests.api.conftest import PASSWORD, add_user, csrf
from tests.ingest.conftest import make_aws, make_demo, run_tool

from argus import reports
from argus.api.routes import reports as report_routes
from argus.collection import FilesystemRawStore
from argus.core.config import get_settings
from argus.reports import build as report_build
from argus.retention import run_retention
from argus.scheduling.worker import Worker

pytestmark = pytest.mark.db

DAY = date(2026, 10, 2)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "reports-root"
    path.mkdir()
    monkeypatch.setenv("ARGUS_REPORTS_ROOT", str(path))
    get_settings.cache_clear()
    return path


@pytest.fixture
def demo(owner: Engine, worker: Engine, store: FilesystemRawStore) -> int:
    target = make_demo(owner)
    for tool in ("steampipe", "prowler", "vulnerabilities"):
        run_tool(worker, store, target, tool, DAY)
    return target.connection_id


def _ask(client: TestClient, kind: str = "misconfigurations", **filters: Any) -> Any:
    return client.post(
        "/api/v1/reports", json={"kind": kind, "filters": filters}, headers=csrf(client)
    )


def _build(worker: Engine, root: Path, **options: Any) -> bool:
    return reports.build_pending(worker, store=reports.LocalReportStore(root), **options)


def _rows(body: bytes) -> list[dict[str, str]]:
    text_ = body.decode("utf-8")
    assert text_.startswith("﻿")
    return list(csv.DictReader(io.StringIO(text_.lstrip("﻿"))))


def _sign_in(client: TestClient, owner: Engine, username: str, role: str) -> TestClient:
    add_user(owner, username, role)
    other = TestClient(client.app, base_url="https://testserver")
    response = other.post("/api/v1/auth/sign-in", json={"username": username, "password": PASSWORD})
    assert response.status_code == 204
    return other


def _audited(owner: Engine) -> list[str]:
    with owner.connect() as conn:
        return list(
            conn.execute(
                text("SELECT action FROM audit_log WHERE action LIKE 'report.%' ORDER BY id")
            ).scalars()
        )


def test_a_report_is_queued_built_and_downloaded(
    signed_in: TestClient, owner: Engine, worker: Engine, root: Path, demo: int
) -> None:
    asked = _ask(signed_in, severity=["critical", "high"])
    assert asked.status_code == 202, asked.text
    report_id = asked.json()["id"]
    page = signed_in.get("/api/v1/reports").json()
    assert page["storage"] == "local" and page["expiry_days"] == 7
    assert page["items"][0]["status"] == "queued" and not page["items"][0]["downloadable"]

    assert _build(worker, root)
    assert not _build(worker, root)  # nothing else queued
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["status"] == "ready" and report["downloadable"] and not report["truncated"]
    assert report["data_through"] == {str(demo): DAY.isoformat()}
    listed = signed_in.get(
        "/api/v1/findings", params={"severity": ["critical", "high"], "limit": 1}
    ).json()
    assert report["row_count"] == listed["total"] > 0

    response = signed_in.get(f"/api/v1/reports/{report_id}/download")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert f"argus-misconfigurations-{report_id}.csv" in response.headers["content-disposition"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    rows = _rows(response.content)
    assert len(rows) == report["row_count"]
    assert {r["severity"] for r in rows} <= {"critical", "high"}
    assert {r["tool"] for r in rows} <= {"prowler", "cloudfox"}
    assert all(r["account_id"] and r["resource_name"] for r in rows)
    assert _audited(owner) == ["report.requested", "report.downloaded"]


def test_a_vulnerabilities_report_carries_the_cve_facts(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    report_id = _ask(signed_in, "vulnerabilities", exploitable=True).json()["id"]
    assert _build(worker, root)
    rows = _rows(signed_in.get(f"/api/v1/reports/{report_id}/download").content)
    assert rows and all(r["exploit_available"] == "yes" for r in rows)
    assert all(r["vulnerability_id"] and r["scanner"] == "aws-inspector" for r in rows)
    assert all(float(r["cvss"]) >= 0 for r in rows if r["cvss"])


def test_no_secret_value_reaches_a_report(
    signed_in: TestClient, owner: Engine, worker: Engine, root: Path, demo: int
) -> None:
    """A report exports list columns only; the result sentence is stored redacted, and a
    configuration or a tag is never exported."""
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE finding SET detail = 'password: ********' "
                "WHERE id = (SELECT min(id) FROM finding WHERE tool = 'prowler')"
            )
        )
    report_id = _ask(signed_in).json()["id"]
    assert _build(worker, root)
    body = signed_in.get(f"/api/v1/reports/{report_id}/download").content.decode()
    assert "password: ********" in body
    header = body.lstrip("﻿").split("\r\n", 1)[0].split(",")
    assert not {"tags", "config", "configuration", "user_data"} & set(header)


def test_a_real_aws_account_is_refused_on_this_store(
    signed_in: TestClient, owner: Engine, worker: Engine, root: Path, demo: int
) -> None:
    aws = make_aws(owner)
    refused = _ask(signed_in)  # every connection, so the AWS one too
    assert refused.status_code == 422
    assert refused.json()["detail"] == reports.queue.DEMO_ONLY
    assert _ask(signed_in, connection_id=[aws]).status_code == 422
    assert _ask(signed_in, connection_id=[demo]).status_code == 202
    assert _ask(signed_in, connection_id=[999999]).status_code == 422  # no account matches

    # And again at build: a row whose scope holds an AWS account (written as the owner, as no
    # API request can) fails without a file.
    with owner.begin() as conn:
        conn.execute(text("DELETE FROM report_request"))
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, "
                "requested_by) VALUES ('misconfigurations', 'csv', '{}', ARRAY[:a], 'admin')"
            ),
            {"a": aws},
        )
    assert _build(worker, root)
    with owner.connect() as conn:
        status, error = conn.execute(text("SELECT status, error FROM report_request")).one()
    assert status == "failed" and error == reports.queue.DEMO_ONLY
    assert not any((root / "reports").iterdir())


def test_an_install_without_a_reports_root_refuses_requests(
    signed_in: TestClient, monkeypatch: pytest.MonkeyPatch, demo: int
) -> None:
    monkeypatch.delenv("ARGUS_REPORTS_ROOT", raising=False)
    get_settings.cache_clear()
    refused = _ask(signed_in)
    assert refused.status_code == 422
    assert refused.json()["detail"] == report_routes.NOT_AVAILABLE
    assert signed_in.get("/api/v1/reports").json()["storage"] == "off"


def test_open_reports_are_capped_per_user(signed_in: TestClient, root: Path, demo: int) -> None:
    for _ in range(reports.MAX_OPEN_PER_USER):
        assert _ask(signed_in).status_code == 202
    refused = _ask(signed_in)
    assert refused.status_code == 422
    assert "being built" in refused.json()["detail"]


def test_an_operator_sees_their_own_and_an_admin_sees_all(
    signed_in: TestClient, owner: Engine, worker: Engine, root: Path, demo: int
) -> None:
    alice = _sign_in(signed_in, owner, "alice", "operator")
    bob = _sign_in(signed_in, owner, "bob", "operator")
    viewer = _sign_in(signed_in, owner, "vera", "viewer")
    report_id = _ask(alice).json()["id"]
    assert _build(worker, root)

    assert [r["id"] for r in alice.get("/api/v1/reports").json()["items"]] == [report_id]
    assert bob.get("/api/v1/reports").json()["items"] == []
    assert bob.get(f"/api/v1/reports/{report_id}").status_code == 404
    assert bob.get(f"/api/v1/reports/{report_id}/download").status_code == 404
    assert alice.get(f"/api/v1/reports/{report_id}/download").status_code == 200
    assert signed_in.get(f"/api/v1/reports/{report_id}/download").status_code == 200  # admin
    assert [r["requested_by"] for r in signed_in.get("/api/v1/reports").json()["items"]] == [
        "alice"
    ]
    for response in (viewer.get("/api/v1/reports"), _ask(viewer)):
        assert response.status_code == 403
    assert _audited(owner) == [
        "report.requested",
        "report.refused",
        "report.downloaded",
        "report.downloaded",
    ]


def test_an_expired_report_is_refused_and_retention_deletes_its_file(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    root: Path,
    demo: int,
    store: FilesystemRawStore,
) -> None:
    report_id = _ask(signed_in).json()["id"]
    assert _build(worker, root)
    with owner.begin() as conn:
        conn.execute(text("UPDATE report_request SET expires_at = now() - interval '1 second'"))
        key = conn.execute(text("SELECT storage_key FROM report_request")).scalar_one()
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["expired"] and not report["downloadable"]
    refused = signed_in.get(f"/api/v1/reports/{report_id}/download")
    assert refused.status_code == 410
    assert (root / key).is_file()

    result = run_retention(
        worker,
        store=store,
        today=DAY,
        retention_days=180,
        demo_raw_days=7,
        reports_store=reports.LocalReportStore(root),
    )
    assert result.report_files_deleted == 1
    assert not (root / key).exists()
    with owner.connect() as conn:
        assert conn.execute(text("SELECT file_deleted_at FROM report_request")).scalar_one()
    assert _audited(owner)[-1] == "report.refused"


def test_the_row_cap_cuts_the_file_and_says_so(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    report_id = _ask(signed_in).json()["id"]
    assert _build(worker, root, row_cap=2)
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["truncated"] and report["row_count"] == 2
    assert len(_rows(signed_in.get(f"/api/v1/reports/{report_id}/download").content)) == 2


def test_an_export_reads_one_state_while_findings_change(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    root: Path,
    demo: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Between two batches another transaction changes every finding and commits; the export
    still holds the state it started reading (REPEATABLE READ)."""
    monkeypatch.setattr(report_build, "BATCH", 1)
    names: Callable[..., dict[int, str]] = report_build.inventory.resource_names
    calls = 0

    def change_after_first_batch(conn: Connection, ids: list[int]) -> dict[int, str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            with owner.begin() as other:
                other.execute(text("UPDATE finding SET title = 'changed meanwhile'"))
        return names(conn, ids)

    monkeypatch.setattr(report_build.inventory, "resource_names", change_after_first_batch)
    report_id = _ask(signed_in).json()["id"]
    assert _build(worker, root)
    rows = _rows(signed_in.get(f"/api/v1/reports/{report_id}/download").content)
    assert calls > 1 and len(rows) > 1
    assert all(r["title"] != "changed meanwhile" for r in rows)


def test_the_download_gives_its_connection_back_before_the_file_streams(
    signed_in: TestClient,
    api_engine: Engine,
    worker: Engine,
    root: Path,
    demo: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_id = _ask(signed_in).json()["id"]
    assert _build(worker, root)
    checked_out: list[int] = []
    real = report_routes.FileResponse

    def recording(*args: Any, **kwargs: Any) -> Any:
        checked_out.append(api_engine.pool.checkedout())  # type: ignore[attr-defined]
        return real(*args, **kwargs)

    monkeypatch.setattr(report_routes, "FileResponse", recording)
    assert signed_in.get(f"/api/v1/reports/{report_id}/download").status_code == 200
    assert checked_out == [0]


def test_a_build_left_by_a_stopped_worker_fails(owner: Engine, worker: Engine) -> None:
    add_user(owner, "admin")
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, "
                "requested_by) VALUES ('misconfigurations', 'csv', '{}', ARRAY[1], 'admin')"
            )
        )
        conn.execute(text("UPDATE report_request SET status = 'building', started_at = now()"))
    with worker.begin() as conn:
        assert reports.fail_abandoned(conn) == 1
    with owner.connect() as conn:
        assert conn.execute(text("SELECT status FROM report_request")).scalar_one() == "failed"


def _fails(conn: Connection, statement: str, params: dict[str, Any] | None = None) -> str:
    savepoint = conn.begin_nested()
    with pytest.raises(DBAPIError) as exc:
        conn.execute(text(statement), params or {})
    savepoint.rollback()
    return str(exc.value.orig)


def test_the_api_cannot_finish_a_report_and_the_worker_cannot_change_a_request(
    owner: Engine, api_engine: Engine, worker: Engine
) -> None:
    user = add_user(owner, "alice", "operator")
    with api_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, "
                "requested_by_id, requested_by) "
                "VALUES ('misconfigurations', 'csv', '{}', ARRAY[1], :u, 'alice')"
            ),
            {"u": user},
        )
        assert "permission denied" in _fails(conn, "UPDATE report_request SET status = 'ready'")
        assert "permission denied" in _fails(
            conn,
            "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by, "
            "storage_key) VALUES ('misconfigurations', 'csv', '{}', ARRAY[1], 'x', "
            "'reports/1-" + "0" * 32 + ".csv')",
        )
        assert "permission denied" in _fails(conn, "DELETE FROM report_request")
    with worker.begin() as conn:
        for column, value in (
            ("connection_ids", "ARRAY[2]"),
            ("requested_by_id", "NULL"),
            ("filters", "'{}'"),
        ):
            assert "permission denied" in _fails(
                conn,
                f"UPDATE report_request SET {column} = {value}",  # noqa: S608
            )
    with owner.begin() as conn:
        assert "report_request_storage_key_check" in _fails(
            conn,
            "UPDATE report_request SET storage_key = 'reports/../../etc/passwd.csv'",
        )
    # Deleting a user (the API's grant) keeps their reports, unowned.
    with api_engine.begin() as conn:
        conn.execute(text("DELETE FROM app_user WHERE id = :u"), {"u": user})
    with owner.connect() as conn:
        owner_id, name = conn.execute(
            text("SELECT requested_by_id, requested_by FROM report_request")
        ).one()
    assert owner_id is None and name == "alice"


def test_a_worker_start_removes_every_file_no_report_names(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    root: Path,
    demo: int,
    store: FilesystemRawStore,
) -> None:
    """A build killed mid-write leaves its partial file, and one published just before a crash
    leaves a file no report names; the report thread's start removes both and keeps the rest."""
    kept_id = _ask(signed_in).json()["id"]
    assert _build(worker, root)
    _ask(signed_in)
    with owner.begin() as conn:
        kept = conn.execute(
            text("SELECT storage_key FROM report_request WHERE id = :i"), {"i": kept_id}
        ).scalar_one()
        conn.execute(
            text(
                "UPDATE report_request SET status = 'building', started_at = now() "
                "WHERE status = 'queued'"
            )
        )
    folder = root / "reports"
    partial = folder / f".2-{'a' * 32}.csv.part"
    orphan = folder / f"9-{'b' * 32}.csv"
    partial.write_text("half")
    orphan.write_text("never recorded")

    runner = Worker(worker, store=store, rules_dir=Path("."), threads=0)
    runner.stop.set()  # the start step only, then the loop ends
    runner._report_loop(reports.LocalReportStore(root))

    assert (root / kept).is_file()
    assert not partial.exists() and not orphan.exists()
    with owner.connect() as conn:
        statuses = sorted(conn.execute(text("SELECT status FROM report_request")).scalars())
    assert statuses == ["failed", "ready"]
    assert signed_in.get(f"/api/v1/reports/{kept_id}/download").status_code == 200
