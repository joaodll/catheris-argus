"""Operate -> Reports (ADR-0047): queued by the API as argus_api, built by the worker as
argus_worker, served by the API from the reports store. Demo connections only on this store."""

import csv
import gzip
import io
import json
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


RESOURCE_COLUMNS = [
    "account_id",
    "account",
    "region",
    "resource_type",
    "resource_name",
    "native_id",
    "resource_uid",
    "first_seen",
    "last_seen",
    "removed_on",
    "open_misconfigurations",
    "worst_severity",
    "open_vulnerabilities",
    "exploitable_vulnerabilities",
    "last_used",
    "last_used_region",
    "last_used_read_on",
    "role_created",
    "workloads",
]


def _listed(client: TestClient, **filters: Any) -> dict[str, dict[str, Any]]:
    """Every resource the Resources list shows for these filters, by uid."""
    out: dict[str, dict[str, Any]] = {}
    offset = 0
    while True:
        page = client.get(
            "/api/v1/resources", params={**filters, "limit": 200, "offset": offset}
        ).json()
        out.update({r["resource_uid"]: r for r in page["items"]})
        offset += 200
        if offset >= page["total"]:
            return out


def test_a_resources_report_is_the_list_with_its_columns(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    """Export on Resources (round 2, 2026-11-17): the file holds the rows the list shows for
    the same filters, each with the list's counts and a role's use."""
    asked = _ask(signed_in, "resources", type=["aws_iam_role", "aws_lambda_function"])
    assert asked.status_code == 202, asked.text
    assert _build(worker, root)
    report = signed_in.get(f"/api/v1/reports/{asked.json()['id']}").json()
    assert report["status"] == "ready", report["error"]
    assert report["kind"] == "resources" and report["data_through"] == {str(demo): DAY.isoformat()}
    body = signed_in.get(f"/api/v1/reports/{report['id']}/download").content
    header = body.decode().lstrip("\ufeff").split("\r\n", 1)[0].split(",")
    assert header == RESOURCE_COLUMNS
    rows = {r["resource_uid"]: r for r in _rows(body)}
    listed = _listed(signed_in, type=["aws_iam_role", "aws_lambda_function"])
    assert rows.keys() == listed.keys() and report["row_count"] == len(rows) > 0

    for uid, row in rows.items():
        item = listed[uid]
        assert row["account_id"] and row["account"] and row["region"] == item["region"]
        assert int(row["open_misconfigurations"]) == item["open_findings"]
        assert (row["worst_severity"] or None) == item["worst_severity"]
        cell = item["vulnerabilities"]
        assert row["open_vulnerabilities"] == (str(cell["open"]) if cell else "")
        role = item["role_use"]
        if item["type"] == "aws_iam_role":
            assert role is not None
            assert row["last_used_read_on"] == (role["observed_on"] or "")
            assert row["workloads"] == ("" if role["workloads"] is None else str(role["workloads"]))
        else:
            assert role is None and not (row["last_used_read_on"] or row["workloads"])
    roles = [r for r in rows.values() if r["resource_type"] == "aws_iam_role"]
    assert any(r["last_used"] for r in roles) and all(r["last_used_read_on"] for r in roles)
    # A Lambda function is scanned for CVEs on the Demo estate: its cell is a number, never blank.
    assert all(
        r["open_vulnerabilities"] for r in rows.values() if r["resource_type"] != "aws_iam_role"
    )


def test_a_resources_report_keeps_the_lists_role_filters(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    filters = {"type": ["aws_iam_role"], "role_unused": "90", "no_workload": True}
    report_id = _ask(signed_in, "resources", **filters).json()["id"]
    assert _build(worker, root)
    rows = _rows(signed_in.get(f"/api/v1/reports/{report_id}/download").content)
    assert {r["resource_uid"] for r in rows} == set(_listed(signed_in, **filters))
    assert all(r["workloads"] == "0" for r in rows)


@pytest.mark.parametrize(
    "case",
    [
        ("resources", "pdf", "report_request_resources_format"),
        ("misconfigurations", "jsonl", "report_request_jsonl_resources"),
        ("vulnerabilities", "jsonl", "report_request_jsonl_resources"),
    ],
    ids=["resources-pdf", "misconfigurations-jsonl", "vulnerabilities-jsonl"],
)
def test_a_report_comes_only_in_its_kinds_formats(
    signed_in: TestClient, owner: Engine, root: Path, demo: int, case: tuple[str, str, str]
) -> None:
    """Resources: a CSV or JSON Lines; the finding kinds: a CSV or a PDF (migrations 0054,
    0056). The API refuses the others, and the table does whatever writes the row."""
    kind, fmt, constraint = case
    refused = signed_in.post(
        "/api/v1/reports",
        json={"kind": kind, "format": fmt, "filters": {}},
        headers=csrf(signed_in),
    )
    assert refused.status_code == 422
    with owner.begin() as conn, pytest.raises(DBAPIError, match=constraint):
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, "
                "requested_by) VALUES (:k, :f, '{}', ARRAY[:c], 'admin')"
            ),
            {"k": kind, "f": fmt, "c": demo},
        )


def _ask_jsonl(client: TestClient, **filters: Any) -> Any:
    return client.post(
        "/api/v1/reports",
        json={"kind": "resources", "format": "jsonl", "filters": filters},
        headers=csrf(client),
    )


def _lines(client: TestClient, report_id: int) -> list[dict[str, Any]]:
    response = client.get(f"/api/v1/reports/{report_id}/download")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/gzip"
    assert (
        f'filename="argus-resources-{report_id}.jsonl.gz"'
        in response.headers["content-disposition"]
    )
    return [json.loads(line) for line in gzip.decompress(response.content).splitlines()]


def test_a_resources_jsonl_report_is_each_panel_with_its_links_and_configuration(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    """The owner's ask (2026-11-19): what a resource's panel shows, in one file. Each matched
    line is a listed resource with the CSV's fields, its panel's links (same ends, same
    directions) and its configuration."""
    filters = {"type": ["aws_ec2_instance", "aws_iam_role", "aws_route53_record"]}
    asked = _ask_jsonl(signed_in, **filters)
    assert asked.status_code == 202, asked.text
    assert _build(worker, root)
    report = signed_in.get(f"/api/v1/reports/{asked.json()['id']}").json()
    assert report["status"] == "ready", report["error"]
    assert report["format"] == "jsonl"
    lines = _lines(signed_in, report["id"])
    assert report["row_count"] == len(lines)
    matched = {line["resource_uid"]: line for line in lines if line["included"] == "matched"}
    listed = _listed(signed_in, **filters)
    assert matched.keys() == listed.keys() and matched
    assert set(RESOURCE_COLUMNS) <= set(lines[0]) and {"links", "config"} <= set(lines[0])

    linked_some = False
    for uid, line in matched.items():
        panel = signed_in.get(f"/api/v1/resources/{listed[uid]['id']}").json()
        assert line["config"] == panel["config"]
        assert line["open_misconfigurations"] == listed[uid]["open_findings"]
        expected = sorted(
            (e["type"], e["target_uid"] if e["source_uid"] == uid else e["source_uid"])
            for e in panel["edges"]
        )
        assert sorted((link["type"], link["other_uid"]) for link in line["links"]) == expected
        for link in line["links"]:
            assert link["direction"] in {"out", "in"}
            linked_some = linked_some or link["other_name"] is not None
    assert linked_some  # the Demo estate links instances, roles and records to other resources


def test_a_linked_resource_gets_its_own_line_once_and_only_in_the_reports_accounts(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    """The config of the links too (owner, 2026-11-19): a resource one link away that the
    filters left out gets its own line, once, marked linked, with its own configuration."""
    asked = _ask_jsonl(signed_in, type=["aws_ec2_instance"])
    assert _build(worker, root)
    lines = _lines(signed_in, asked.json()["id"])
    matched = [line for line in lines if line["included"] == "matched"]
    linked = [line for line in lines if line["included"] == "linked"]
    assert linked, "an instance links to its security groups, subnet and role"
    uids = [line["resource_uid"] for line in lines]
    assert len(uids) == len(set(uids))  # each resource once
    assert all(line["resource_type"] != "aws_ec2_instance" for line in linked)
    ends = {link["other_uid"] for line in matched for link in line["links"]}
    assert {line["resource_uid"] for line in linked} <= ends
    accounts = {line["account_id"] for line in matched}
    assert {line["account_id"] for line in linked} <= accounts
    assert any(line["config"] for line in linked)


def test_another_accounts_resource_is_named_in_a_link_never_exported(
    signed_in: TestClient, owner: Engine, worker: Engine, root: Path, demo: int
) -> None:
    """A report holds its accounts' data only: a link to another account's resource names it,
    and that resource gets no line (on this store, also: a real account's configuration never
    stays on a local disk, ADR-0032)."""
    other = make_demo(owner, seed=1)
    with owner.begin() as conn:
        src = conn.execute(
            text(
                "SELECT id, resource_uid FROM resource WHERE connection_id = :c "
                "AND type = 'aws_ec2_instance' ORDER BY id LIMIT 1"
            ),
            {"c": demo},
        ).one()
        conn.execute(
            text("""
            INSERT INTO resource (resource_uid, connection_id, region, type, native_id, name,
                                  first_seen, last_seen)
            VALUES ('arn:aws:iam::999999999999:role/elsewhere', :c, 'global', 'aws_iam_role',
                    'elsewhere', 'elsewhere', :d, :d)
        """),
            {"c": other.connection_id, "d": DAY},
        )
        conn.execute(
            text("""
            INSERT INTO edge (edge_key, source_uid, target_uid, source_resource_id,
                              target_resource_id, type, origin, first_seen, last_seen, author,
                              reason)
            SELECT sha256('report-test'::bytea), :s, r.resource_uid, :sid, r.id, 'CAN_ASSUME',
                   'manual', :d, :d, 'admin', 'test'
            FROM resource r WHERE r.resource_uid = 'arn:aws:iam::999999999999:role/elsewhere'
        """),
            {"s": src.resource_uid, "sid": src.id, "d": DAY},
        )
    asked = _ask_jsonl(signed_in, type=["aws_ec2_instance"], connection_id=[demo])
    assert asked.status_code == 202, asked.text
    assert _build(worker, root)
    lines = _lines(signed_in, asked.json()["id"])
    (source,) = [line for line in lines if line["resource_uid"] == src.resource_uid]
    (named,) = [
        link
        for link in source["links"]
        if link["other_uid"] == "arn:aws:iam::999999999999:role/elsewhere"
    ]
    assert named["other_name"] == "elsewhere" and named["direction"] == "out"
    assert "arn:aws:iam::999999999999:role/elsewhere" not in {
        line["resource_uid"] for line in lines
    }


def test_a_jsonl_report_past_its_cap_is_cut_and_says_so(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    asked = _ask_jsonl(signed_in)
    assert _build(worker, root, row_cap=5)
    report = signed_in.get(f"/api/v1/reports/{asked.json()['id']}").json()
    assert report["status"] == "ready" and report["truncated"] is True
    assert report["row_count"] == 5 == len(_lines(signed_in, report["id"]))


def test_the_report_role_builds_a_resources_report_through_every_filter(
    signed_in: TestClient, reports_role: Engine, root: Path, demo: int
) -> None:
    """argus_reports (the Kubernetes report Job, migrations 0054 and 0056) reads everything a
    Resources report reads: every filter's set, each row's columns, and in JSON Lines the
    configurations and links."""
    every_filter = {
        "vulnerabilities": "any",
        "misconfigurations": "any",
        "internet": True,
        "role_unused": "365",
        "no_workload": True,
        "q": "a",
        "assets": True,
        "include_deleted": True,
        "first_seen_from": "2020-01-01",
        "deleted_to": "2030-01-01",
    }
    for filters in (every_filter, {}):
        report_id = _ask(signed_in, "resources", **filters).json()["id"]
        assert _build(reports_role, root)
        report = signed_in.get(f"/api/v1/reports/{report_id}").json()
        assert report["status"] == "ready", report["error"]
    assert report["row_count"] == len(_listed(signed_in)) > 0
    # And a JSON Lines file with links and configuration (migration 0056), linked lines too.
    report_id = _ask_jsonl(signed_in, type=["aws_ec2_instance"]).json()["id"]
    assert _build(reports_role, root)
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["status"] == "ready", report["error"]
    lines = _lines(signed_in, report_id)
    assert any(line["included"] == "linked" for line in lines)
    assert any(line["config"] for line in lines) and any(line["links"] for line in lines)


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
    assert refused.json()["detail"] == report_routes.UNAVAILABLE["off"]
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
    real = report_routes.StreamingResponse

    def recording(*args: Any, **kwargs: Any) -> Any:
        checked_out.append(api_engine.pool.checkedout())  # type: ignore[attr-defined]
        return real(*args, **kwargs)

    monkeypatch.setattr(report_routes, "StreamingResponse", recording)
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
