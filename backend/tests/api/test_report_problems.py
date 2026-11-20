"""The by-resource report, "Misconfigurations and vulnerabilities" (ADR-0047 section 3d): the
Resources list's filters choose the resources; each one's open misconfigurations and open CVEs
are its problems, counted as the Resources list counts them."""

import csv
import io
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from tests.api.conftest import csrf
from tests.ingest.conftest import make_demo, run_tool

from argus import findings, reports
from argus.collection import FilesystemRawStore
from argus.core.config import get_settings
from argus.findings import ResourceListFilters
from argus.reports import filters as report_filters
from argus.reports import pdf, problems
from argus.reports.filters import ResourceProblemFilters

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
    for tool in ("steampipe", "prowler", "cloudfox", "vulnerabilities"):
        run_tool(worker, store, target, tool, DAY)
    return target.connection_id


@pytest.fixture
def rendered(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []

    def fake(context: dict[str, Any]) -> bytes:
        contexts.append(json.loads(json.dumps(context)))  # what really crosses: JSON
        return b"%PDF-1.7\n% stub\n"

    monkeypatch.setattr(pdf, "render", fake)
    return contexts


def _ask(client: TestClient, fmt: str = "pdf", **filters: Any) -> Any:
    return client.post(
        "/api/v1/reports",
        json={"kind": "resource-problems", "format": fmt, "filters": filters},
        headers=csrf(client),
    )


def _build(engine: Engine, root: Path) -> bool:
    return reports.build_pending(engine, store=reports.LocalReportStore(root))


def _expected(worker: Engine, demo: int) -> dict[int, int]:
    """Each resource's open problems as the Resources list counts them: its open
    misconfigurations plus its open CVEs."""
    with worker.connect() as conn:
        ids = [
            r[0]
            for r in conn.execute(
                text("SELECT id FROM resource WHERE connection_id = :c AND deleted_on IS NULL"),
                {"c": demo},
            )
        ]
        misconfigured = findings.open_finding_counts(conn, ids)
        vulnerable = findings.vulnerability_counts(conn, ids)
    out = {}
    for rid in ids:
        n = misconfigured.get(rid, (0, None))[0] + (
            vulnerable[rid].open if rid in vulnerable else 0
        )
        if n:
            out[rid] = n
    return out


def test_a_pdf_lists_each_resource_with_its_misconfigurations_and_cves(
    signed_in: TestClient,
    worker: Engine,
    root: Path,
    demo: int,
    rendered: list[dict[str, Any]],
) -> None:
    report_id = _ask(signed_in).json()["id"]
    assert _build(worker, root)
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["kind"] == "resource-problems" and report["status"] == "ready", report
    expected = _expected(worker, demo)
    (context,) = rendered
    assert context["kind"] == "resource-problems"
    assert context["resources"] == len(expected) > 0
    assert context["total"] == sum(expected.values()) == report["row_count"]
    sources = context["by_source"]
    assert sum(sources["misconfiguration"]) > 0 and sum(sources["vulnerability"]) > 0
    assert sum(sources["misconfiguration"]) + sum(sources["vulnerability"]) == context["total"]
    # By resource type (owner, 2026-11-20): the inventory's types, split by source, worst first.
    by_type = context["by_type"]
    assert "worst" not in context and by_type
    assert sum(t["total"] for t in by_type) == context["total"] or context["more_types"]
    for t in by_type:
        assert t["misconfigurations"] + t["vulnerabilities"] == t["total"] == sum(t["counts"])
        assert t["words"] == pdf.type_words(t["type"]) and t["type"].startswith("aws_")
    assert sum(t["resources"] for t in by_type) == context["resources"] or context["more_types"]

    blocks = context["blocks"]
    assert blocks and len(blocks) == min(len(expected), reports.model.PDF_RESOURCE_BLOCKS)
    ranks = [
        tuple(
            -sum(c["count"] for side in b["chips"].values() for c in side if c["severity"] == s)
            for s in pdf.SEVERITIES
        )
        for b in blocks
    ]
    assert ranks == sorted(ranks)  # worst first
    with worker.connect() as conn:
        ids = dict(conn.execute(text("SELECT resource_uid, id FROM resource")).all())
    both = 0
    for block in blocks:
        rid = ids[block["uid"]]
        shown = len(block["misconfigurations"]) + len(block["vulnerabilities"])
        assert block["total"] == expected[rid] == shown + block["more"]
        assert block["account"] and block["account_id"] and block["type"]
        assert block["type_words"] == pdf.type_words(block["type"])
        # A CVE's facts (a code finding, CWE, has no CVE id: the template shows its check id).
        assert all(p["facts"] and "cve" in p["facts"] for p in block["vulnerabilities"])
        assert all(p["facts"] is None for p in block["misconfigurations"])
        both += bool(block["misconfigurations"] and block["vulnerabilities"])
    assert both > 0  # a resource with both kinds of problem, in one block

    # Each check or CVE shown is explained once, in the Reference.
    shown_ids = {
        (p["tool"], p["check_id"])
        for b in blocks
        for p in [*b["misconfigurations"], *b["vulnerabilities"]]
    }
    referenced = [(r["tool"], r["check_id"]) for r in context["reference"]]
    assert len(referenced) == len(set(referenced)) and set(referenced) == shown_ids
    assert any(r["risk"] for r in context["reference"] if r["tool"] == "prowler")
    assert all(r["facts"] for r in context["reference"] if r["tool"] == "vulnerabilities")


def test_the_csv_holds_a_row_per_problem(
    signed_in: TestClient, worker: Engine, root: Path, demo: int
) -> None:
    report_id = _ask(signed_in, "csv").json()["id"]
    assert _build(worker, root)
    body = signed_in.get(f"/api/v1/reports/{report_id}/download").content.decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(body.lstrip("﻿"))))
    expected = _expected(worker, demo)
    assert len(rows) == sum(expected.values())
    assert {r["source"] for r in rows} == {"misconfiguration", "vulnerability"}
    cves = [r for r in rows if r["source"] == "vulnerability"]
    assert all(r["result"] == "" and r["check_id"] for r in cves)  # a result is a check's
    assert any(r["vulnerability_id"].startswith("CVE-") for r in cves)
    assert all(r["vulnerability_id"] == "" for r in rows if r["source"] == "misconfiguration")
    assert len({r["resource_uid"] for r in rows}) == len(expected)


def test_severities_and_the_lists_filters_narrow_it(
    signed_in: TestClient, worker: Engine, root: Path, demo: int, rendered: list[dict[str, Any]]
) -> None:
    _ask(signed_in, severity=["critical"], type=["aws_ec2_instance"])
    assert _build(worker, root)
    (context,) = rendered
    assert context["total"] > 0
    assert {s["severity"] for s in context["severities"] if s["count"]} == {"critical"}
    assert {b["type"] for b in context["blocks"]} == {"aws_ec2_instance"}
    assert context["scope"].startswith("Critical") and "aws_ec2_instance" in context["scope"]


def test_the_caps_cut_the_list_never_the_counts(worker: Engine, demo: int) -> None:
    filters = ResourceProblemFilters(resources=ResourceListFilters(connection_ids=(demo,)))
    with worker.connect() as conn:
        full = problems.collect(conn, filters)
        cut = problems.collect(conn, filters, blocks=3, per_resource=1, cap=2)
    assert cut.total == full.total and cut.by_severity == full.by_severity
    assert len(cut.rows) == 3 and cut.listed == 2 and cut.truncated
    assert [r.resource_id for r in cut.resources] == [r.resource_id for r in full.resources]


def test_a_resources_jsonl_format_is_refused(signed_in: TestClient, root: Path) -> None:
    response = _ask(signed_in, "jsonl")
    assert response.status_code == 422


def test_the_kind_is_a_csv_or_a_pdf_whatever_writes_the_row(owner: Engine) -> None:
    with (
        owner.begin() as conn,
        pytest.raises(DBAPIError, match=r"resource_problems_format|jsonl_resources"),
    ):
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by) "
                "VALUES ('resource-problems', 'jsonl', '{}', ARRAY[1], 'x')"
            )
        )


def test_the_filters_go_back_as_they_were_stored() -> None:
    asked = ResourceProblemFilters(
        resources=ResourceListFilters(
            connection_ids=(3,), resource_types=("aws_s3_bucket",), internet=True
        ),
        severities=("critical", "high"),
        tags=(("env", ("prod", "stage")),),
    )
    stored = json.loads(json.dumps(report_filters.to_json(asked)))
    assert report_filters.from_json("resource-problems", stored, connection_ids=[3]) == asked
    with pytest.raises(ValueError, match="unknown report filters"):
        report_filters.from_json("resource-problems", {"check_ids": ["x"]}, connection_ids=[3])


def test_the_report_role_builds_it(
    signed_in: TestClient,
    reports_role: Engine,
    root: Path,
    demo: int,
    rendered: list[dict[str, Any]],
) -> None:
    """argus_reports (the Kubernetes report Job) reads everything this kind reads."""
    for fmt in ("pdf", "csv"):
        report_id = _ask(signed_in, fmt, internet=True).json()["id"]
        assert _build(reports_role, root)
        report = signed_in.get(f"/api/v1/reports/{report_id}").json()
        assert report["status"] == "ready", report["error"]
    assert rendered and rendered[0]["generated_at"] <= datetime.now(UTC).strftime("%Y-%m-%d %H:%M")


def test_one_resource_from_its_sheet(
    signed_in: TestClient, worker: Engine, root: Path, demo: int, rendered: list[dict[str, Any]]
) -> None:
    expected = _expected(worker, demo)
    rid = max(expected, key=lambda r: expected[r])
    _ask(signed_in, resource_id=rid, connection_id=[demo])
    assert _build(worker, root)
    (context,) = rendered
    assert context["resources"] == 1 and context["total"] == expected[rid]
    assert "one resource" in context["scope"]
    # The scope still bounds it: an account that does not exist is refused.
    asked = _ask(signed_in, resource_id=rid, connection_id=[demo + 1000])
    assert asked.status_code == 422  # no such account: nothing to report
