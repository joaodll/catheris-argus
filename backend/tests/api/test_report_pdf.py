"""The PDF report (ADR-0047, round 2). The renderer itself (Jinja2, WeasyPrint) lives in its own
venv in the reports and worker images and proves itself at image build (render.py --self-test);
here its input is checked: what crosses into it, grouped, capped, and named."""

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError
from tests.api.conftest import csrf
from tests.ingest.conftest import make_demo, run_tool

from argus import findings, reports
from argus.collection import FilesystemRawStore
from argus.core.config import get_settings
from argus.core.process import IsolatedRunError
from argus.findings import FindingFilters
from argus.reports import pdf

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
    """The renderer stubbed: each context it is given, and a PDF-shaped answer."""
    contexts: list[dict[str, Any]] = []

    def fake(context: dict[str, Any]) -> bytes:
        contexts.append(json.loads(json.dumps(context)))  # what really crosses: JSON
        return b"%PDF-1.7\n% stub\n"

    monkeypatch.setattr(pdf, "render", fake)
    return contexts


def _ask(client: TestClient, kind: str, **filters: Any) -> Any:
    return client.post(
        "/api/v1/reports",
        json={"kind": kind, "format": "pdf", "filters": filters},
        headers=csrf(client),
    )


def test_a_pdf_report_is_built_from_its_context_and_downloaded(
    signed_in: TestClient,
    worker: Engine,
    root: Path,
    demo: int,
    rendered: list[dict[str, Any]],
) -> None:
    report_id = _ask(signed_in, "misconfigurations").json()["id"]
    assert reports.build_pending(worker, store=reports.LocalReportStore(root))
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["format"] == "pdf" and report["status"] == "ready", report
    total = signed_in.get("/api/v1/findings", params={"limit": 1}).json()["total"]
    assert report["row_count"] == total > 0

    (context,) = rendered
    assert context["total"] == total == sum(s["count"] for s in context["severities"])
    assert context["listed"] == sum(len(b["rows"]) for b in context["blocks"])
    assert context["truncated"] == report["truncated"] == (context["listed"] < total)
    order = [pdf.SEVERITIES.index(b["severity"]) for b in context["blocks"]]
    assert order == sorted(order)  # worst first
    assert all(
        len(b["rows"]) <= 25 and b["more"] == b["count"] - len(b["rows"]) for b in context["blocks"]
    )
    prowler = [b for b in context["blocks"] if b["tool"] == "prowler"]
    assert prowler and any(b["risk"] for b in prowler)  # finding_check_text reached the PDF
    cloudfox = [b for b in context["blocks"] if b["tool"] == "cloudfox"]
    assert cloudfox and all(b["risk"] is None for b in cloudfox)  # the template says why
    links = [b["fix_link"] for b in context["blocks"] if b["fix_link"]]
    assert all(link.startswith(("http://", "https://")) for link in links)

    response = signed_in.get(f"/api/v1/reports/{report_id}/download")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert (
        f'filename="argus-misconfigurations-{report_id}.pdf"'
        in response.headers["content-disposition"]
    )
    assert response.content.startswith(b"%PDF")


def test_a_vulnerabilities_pdf_carries_each_cves_facts(
    signed_in: TestClient, worker: Engine, root: Path, demo: int, rendered: list[dict[str, Any]]
) -> None:
    _ask(signed_in, "vulnerabilities", exploitable=True)
    assert reports.build_pending(worker, store=reports.LocalReportStore(root))
    (context,) = rendered
    assert context["blocks"]
    for block in context["blocks"]:
        assert block["tool"] == "vulnerabilities"
        assert block["facts"]["exploit"] is True and block["facts"]["cve"]
        assert set(block["facts"]) == set(pdf._NO_FACTS)
    assert "Public exploit" not in json.dumps(context)  # words live in the template, not the data
    assert context["scope"].endswith("public exploit")


def test_the_caps_cut_the_list_never_the_counts(owner: Engine, worker: Engine, demo: int) -> None:
    filters = FindingFilters(connection_ids=(demo,), tools=("prowler", "cloudfox"))
    with worker.connect() as conn:
        full = pdf.collect(conn, "misconfigurations", filters)
        cut = pdf.collect(conn, "misconfigurations", filters, per_block=2, cap=7)
    assert cut.total == full.total and cut.by_severity == full.by_severity
    assert cut.listed == 7 and cut.truncated
    assert all(len(g.rows) <= 2 for g in cut.groups)
    assert [g.check_id for g in cut.groups] == [g.check_id for g in full.groups]


def test_a_failing_render_fails_the_report_with_a_fixed_sentence(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    root: Path,
    demo: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(_: dict[str, Any]) -> bytes:
        raise IsolatedRunError("exited with 1")

    monkeypatch.setattr(pdf, "render", broken)
    report_id = _ask(signed_in, "misconfigurations").json()["id"]
    assert reports.build_pending(worker, store=reports.LocalReportStore(root))
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["status"] == "failed"
    assert report["error"] == "The PDF could not be drawn. Try the CSV, or narrow the filters."
    assert not list((root / "reports").iterdir())


def test_check_texts_reads_many_checks_at_once(worker: Engine, demo: int) -> None:
    with worker.connect() as conn:
        keys = [
            (r.tool, r.check_id)
            for r in conn.execute(
                text("SELECT DISTINCT tool, check_id FROM finding WHERE tool = 'prowler' LIMIT 5")
            )
        ]
        found = findings.check_texts(conn, [*keys, ("cloudfox", "no-such-check")])
    assert set(found) == set(keys)
    assert all({"risk", "description", "links", "code_cli"} <= set(v) for v in found.values())


def _fails(conn: Connection, statement: str) -> str:
    savepoint = conn.begin_nested()
    with pytest.raises(DBAPIError) as exc:
        conn.execute(text(statement))
    savepoint.rollback()
    return str(exc.value.orig)


def test_a_reports_file_extension_matches_its_format(owner: Engine) -> None:
    hexes = "0" * 32
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by) "
                "VALUES ('misconfigurations', 'pdf', '{}', ARRAY[1], 'x')"
            )
        )
        base = (
            "UPDATE report_request SET status = 'ready', started_at = now(), finished_at = now(), "
            "expires_at = now(), size_bytes = 1, sha256 = repeat('a', 64), row_count = 1, "
            "data_through = '{}', storage_key = "
        )
        assert "report_request_key_matches_format" in _fails(
            conn, base + f"'reports/1-{hexes}.csv'"
        )
        refused = _fails(conn, base + f"'reports/1-{hexes}.exe'")  # breaks both CHECKs
        assert "report_request_storage_key_check" in refused or "matches_format" in refused
        conn.execute(text(base + f"'reports/1-{hexes}.pdf'"))


def test_the_cover_says_the_scope_in_words() -> None:
    words = pdf.describe(
        FindingFilters(
            severities=("high", "critical"),
            state="resolved",
            regions=("us-east-1",),
            first_seen_from=date(2026, 10, 1),
            q="bucket",
            fix="available",
        ),
        accounts=3,
    )
    assert words == (
        "Critical, High · 3 accounts · resolved · us-east-1 · first seen from 2026-10-01"
        " · matching “bucket” · fix available"
    )
    assert pdf.describe(FindingFilters(), accounts=1) == "1 account · open"


@pytest.mark.parametrize(
    ("url", "kept"),
    [
        ("https://docs.aws.amazon.com/x", True),
        ("http://example.com", True),
        ("javascript:alert(1)", False),
        ("file:///etc/passwd", False),
        ("https://", False),
        (None, False),
    ],
    ids=["https", "http", "javascript", "file", "no-host", "none"],
)
def test_only_web_links_reach_a_pdf(url: str | None, kept: bool) -> None:
    assert (pdf._link(url) is not None) == kept


def test_the_context_is_plain_json(demo: int, worker: Engine) -> None:
    with worker.connect() as conn:
        collected = pdf.collect(
            conn,
            "vulnerabilities",
            FindingFilters(connection_ids=(demo,), tools=("vulnerabilities",)),
        )
    context = pdf.build_context(
        collected,
        report_id=1,
        kind="vulnerabilities",
        requested_by="admin",
        generated_at=datetime(2026, 11, 11, 12, 0, tzinfo=UTC),
        scope_words="all",
        severities_in_scope=list(pdf.SEVERITIES),
        data_through={demo: DAY},
    )
    assert json.loads(json.dumps(context)) == context
    assert context["generated_at"] == "2026-11-11 12:00"


@pytest.mark.parametrize(
    ("raw", "plain"),
    [
        ("Risks **lateral movement** via `464`.", "Risks lateral movement via 464."),
        ('```hcl\nresource "x" {}\n```', 'resource "x" {}'),
        ("   ", None),
        (None, None),
    ],
    ids=["emphasis-and-code", "fence", "blank", "none"],
)
def test_tool_text_reaches_a_pdf_without_markdown(raw: str | None, plain: str | None) -> None:
    assert pdf._plain(raw) == plain


def test_past_the_detailed_blocks_checks_are_named_then_counted(
    worker: Engine, demo: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every check appears: in full up to PDF_DETAILED_BLOCKS, named up to PDF_NAMED_CAP more,
    and counted past that (the renderer ran out of memory at 10,000 names)."""
    monkeypatch.setattr(pdf, "PDF_DETAILED_BLOCKS", 3)
    monkeypatch.setattr(pdf, "PDF_NAMED_CAP", 4)
    with worker.connect() as conn:
        collected = pdf.collect(
            conn, "misconfigurations", FindingFilters(connection_ids=(demo,), tools=("prowler",))
        )
    context = pdf.build_context(
        collected,
        report_id=1,
        kind="misconfigurations",
        requested_by="admin",
        generated_at=datetime(2026, 11, 11, tzinfo=UTC),
        scope_words="all",
        severities_in_scope=list(pdf.SEVERITIES),
        data_through={},
    )
    groups = len(collected.groups)
    assert groups > 7
    assert len(context["blocks"]) == 3 and len(context["others"]) == 4
    assert context["more_others"] == groups - 7
    named = [o["check_id"] for o in context["others"]]
    assert named == [g.check_id for g in collected.groups[3:7]]  # worst first, after the blocks
