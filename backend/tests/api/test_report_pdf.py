"""The PDF report (ADR-0047, round 2). The renderer itself (Jinja2, WeasyPrint) lives in its own
venv in the reports and worker images and proves itself at image build (render.py --self-test);
here its input is checked: what crosses into it, grouped, capped, and named."""

import json
from collections import Counter
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
        full = pdf.collect(conn, "misconfigurations", filters, today=DAY)
        cut = pdf.collect(conn, "misconfigurations", filters, today=DAY, per_block=2, cap=7)
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
            today=DAY,
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
            conn,
            "misconfigurations",
            FindingFilters(connection_ids=(demo,), tools=("prowler",)),
            today=DAY,
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


def _context(conn: Connection, kind: str, demo: int) -> dict[str, Any]:
    tools = ("prowler", "cloudfox") if kind == "misconfigurations" else ("vulnerabilities",)
    collected = pdf.collect(
        conn,
        kind,
        FindingFilters(connection_ids=(demo,), tools=tools),
        today=DAY,  # type: ignore[arg-type]
    )
    return pdf.build_context(
        collected,
        report_id=1,
        kind=kind,  # type: ignore[arg-type]
        requested_by="admin",
        generated_at=datetime(2026, 11, 19, tzinfo=UTC),
        scope_words="all",
        severities_in_scope=list(pdf.SEVERITIES),
        data_through={demo: DAY},
    )


@pytest.mark.parametrize("kind", ["misconfigurations", "vulnerabilities"])
def test_the_summary_names_the_worst_resources_and_where_they_are(
    worker: Engine, demo: int, kind: str
) -> None:
    """Spec frontend/709108a0: resources worst first with their counts by severity, the most
    common checks or CVEs by resources, the regions, and the severity share bar."""
    tools = ("prowler", "cloudfox") if kind == "misconfigurations" else ("vulnerabilities",)
    with worker.connect() as conn:
        context = _context(conn, kind, demo)
        rows = [
            r
            for batch in findings.iter_findings(
                conn, FindingFilters(connection_ids=(demo,), tools=tools)
            )
            for r in batch
        ]
    per_resource: dict[Any, list[int]] = {}
    for r in rows:
        key = r["resource_id"] if r["resource_id"] is not None else r["resource_uid"]
        counts = per_resource.setdefault(key, [0] * 5)
        counts[pdf.SEVERITIES.index(r["severity"])] += 1
    assert context["resources"] == len(per_resource) > 0

    worst = context["worst"]
    assert 0 < len(worst) <= pdf.TOP_RESOURCES
    ranks = [
        tuple(
            -next((c["count"] for c in w["chips"] if c["severity"] == s), 0) for s in pdf.SEVERITIES
        )
        for w in worst
    ]
    assert ranks == sorted(ranks)  # most critical first, then most high, and so on
    expected_first = min(tuple(-n for n in counts) for counts in per_resource.values())
    assert ranks[0] == expected_first
    for w in worst:
        assert w["total"] == sum(c["count"] for c in w["chips"]) > 0
        assert w["uid"] and w["account"] and w["account_id"]
        assert all(c["count"] > 0 and c["letter"] for c in w["chips"])

    common = context["common"]
    assert 0 < len(common) <= pdf.TOP_COMMON
    assert [c["resources"] for c in common] == sorted(
        (c["resources"] for c in common), reverse=True
    )

    assert (
        sum(r["findings"] for r in context["by_region"]) == context["total"]
        or context["more_regions"]
    )
    shares = context["shares"]
    assert sum(s["width"] for s in shares) == pdf.BAR_UNITS
    assert [s["x"] for s in shares] == [
        sum(s["width"] for s in shares[:i]) for i in range(len(shares))
    ]
    assert round(sum(s["percent"] for s in shares)) == 100


def test_assets_by_category_are_the_overviews(
    signed_in: TestClient, worker: Engine, demo: int
) -> None:
    """The PDF's "Assets by category" counts what the Overview's Inventory card counts: one
    taxonomy (metrics.categories), each account at its latest inventory scan."""
    with worker.connect() as conn:
        context = _context(conn, "misconfigurations", demo)
    overview = signed_in.get(
        "/api/v1/overview", params={"connection_id": demo, "as_of": DAY.isoformat()}
    ).json()
    by_category: dict[str, int] = {}
    for row in overview["inventory"]["by_type"]:
        by_category[row["category"]] = by_category.get(row["category"], 0) + int(row["count"])
    assert {a["category"]: a["count"] for a in context["assets"]} == by_category
    assert context["assets"][-1]["category"] == "Other" or "Other" not in by_category
    counts = [a["count"] for a in context["assets"] if a["category"] != "Other"]
    assert counts == sorted(counts, reverse=True)


def test_a_pdf_without_any_inventory_says_not_covered(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "prowler", DAY)
    with worker.connect() as conn:
        context = _context(conn, "misconfigurations", target.connection_id)
    assert context["total"] > 0 and context["assets"] is None  # "not covered", never 0


def test_the_report_role_builds_a_pdf_with_its_assets(
    signed_in: TestClient,
    reports_role: Engine,
    root: Path,
    demo: int,
    rendered: list[dict[str, Any]],
) -> None:
    """argus_reports (the Kubernetes report Job) reads metric_daily since migration 0058."""
    report_id = _ask(signed_in, "misconfigurations").json()["id"]
    assert reports.build_pending(reports_role, store=reports.LocalReportStore(root))
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["status"] == "ready", report["error"]
    (context,) = rendered
    assert context["assets"] and context["worst"]


def test_the_share_bar_always_makes_the_whole() -> None:
    """Whole thousandths in order, by largest remainder, even with a severity word Argus does not
    know (the renderer refuses a bar that is not exactly the whole)."""
    for counts in (
        {"critical": 1, "high": 1, "medium": 1},
        {"critical": 114, "high": 151, "medium": 199, "low": 22},
        {"low": 7},
        {"critical": 1, "unheard-of": 5},
    ):
        shares = pdf._shares(Counter(counts), sum(counts.values()))
        assert sum(s["width"] for s in shares) == pdf.BAR_UNITS
        assert all(isinstance(s["x"], int) and isinstance(s["width"], int) for s in shares)
        assert [s["x"] for s in shares] == [
            sum(s["width"] for s in shares[:i]) for i in range(len(shares))
        ]
    assert pdf._shares(Counter(), 0) == []
