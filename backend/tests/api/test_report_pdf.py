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


def test_a_vulnerabilities_pdf_lists_each_resource_with_its_cves(
    signed_in: TestClient, worker: Engine, root: Path, demo: int, rendered: list[dict[str, Any]]
) -> None:
    """Owner, 2026-11-20: the Vulnerabilities PDF is grouped by resource, like the Catheris
    Platform report: each resource worst first, with its CVEs worst first, their facts and
    descriptions, read through the report's own filters (here: a public exploit)."""
    _ask(signed_in, "vulnerabilities", exploitable=True)
    assert reports.build_pending(worker, store=reports.LocalReportStore(root))
    (context,) = rendered
    with worker.connect() as conn:
        rows = [
            r
            for batch in findings.iter_findings(
                conn,
                FindingFilters(
                    connection_ids=(demo,), tools=("vulnerabilities",), exploitable=True
                ),
            )
            for r in batch
        ]
    per_resource = Counter(r["resource_uid"] for r in rows)
    blocks = context["blocks"]
    assert blocks and len(blocks) == min(len(per_resource), reports.model.PDF_RESOURCE_BLOCKS)
    ranks = [
        tuple(
            -next((c["count"] for c in b["chips"] if c["severity"] == s), 0) for s in pdf.SEVERITIES
        )
        for b in blocks
    ]
    assert ranks == sorted(ranks)  # worst first
    for block in blocks:
        assert block["total"] == per_resource[block["uid"]] == len(block["lines"]) + block["more"]
        assert len(block["lines"]) <= reports.model.PDF_PROBLEMS_PER_RESOURCE
        order = [pdf.SEVERITIES.index(line["severity"]) for line in block["lines"]]
        assert order == sorted(order)
        for line in block["lines"]:
            assert line["facts"]["exploit"] is True and line["facts"]["cve"]
            assert set(line["facts"]) == set(pdf._NO_FACTS)
        assert block["account"] and block["type_words"] == pdf.type_words(block["type"])
    assert any(line["description"] for b in blocks for line in b["lines"])
    assert context["listed"] == sum(len(b["lines"]) for b in blocks)
    assert "Public exploit" not in json.dumps(context)  # words live in the template, not the data
    assert context["scope"].endswith("public exploit")


def test_a_vulnerabilities_pdf_caps_the_cves_never_the_counts(worker: Engine, demo: int) -> None:
    filters = FindingFilters(connection_ids=(demo,), tools=("vulnerabilities",))
    with worker.connect() as conn:
        full = pdf.collect(conn, "vulnerabilities", filters)
        cut = pdf.collect(conn, "vulnerabilities", filters, cap=5)
    assert cut.total == full.total and cut.by_severity == full.by_severity
    assert cut.listed == 5 < full.listed and cut.truncated
    assert [r.uid for r in cut.ranked] == [r.uid for r in full.ranked]


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
            conn,
            "misconfigurations",
            FindingFilters(connection_ids=(demo,), tools=("prowler",)),
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
def test_the_summary_counts_each_resource_type_by_severity(
    worker: Engine, demo: int, kind: str
) -> None:
    """Spec frontend/924f747a (owner, 2026-11-20): "By resource type" replaces the worst
    resources: each type's findings by severity and its distinct resources, worst first, as the
    findings list counts them; then the most common checks or CVEs, the regions, the share bar."""
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
    counts: dict[str, list[int]] = {}
    resources: dict[str, set[Any]] = {}
    for r in rows:
        key = r["resource_id"] if r["resource_id"] is not None else r["resource_uid"]
        kind_of = r["resource_type"] or "unknown"
        counts.setdefault(kind_of, [0] * 5)[pdf.SEVERITIES.index(r["severity"])] += 1
        resources.setdefault(kind_of, set()).add(key)
    assert context["resources"] == len(set().union(*resources.values())) > 0
    assert "worst" not in context

    by_type = context["by_type"]
    assert 0 < len(by_type) <= pdf.TYPE_ROWS
    assert len(by_type) + context["more_types"] == len(counts)
    for t in by_type:
        assert t["counts"] == counts[t["type"]]
        assert t["resources"] == len(resources[t["type"]])
        assert t["total"] == sum(t["counts"]) > 0
        assert t["words"] == pdf.type_words(t["type"])
    ranks = [(*(-n for n in t["counts"]), -t["total"], t["type"]) for t in by_type]
    assert ranks == sorted(ranks)  # most critical first, then most high, and so on
    assert ranks[0] == min((*(-n for n in c), -sum(c), k) for k, c in counts.items())

    common = context["common"]
    assert 0 < len(common) <= pdf.TOP_COMMON
    assert [c["resources"] for c in common] == sorted(
        (c["resources"] for c in common), reverse=True
    )

    # By account and region (owner, 2026-11-20): each account's regions add up to its findings.
    assert sum(a["findings"] for a in context["by_account"]) == context["total"]
    for a in context["by_account"]:
        assert len(a["regions"]) <= pdf.REGIONS_PER_ACCOUNT
        assert sum(r["findings"] for r in a["regions"]) == a["findings"] or a["more_regions"]
        assert all(r["region"] is None or r["region"] for r in a["regions"])
    assert "assets" not in context and "by_region" not in context
    shares = context["shares"]
    assert sum(s["width"] for s in shares) == pdf.BAR_UNITS
    assert [s["x"] for s in shares] == [
        sum(s["width"] for s in shares[:i]) for i in range(len(shares))
    ]
    assert round(sum(s["percent"] for s in shares)) == 100


def test_the_summary_names_at_most_its_rows_of_types() -> None:
    types = {f"AwsType{i:02d}": pdf.TypeCount(f"AwsType{i:02d}") for i in range(40)}
    for i, t in enumerate(types.values()):
        t.add("high" if i % 2 else "low", i)
    rows = pdf.type_rows(types)
    assert len(rows) == pdf.TYPE_ROWS
    assert [r["counts"][1] for r in rows[:20]] == [1] * 20  # every high before any low


def test_a_check_lists_each_resource_with_what_the_tool_says_about_it(
    worker: Engine, demo: int
) -> None:
    """Owner, 2026-11-20: "I don't understand in what resource is the finding". A block's rows
    carry the finding's own sentence (Prowler's status_extended) without Markdown, and say how
    many distinct resources the check failed on."""
    with worker.connect() as conn:
        context = _context(conn, "misconfigurations", demo)
        details = {
            pdf._plain(r["detail"])
            for batch in findings.iter_findings(
                conn, FindingFilters(connection_ids=(demo,), tools=("prowler",))
            )
            for r in batch
            if r["detail"]
        }
    rows = [r for b in context["blocks"] for r in b["rows"]]
    said = [r for r in rows if r["result"]]
    assert said, "no block row carries the tool's sentence"
    for r in said:
        assert "**" not in r["result"] and "`" not in r["result"]
        assert r["result"] in details  # one of the tool's own sentences, as it wrote it
    for b in context["blocks"]:
        assert 0 < b["resources"] <= b["count"]
        assert all(r["type_words"] == pdf.type_words(r["type"]) for r in b["rows"])


@pytest.mark.parametrize(
    ("raw", "words"),
    [
        ("AwsEc2Instance", "EC2 instance"),
        ("AwsEc2SecurityGroup", "EC2 security group"),
        ("AwsS3Bucket", "S3 bucket"),
        ("AwsIamRole", "IAM role"),
        ("AwsCloudTrailTrail", "CloudTrail trail"),
        ("AwsCloudWatchAlarm", "CloudWatch alarm"),
        ("AwsElbv2LoadBalancer", "ELBv2 load balancer"),
        ("AwsRdsDbInstance", "RDS DB instance"),
        ("AwsDynamoDbTable", "DynamoDB table"),
        ("aws_ec2_instance", "EC2 instance"),
        ("aws_cloudtrail_trail", "CloudTrail trail"),
        ("aws_lambda_function", "Lambda function"),
        ("Other", "Other"),
        ("unknown", "unknown"),
        (None, "unknown"),
        ("Aws", "Aws"),
    ],
)
def test_a_resource_type_reads_as_people_say_it(raw: str | None, words: str) -> None:
    assert pdf.type_words(raw) == words


@pytest.mark.parametrize("kind", ["misconfigurations", "vulnerabilities"])
def test_the_report_role_builds_a_pdf_and_reads_no_metrics(
    signed_in: TestClient,
    reports_role: Engine,
    root: Path,
    demo: int,
    rendered: list[dict[str, Any]],
    kind: str,
) -> None:
    """argus_reports (the Kubernetes report Job) builds both PDFs, by check and by resource.
    Since 0060 it no longer reads metric_daily: the assets left the PDF (owner, 2026-11-20)."""
    report_id = _ask(signed_in, kind).json()["id"]
    assert reports.build_pending(reports_role, store=reports.LocalReportStore(root))
    report = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert report["status"] == "ready", report["error"]
    (context,) = rendered
    assert context["blocks"] and context["by_type"]
    with reports_role.connect() as conn, pytest.raises(DBAPIError, match="permission denied"):
        conn.execute(text("SELECT metric FROM metric_daily LIMIT 1"))


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
