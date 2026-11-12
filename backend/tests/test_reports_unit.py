"""Reports without a database (ADR-0047): the CSV's formula guard and columns, the stored filters,
and the store's path checks."""

import csv
import io
from datetime import date
from pathlib import Path

import pytest

from argus.findings import FindingFilters, VulnerabilityFacts
from argus.reports import LocalReportStore, ReportStoreError
from argus.reports.csv_report import COLUMNS, CsvReport
from argus.reports.filters import from_json, to_json


@pytest.mark.parametrize(
    "value",
    ["=HYPERLINK(1)", "+1", "-2+3", "@SUM(A1)", "\tx", "\rx"],
    ids=["equals", "plus", "minus", "at", "tab", "cr"],
)
def test_a_cell_that_reads_as_a_formula_is_quoted(value: str) -> None:
    out = io.StringIO()
    CsvReport(out, "misconfigurations").write({"title": value, "resource_name": value})
    header, row = list(csv.reader(io.StringIO(out.getvalue().lstrip("\ufeff"))))
    cells = dict(zip(header, row, strict=True))
    assert cells["title"] == f"'{value}"
    assert cells["resource_name"] == f"'{value}"


def test_numbers_are_never_quoted_and_the_file_starts_with_a_bom() -> None:
    out = io.StringIO()
    report = CsvReport(out, "vulnerabilities")
    facts = VulnerabilityFacts(
        scanner="aws-inspector",
        kind="package",
        vulnerability_id="CVE-2026-0001",
        package_name="openssl",
        package_manager="OS",
        installed_version="1.0",
        fixed_version="1.1",
        cvss_score=-1.5,
        epss_score=0.25,
        scanner_score=None,
        exploit_available=True,
        fix_available="YES",
        image_digest=None,
        image_tags=[],
        reference_url=None,
    )
    report.write({"title": "CVE-2026-0001 - openssl", "vulnerability": facts, "muted": False})
    text = out.getvalue()
    assert text.startswith("\ufeff")
    header, row = text.lstrip("\ufeff").split("\r\n")[:2]
    names = header.split(",")
    assert names == [name for name, _ in COLUMNS["vulnerabilities"]]
    cells = dict(zip(names, row.split(","), strict=True))
    assert cells["cvss"] == "-1.5"  # a number, not a formula
    assert cells["epss"] == "0.25"
    assert cells["exploit_available"] == "yes"
    assert cells["muted"] == "no"
    assert cells["vulnerability_id"] == "CVE-2026-0001"


def test_the_kind_decides_the_tools_never_the_stored_filters() -> None:
    stored = to_json(
        FindingFilters(
            connection_ids=(9,),
            severities=("high",),
            tools=("prowler",),
            first_seen_from=date(2026, 10, 1),
            q="bucket",
        )
    )
    misconfigurations = from_json("misconfigurations", stored, connection_ids=[1, 2])
    assert misconfigurations.tools == ("prowler",)  # narrowed within the kind
    assert misconfigurations.connection_ids == (1, 2)  # the row's scope, not the stored one
    assert misconfigurations.first_seen_from == date(2026, 10, 1)
    assert misconfigurations.severities == ("high",)
    vulnerabilities = from_json("vulnerabilities", stored, connection_ids=[1])
    assert vulnerabilities.tools == ("vulnerabilities",)
    wider = from_json(
        "misconfigurations", {**stored, "tools": ["vulnerabilities"]}, connection_ids=[1]
    )
    assert wider.tools == ("prowler", "cloudfox")
    with pytest.raises(ValueError, match="unknown report filters"):
        from_json("misconfigurations", {"sql": "1"}, connection_ids=[1])


@pytest.mark.parametrize(
    "key",
    [
        "reports/../../etc/passwd",
        "/etc/passwd",
        "reports/1-abc.csv",
        "raw/prowler/x.csv",
        "reports/1-" + "0" * 32 + ".csv/..",
    ],
    ids=["dotdot", "absolute", "short", "raw", "trailing"],
)
def test_a_key_that_is_not_a_reports_is_refused(tmp_path: Path, key: str) -> None:
    with pytest.raises(ReportStoreError):
        LocalReportStore(tmp_path).path(key)


def test_a_symlinked_folder_cannot_lead_outside_the_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "reports").symlink_to(tmp_path)
    with pytest.raises(ReportStoreError):
        LocalReportStore(root).path("reports/1-" + "0" * 32 + ".csv")
