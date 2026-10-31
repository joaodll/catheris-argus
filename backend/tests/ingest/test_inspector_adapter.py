"""The Inspector adapter (ADR-0042), pure: rows as the export writes them -> findings,
vulnerability facts, check text and coverage. No database."""

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from argus.collection.tables import INSPECTOR_TABLES, inspector_table_options
from argus.core.manifest import Manifest, ManifestFile
from argus.core.rawstore import RawRun
from argus.findings import parse_inspector
from argus.findings.inspector import UnsupportedVersionError

ACCOUNT = "123456789012"
OTHER = "210987654321"
REGION = "us-east-1"
FN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:billing"
REPO = f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/team/api"
IMAGE = f"{REPO}/sha256:{'ab' * 32}"


def _run(
    tmp_path: Path,
    tables: dict[str, list[dict[str, Any]]],
    *,
    status: str = "complete",
    incomplete: tuple[str, ...] = (),
    version: str = "1.34.0",
) -> RawRun:
    files = []
    for table, rows in tables.items():
        # JSON columns as the export writes them: JSON text.
        data = "".join(
            json.dumps(
                {k: json.dumps(v) if isinstance(v, list | dict) else v for k, v in r.items()}
            )
            + "\n"
            for r in rows
        ).encode()
        (tmp_path / f"{table}.jsonl").write_bytes(data)
        files.append(
            ManifestFile(
                path=f"{table}.jsonl", bytes=len(data), sha256=hashlib.sha256(data).hexdigest()
            )
        )
    now = datetime.now(UTC)
    manifest = Manifest(
        run_uid=uuid4(),
        tool="inspector",
        tool_version=version,
        account_id=ACCOUNT,
        source="aws",
        snapshot_date=date(2026, 10, 30),
        region_scope=[],
        started_at=now,
        finished_at=now,
        status=status,  # type: ignore[arg-type]
        exit_code=0,
        throttle_events=0,
        files=files,
        incomplete_tables=list(incomplete),
    )
    return RawRun(manifest=manifest, root=tmp_path)


def _finding(n: int, resource: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "arn": f"arn:aws:inspector2:{REGION}:{ACCOUNT}:finding/{n:032x}",
        "finding_account_id": ACCOUNT,
        "status": "ACTIVE",
        "type": "PACKAGE_VULNERABILITY",
        "severity": "HIGH",
        "title": "CVE-2024-6387 - openssh-server",
        "description": "A race condition in sshd.",
        "vulnerability_id": "CVE-2024-6387",
        "exploit_available": "YES",
        "fix_available": "YES",
        "inspector_score": 8.1,
        "epss_score": 0.43,
        "vulnerable_packages": [
            {"Name": "openssh-server", "Version": "9.2p1", "FixedInVersion": "9.8p1"}
        ],
        "cvss": [
            {"BaseScore": 9.0, "Source": "GITHUB", "Version": "3.1"},
            {"BaseScore": 8.1, "Source": "NVD", "Version": "3.1"},
        ],
        "remediation_recommendation_text": "Upgrade openssh-server.",
        "remediation_recommendation_url": "javascript:alert(1)",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        "resources": [resource],
        "region": REGION,
        "partition": "aws",
        "account_id": ACCOUNT,
        **fields,
    }


EC2 = {"Type": "AWS_EC2_INSTANCE", "Id": "i-0123456789abcdef0", "Region": REGION}
LAMBDA = {
    "Type": "AWS_LAMBDA_FUNCTION",
    "Id": f"{FN}:$LATEST",
    "Details": {"AwsLambdaFunction": {"FunctionName": "billing"}},
}
ECR = {
    "Type": "AWS_ECR_CONTAINER_IMAGE",
    "Id": IMAGE,
    "Details": {
        "AwsEcrContainerImage": {
            "RepositoryName": "team/api",
            "ImageHash": f"sha256:{'ab' * 32}",
            "ImageTags": ["v1", "latest"],
        }
    },
}


def test_each_resource_kind_links_to_what_the_inventory_names(tmp_path: Path) -> None:
    batch = parse_inspector(
        _run(
            tmp_path,
            {"aws_inspector2_finding": [_finding(1, EC2), _finding(2, LAMBDA), _finding(3, ECR)]},
        )
    )
    by_type = {f.resource_type: f for f in batch.findings}
    # The instance id is resolved with the region at load, like Prowler's short ids.
    assert by_type["AwsEc2Instance"].resource_uid == "i-0123456789abcdef0"
    assert by_type["AwsLambdaFunction"].resource_uid == FN  # no :$LATEST
    assert by_type["AwsLambdaFunction"].resource_name == "billing"
    assert by_type["AwsEcrRepository"].resource_uid == REPO  # the repository, not the image
    image = batch.vulnerabilities[by_type["AwsEcrRepository"].finding_uid]
    assert image.image_digest == f"sha256:{'ab' * 32}" and image.image_tags == ("v1", "latest")
    assert batch.complete and not batch.skipped


def test_a_package_finding_maps_to_a_finding_and_its_vulnerability(tmp_path: Path) -> None:
    batch = parse_inspector(_run(tmp_path, {"aws_inspector2_finding": [_finding(1, EC2)]}))
    (finding,) = batch.findings
    assert finding.check_id == "CVE-2024-6387" and finding.status == "FAIL"
    assert finding.severity == "high" and not finding.muted
    assert finding.categories == ("vulnerability",) and finding.service == "ec2"
    assert finding.remediation_url is None  # http(s) only
    assert finding.detail == "openssh-server 9.2p1 is affected; fixed in 9.8p1."
    v = batch.vulnerabilities[finding.finding_uid]
    assert (v.vulnerability_id, v.package_name, v.installed_version, v.fixed_version) == (
        "CVE-2024-6387",
        "openssh-server",
        "9.2p1",
        "9.8p1",
    )
    assert v.cvss_score == 8.1  # NVD v3 preferred over a higher score from another source
    assert v.epss_score == 0.43 and v.exploit_available and v.fix_available == "YES"
    assert v.reference_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"
    check = batch.checks["CVE-2024-6387"]
    assert check.description == "A race condition in sshd."
    assert check.links == ("https://nvd.nist.gov/vuln/detail/CVE-2024-6387",)


def test_suppressed_untriaded_no_fix_and_a_code_finding(tmp_path: Path) -> None:
    rows = [
        _finding(1, EC2, status="SUPPRESSED"),
        _finding(
            2,
            EC2,
            severity="UNTRIADED",
            vulnerability_id="CVE-2022-48174",
            fix_available="NO",
            vulnerable_packages=[
                {"Name": "busybox", "Version": "1.36.0", "FixedInVersion": "NotAvailable"}
            ],
        ),
        _finding(
            3,
            LAMBDA,
            type="CODE_VULNERABILITY",
            title="CWE-117 - Log injection",
            vulnerability_id=None,
            vulnerable_packages=None,
            exploit_available=None,
        ),
    ]
    batch = parse_inspector(_run(tmp_path, {"aws_inspector2_finding": rows}))
    suppressed, untriaged, code = batch.findings
    assert suppressed.muted
    assert untriaged.severity == "informational"
    assert batch.vulnerabilities[untriaged.finding_uid].fixed_version is None
    assert untriaged.detail == "busybox 1.36.0 is affected."
    assert code.check_id == "code:CWE-117 - Log injection"
    facts = batch.vulnerabilities[code.finding_uid]
    assert facts.finding_type == "CODE_VULNERABILITY" and facts.vulnerability_id is None


def test_rows_left_out_are_counted(tmp_path: Path) -> None:
    rows = [
        _finding(1, EC2, type="NETWORK_REACHABILITY"),
        _finding(2, EC2, finding_account_id=OTHER),
        _finding(3, EC2, status="CLOSED"),
        _finding(4, {"Type": "AWS_EC2_INSTANCE"}),
        _finding(5, EC2),
        _finding(5, EC2),  # the same finding twice is one finding
    ]
    batch = parse_inspector(_run(tmp_path, {"aws_inspector2_finding": rows}))
    assert len(batch.findings) == 1
    assert batch.skipped == {
        "type NETWORK_REACHABILITY": 1,
        "another account": 1,
        "closed": 1,
        "no resource": 1,
    }


def test_coverage_per_resource_and_scan_type(tmp_path: Path) -> None:
    def row(rid: str, kind: str, code: str, **more: Any) -> dict[str, Any]:
        return {
            "resource_id": rid,
            "resource_type": kind,
            "scan_type": "PACKAGE",
            "scan_status_code": code,
            "scan_status_reason": "SUCCESSFUL" if code == "ACTIVE" else "UNMANAGED_EC2_INSTANCE",
            "last_scanned_at": "2026-10-30T03:00:00Z",
            "source_account_id": ACCOUNT,
            "region": REGION,
            **more,
        }

    coverage = [
        row("i-0123456789abcdef0", "AWS_EC2_INSTANCE", "INACTIVE", last_scanned_at=None),
        row(f"{FN}:3", "AWS_LAMBDA_FUNCTION", "ACTIVE"),
        # Two images of one repository: scanned, as of the later image.
        row(IMAGE, "AWS_ECR_CONTAINER_IMAGE", "ACTIVE", ecr_repository_name="team/api"),
        row(
            f"{REPO}/sha256:{'cd' * 32}",
            "AWS_ECR_CONTAINER_IMAGE",
            "ACTIVE",
            ecr_repository_name="team/api",
            last_scanned_at="2026-10-30T05:00:00Z",
        ),
        row("i-0fedcba9876543210", "AWS_EC2_INSTANCE", "ACTIVE", source_account_id=OTHER),
    ]
    batch = parse_inspector(_run(tmp_path, {"aws_inspector2_coverage": coverage}))
    by_uid = {c.resource_uid: c for c in batch.coverage}
    assert set(by_uid) == {"i-0123456789abcdef0", FN, REPO}
    assert by_uid["i-0123456789abcdef0"].status_reason == "UNMANAGED_EC2_INSTANCE"
    assert by_uid[REPO].last_scanned_at == datetime(2026, 10, 30, 5, tzinfo=UTC)
    # No findings table: nothing may resolve; the coverage table alone is complete.
    assert not batch.complete and batch.coverage_complete


def test_an_incomplete_findings_table_resolves_nothing(tmp_path: Path) -> None:
    tables = {"aws_inspector2_finding": [_finding(1, EC2)], "aws_inspector2_coverage": []}
    partial = parse_inspector(
        _run(tmp_path, tables, status="partial", incomplete=("aws_inspector2_finding",))
    )
    assert partial.findings and not partial.complete and partial.coverage_complete


def test_an_unknown_export_version_is_refused(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedVersionError):
        parse_inspector(_run(tmp_path, {}, version="1.35.0"))


def test_the_export_asks_for_this_account_and_open_findings_only() -> None:
    findings, coverage = (inspector_table_options(t, ACCOUNT) for t in INSPECTOR_TABLES)
    wheres = [findings[i + 1] for i, word in enumerate(findings) if word == "--where"]
    assert wheres == [f"finding_account_id = '{ACCOUNT}'", "status <> 'CLOSED'"]
    assert "--select" in findings and "--select" in coverage
    with pytest.raises(ValueError, match="12 digits"):
        inspector_table_options(INSPECTOR_TABLES[0], "1' OR '1'='1")
