"""Synthetic AWS Inspector output (ADR-0042): what the Inspector collector's Steampipe export
writes for a demo account, aws_inspector2_finding.jsonl and aws_inspector2_coverage.jsonl.

Columns are the collector's --select (collection/tables.py). Nested AWS structures are in the
SDK's field names, as the plugin serialises them. Deterministic per (account, day):
- every instance and function is covered, except one instance in seven (no SSM agent);
- a covered resource carries a few CVEs from a fixed catalog, each open for a span of days, so
  history has CVEs that resolve and new ones that open;
- one CVE in eleven is suppressed in Inspector, some functions carry a code vulnerability, and
  some instances a network reachability finding (which the adapter leaves out).
CVE ids and packages are public examples; versions are made up.
"""

import json
from datetime import UTC, datetime, time
from pathlib import Path
from typing import Any

from argus.collection.synthetic.estate import EstateDay, day_number
from argus.collection.synthetic.model import Resource, h, hexid, u

TOOL_VERSION = "1.34.0"
FINDINGS_TABLE = "aws_inspector2_finding"
COVERAGE_TABLE = "aws_inspector2_coverage"
# (CVE, severity, package, installed, fixed or None, CVSS, EPSS, exploit available)
CATALOG: tuple[tuple[str, str, str, str, str | None, float, float, bool], ...] = (
    ("CVE-2023-38545", "CRITICAL", "curl", "7.88.1", "8.4.0", 9.8, 0.27, True),
    ("CVE-2024-6387", "HIGH", "openssh-server", "9.2p1", "9.8p1", 8.1, 0.43, True),
    ("CVE-2023-4863", "HIGH", "libwebp", "1.2.4", "1.3.2", 8.8, 0.62, True),
    ("CVE-2024-3094", "CRITICAL", "xz-utils", "5.6.0", "5.4.6", 10.0, 0.86, True),
    ("CVE-2023-44487", "HIGH", "nghttp2", "1.52.0", "1.57.0", 7.5, 0.82, True),
    ("CVE-2023-5363", "MEDIUM", "openssl", "3.0.9", "3.0.12", 7.5, 0.01, False),
    ("CVE-2024-2511", "LOW", "openssl", "3.0.9", "3.0.14", 5.9, 0.002, False),
    ("CVE-2023-29491", "MEDIUM", "ncurses", "6.4", "6.4-20230408", 7.8, 0.0005, False),
    ("CVE-2023-24329", "MEDIUM", "python3.11", "3.11.2", "3.11.4", 7.5, 0.004, False),
    ("CVE-2024-27983", "HIGH", "nodejs", "20.11.0", "20.12.1", 8.2, 0.003, False),
    ("CVE-2022-48174", "CRITICAL", "busybox", "1.36.0", None, 9.8, 0.001, False),
    ("CVE-2023-2650", "UNTRIADED", "openssl", "3.0.8", "3.0.9", 6.5, 0.003, False),
)
SPAN_DAYS = 40  # a CVE stays open on a resource for up to this many days, then is patched


def _covered(r: Resource) -> bool:
    return r.table != "aws_ec2_instance" or h(r.uid, "inspector-agent") % 7 != 0


def _coverage_row(r: Resource, e: EstateDay, day_start: datetime) -> dict[str, Any]:
    instance = r.table == "aws_ec2_instance"
    covered = _covered(r)
    return {
        "resource_id": r.native_id if instance else r.arn,
        "resource_type": "AWS_EC2_INSTANCE" if instance else "AWS_LAMBDA_FUNCTION",
        "scan_type": "PACKAGE",
        "scan_status_code": "ACTIVE" if covered else "INACTIVE",
        "scan_status_reason": "SUCCESSFUL" if covered else "UNMANAGED_EC2_INSTANCE",
        "last_scanned_at": (day_start.replace(hour=h(r.uid, "scan-hour") % 6)).isoformat()
        if covered
        else None,
        "source_account_id": e.account_id,
        "partition": "aws",
        "region": r.region,
        "account_id": e.account_id,
    }


def _resource(r: Resource, e: EstateDay) -> dict[str, Any]:
    if r.table == "aws_ec2_instance":
        return {
            "Type": "AWS_EC2_INSTANCE",
            "Id": r.native_id,
            "Partition": "aws",
            "Region": r.region,
            "Details": {"AwsEc2Instance": {"Type": r.attrs["instance_type"]}},
        }
    return {
        "Type": "AWS_LAMBDA_FUNCTION",
        # Inspector names the version it scanned; the inventory names the function.
        "Id": f"{r.arn}:$LATEST",
        "Partition": "aws",
        "Region": r.region,
        "Details": {"AwsLambdaFunction": {"FunctionName": r.name, "Runtime": r.attrs["runtime"]}},
    }


def _finding_row(
    r: Resource, e: EstateDay, kind: str, key: str, fields: dict[str, Any]
) -> dict[str, Any]:
    return {
        "arn": f"arn:aws:inspector2:{r.region}:{e.account_id}:finding/{hexid(32, r.uid, key)}",
        "finding_account_id": e.account_id,
        "status": "SUPPRESSED" if h(r.uid, key, "suppressed") % 11 == 0 else "ACTIVE",
        "type": kind,
        "resources": [_resource(r, e)],
        "partition": "aws",
        "region": r.region,
        "account_id": e.account_id,
        **fields,
    }


def _package_findings(r: Resource, e: EstateDay, dayno: int) -> list[dict[str, Any]]:
    rows = []
    for cve, severity, package, installed, fixed, cvss, epss, exploit in CATALOG:
        # Each (resource, CVE) is open on a window of days that repeats, so it resolves and
        # comes back over a long history.
        offset = h(r.uid, cve, "offset") % 200
        if (dayno + offset) % 200 >= SPAN_DAYS or h(r.uid, cve, "has") % 4 != 0:
            continue
        rows.append(
            _finding_row(
                r,
                e,
                "PACKAGE_VULNERABILITY",
                cve,
                {
                    "severity": severity,
                    "title": f"{cve} - {package}",
                    "description": f"A vulnerability in {package} ({cve}).",
                    "vulnerability_id": cve,
                    "exploit_available": "YES" if exploit else "NO",
                    "fix_available": "YES" if fixed else "NO",
                    "inspector_score": cvss,
                    "epss_score": epss,
                    "vulnerable_packages": [
                        {
                            "Name": package,
                            "Version": installed,
                            "FixedInVersion": fixed or "NotAvailable",
                            "PackageManager": "OS" if r.table == "aws_ec2_instance" else "PYTHON",
                        }
                    ],
                    "cvss": [
                        {"BaseScore": cvss, "Source": "NVD", "Version": "3.1"},
                    ],
                    "remediation_recommendation_text": (
                        f"Upgrade {package} to {fixed}." if fixed else "None provided"
                    ),
                    "remediation_recommendation_url": None,
                    "source_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                },
            )
        )
    return rows


def _other_findings(r: Resource, e: EstateDay) -> list[dict[str, Any]]:
    if r.table == "aws_lambda_function" and u(r.uid, "code-vuln") < 0.3:
        return [
            _finding_row(
                r,
                e,
                "CODE_VULNERABILITY",
                "code-log-injection",
                {
                    "severity": "MEDIUM",
                    "title": "CWE-117 - Log injection",
                    "description": "User input is written to the log without neutralisation.",
                    "vulnerability_id": None,
                    "exploit_available": None,
                    "fix_available": None,
                    "inspector_score": 5.3,
                    "remediation_recommendation_text": "Sanitise input before logging it.",
                },
            )
        ]
    if r.table == "aws_ec2_instance" and r.attrs.get("public_ip"):
        return [
            _finding_row(
                r,
                e,
                "NETWORK_REACHABILITY",
                "network-22",
                {"severity": "MEDIUM", "title": "Port 22 is reachable from an Internet Gateway"},
            )
        ]
    return []


def write(out_dir: Path, estate: EstateDay, *, keep_findings: bool = True) -> int:
    """Writes both tables; a throttled run loses the findings table (kept=False). Returns the
    number of rows written."""
    day_start = datetime.combine(estate.day, time(), tzinfo=UTC)
    dayno = day_number(estate.day)
    scanned = [
        r
        for table in ("aws_ec2_instance", "aws_lambda_function")
        for r in estate.resources.get(table, [])
    ]
    coverage = [_coverage_row(r, estate, day_start) for r in scanned]
    findings = [
        row
        for r in scanned
        if _covered(r)
        for row in (*_package_findings(r, estate, dayno), *_other_findings(r, estate))
    ]
    (out_dir / f"{COVERAGE_TABLE}.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in coverage)
    )
    if keep_findings:
        (out_dir / f"{FINDINGS_TABLE}.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in findings)
        )
    return len(coverage) + (len(findings) if keep_findings else 0)
