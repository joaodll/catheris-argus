"""Synthetic Prowler 5.45.0 output: the OCSF findings file, the findings CSV and the compliance
CSVs.

Formats follow Prowler's own writers at 5.45.0:
- prowler/lib/outputs/ocsf/ocsf.py: a JSON array of DetectionFinding objects, dumped with
  exclude_none and indent=4.
- prowler/lib/outputs/finding.py: finding uid = prowler-{provider}-{check}-{account}-{region}-
  {resource_name}.
- prowler/lib/outputs/utils.py sanitize_csv_value (5.45.0): every CSV cell a spreadsheet would
  read as a formula is prefixed with "'" (_QuotingWriter below).
- prowler/lib/outputs/csv/csv.py: csv.DictWriter, delimiter ";", one row per result, the
  columns below in Prowler's order. The remediation code (CLI, CloudFormation, Terraform,
  console steps) is only in this file: the OCSF file carries the recommendation URL alone.
- prowler/lib/outputs/compliance/{cis,prowler_threatscore}/: csv.DictWriter, delimiter ";",
  headers are the model field names upper-cased, one row per requirement and finding.
- prowler/lib/outputs/compliance/universal/ocsf_compliance.py: compliance/<stem>_<framework>
  .ocsf.json, written for every universal framework whatever the output formats. One
  ComplianceFinding per finding and requirement (uid <finding uid>-<requirement id>, title the
  requirement id) and one "manual-<id>" item per requirement without checks. Here over the CIS
  requirements of the catalog, so the adapter is proven to read none of it as findings.

Check ids, titles, severities and framework mappings come from the vendored catalog (real
Prowler data, see catalog/NOTICE). Results are consistent with the estate's configuration
where a check has an obvious counterpart (open ports, IMDSv2, public URLs, public databases);
everything else fails at a severity-weighted rate that improves with the estate's posture.
"""

import csv
import io
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime, time
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from argus.collection.synthetic.estate import (
    REGRESSION_CHECK,
    Estate,
    EstateDay,
    regression_bucket,
)
from argus.collection.synthetic.model import Resource, u

TOOL_VERSION = "5.45.0"
FRAMEWORKS = ("cis_6.0_aws", "prowler_threatscore_aws")
SEVERITY_ID = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
BASE_FAIL_RATE = {
    "critical": 0.12,
    "high": 0.22,
    "medium": 0.30,
    "low": 0.35,
    "informational": 0.20,
}

# Prowler resource type -> the Steampipe table holding those resources in the estate.
RESOURCE_TABLES = {
    "AwsEc2Instance": ("aws_ec2_instance",),
    "AwsEc2SecurityGroup": ("aws_vpc_security_group",),
    "AwsS3Bucket": ("aws_s3_bucket",),
    "AwsRdsDbInstance": ("aws_rds_db_instance",),
    "AwsLambdaFunction": ("aws_lambda_function",),
    "AwsIamRole": ("aws_iam_role",),
    "AwsElbv2LoadBalancer": ("aws_ec2_application_load_balancer", "aws_ec2_network_load_balancer"),
    "AwsEc2Vpc": ("aws_vpc",),
}
GLOBAL_SERVICES = frozenset({"iam", "account", "organizations", "s3", "trustedadvisor"})
# On AWS, Prowler's resource_name (and so the finding uid) is the check's resource_id: the
# service model's id where it has one, its name otherwise (finding.py: resource_name =
# check_output.resource_id). An instance's replacement reuses its Name tag, not its id, so it
# never inherits the old instance's findings.
NAMED_BY_ID = frozenset({"aws_ec2_instance", "aws_vpc_security_group"})
EXPOSED_PORTS = {
    "ec2_instance_port_ssh_exposed_to_internet": 22,
    "ec2_instance_port_rdp_exposed_to_internet": 3389,
    "ec2_instance_port_postgresql_exposed_to_internet": 5432,
}


@cache
def catalog() -> dict[str, Any]:
    text = resources.files("argus.collection.synthetic") / "catalog/prowler_aws_5.45.0.json"
    data: dict[str, Any] = json.loads(text.read_text())
    return data


@cache
def manual_checks() -> frozenset[str]:
    """Checks Prowler reports as MANUAL: every CIS requirement using them is manual."""
    by_check: dict[str, list[str]] = {}
    for req in catalog()["frameworks"]["cis_6.0_aws"]["requirements"]:
        for check in req["checks"]:
            by_check.setdefault(check, []).append(req["attributes"].get("AssessmentStatus", ""))
    return frozenset(c for c, statuses in by_check.items() if all(s == "Manual" for s in statuses))


@cache
def compliance_by_check() -> dict[str, dict[str, list[str]]]:
    """check -> {"CIS-6.0": [requirement ids], ...}, as Prowler's finding.compliance holds it."""
    out: dict[str, dict[str, list[str]]] = {}
    for fw in catalog()["frameworks"].values():
        key = f"{fw['framework']}-{fw['version']}"
        for req in fw["requirements"]:
            for check in req["checks"]:
                out.setdefault(check, {}).setdefault(key, []).append(req["id"])
    return out


@dataclass(frozen=True)
class Result:
    check_id: str
    status: str  # PASS | FAIL | MANUAL
    muted: bool
    region: str
    resource_uid: str
    resource_name: str
    resource_type: str
    metadata: dict[str, Any]
    tags: dict[str, str]

    @property
    def uid(self) -> str:
        return (
            f"prowler-aws-{self.check_id}-{self.metadata['account_id']}-{self.region}-"
            f"{self.resource_name}"
        )


def _targets(
    check: dict[str, Any], estate: EstateDay
) -> list[tuple[str, str, str, dict[str, Any]]]:
    """(region, resource uid, resource name, metadata) for every resource a check evaluates."""
    tables = RESOURCE_TABLES.get(check["resource_type"])
    if tables:
        found = []
        for table in tables:
            for r in estate.resources.get(table, []):
                region = r.attrs.get("bucket_region", r.region)
                region = estate.profile.regions[0] if region == "global" else region
                name = r.native_id if r.table in NAMED_BY_ID else r.name
                found.append((region, r.uid, name, _metadata(r)))
        return found
    # Account- and service-level checks: one result per region, or once for global services.
    regions = (
        (estate.profile.regions[0],)
        if check["service"] in GLOBAL_SERVICES
        else estate.profile.regions
    )
    if check["service"] in ("iam", "account", "organizations"):
        return [(regions[0], f"arn:aws:iam::{estate.account_id}:root", estate.account_id, {})]
    return [
        (
            region,
            f"arn:aws:{check['service']}:{region}:{estate.account_id}:account",
            f"{check['service']}-{region}",
            {},
        )
        for region in regions
    ]


def _metadata(r: Resource) -> dict[str, Any]:
    """A small slice of the resource object Prowler embeds in resources[].data.metadata."""
    if r.table == "aws_lambda_function":
        # Real Prowler includes the function's environment here: redaction must handle it.
        return {
            "name": r.name,
            "arn": r.arn,
            "runtime": r.attrs["runtime"],
            "environment": {"Variables": r.attrs["environment"]},
        }
    if r.table == "aws_ec2_instance":
        return {
            "id": r.native_id,
            "arn": r.arn,
            "public_ip": r.attrs["public_ip"],
            "security_groups": r.attrs["security_groups"],
        }
    return {"name": r.name, "arn": r.arn}


def _consistent_status(
    check_id: str, resource: Resource | None, groups: dict[str, Resource]
) -> str | None:
    """PASS/FAIL dictated by the estate's configuration, or None when the check has no
    counterpart in it."""
    if resource is None:
        return None
    if check_id in EXPOSED_PORTS and resource.table == "aws_ec2_instance":
        port = EXPOSED_PORTS[check_id]
        exposed = resource.attrs["public_ip"] and any(
            rule.get("cidr") == "0.0.0.0/0" and rule["from_port"] <= port <= rule["to_port"]
            for gid in resource.attrs["security_groups"]
            if gid in groups
            for rule in groups[gid].attrs["ingress"]
        )
        return "FAIL" if exposed else "PASS"
    if check_id == "ec2_instance_imdsv2_enabled" and resource.table == "aws_ec2_instance":
        return "PASS" if resource.attrs["imdsv2"] else "FAIL"
    if check_id == "awslambda_function_url_public":
        return "FAIL" if resource.attrs.get("public_url") else "PASS"
    if check_id == "rds_instance_no_public_access":
        return "FAIL" if resource.attrs.get("public") else "PASS"
    if check_id == "rds_instance_storage_encrypted":
        return "PASS" if resource.attrs.get("encrypted") else "FAIL"
    return None


def evaluate(estate: EstateDay, model: Estate) -> list[Result]:
    results: list[Result] = []
    posture = Estate.posture(estate.day)
    dayno = (estate.day - datetime(2020, 1, 1).date()).days
    manual = manual_checks()
    by_uid = {r.uid: r for r in estate.all()}
    groups = {g.native_id: g for g in estate.resources["aws_vpc_security_group"]}
    for check_id, check in sorted(catalog()["checks"].items()):
        for region, uid, name, metadata in _targets(check, estate):
            if check_id in manual:
                status = "MANUAL"
            elif check_id == REGRESSION_CHECK and name == regression_bucket(estate.account_id):
                status = "FAIL" if model.regression_failing(estate.day) else "PASS"
            else:
                status = _consistent_status(check_id, by_uid.get(uid), groups) or ""
                if not status:
                    # Stable within a window, so findings persist for days to weeks.
                    width = 20 + int(u(uid, check_id, "w") * 70)
                    window = (dayno + int(u(uid, check_id, "p") * width)) // width
                    rate = BASE_FAIL_RATE[check["severity"]] * posture
                    status = "FAIL" if u(uid, check_id, window) < rate else "PASS"
            muted = status == "FAIL" and u(uid, check_id, "mute") < 0.02
            results.append(
                Result(
                    check_id,
                    status,
                    muted,
                    region,
                    uid,
                    name,
                    check["resource_type"],
                    {**metadata, "account_id": estate.account_id},
                    {},
                )
            )
    return results


def _extended(check: dict[str, Any], result: Result) -> str:
    """Prowler's status_extended: what this result says about this resource."""
    return (
        f"{check['title']}: {result.resource_name} "
        f"{'passes' if result.status == 'PASS' else 'does not pass'} this check."
    )


def _ocsf(result: Result, estate: EstateDay, scan_time: datetime, scan_id: str) -> dict[str, Any]:
    check = catalog()["checks"][result.check_id]
    severity = check["severity"]
    extended = _extended(check, result)
    epoch = int(scan_time.timestamp())
    metadata = {k: v for k, v in result.metadata.items() if k != "account_id"}
    finding: dict[str, Any] = {
        "message": extended,
        "metadata": {
            "event_code": result.check_id,
            "product": {
                "name": "Prowler",
                "uid": "prowler",
                "vendor_name": "Prowler",
                "version": TOOL_VERSION,
            },
            "profiles": ["cloud", "datetime"],
            "version": "1.5.0",
        },
        "severity_id": SEVERITY_ID[severity],
        "severity": severity.capitalize(),
        "status": "Suppressed" if result.muted else "New",
        "status_code": result.status,
        "status_detail": extended,
        "status_id": 3 if result.muted else 1,
        "unmapped": {
            "related_url": check["related_url"],
            "categories": check["categories"],
            "depends_on": [],
            "related_to": [],
            "additional_urls": check["additional_urls"],
            "notes": check["notes"],
            "compliance": compliance_by_check().get(result.check_id, {}),
            "scan_id": scan_id,
            "provider_uid": estate.account_id,
            "provider": "aws",
        },
        "activity_name": "Create",
        "activity_id": 1,
        "finding_info": {
            "analytic": {
                "category": check["service"],
                "name": check["title"],
                "type": "Rule",
                "type_id": 1,
                "uid": result.check_id,
            },
            "created_time": epoch,
            "created_time_dt": scan_time.isoformat(),
            "desc": check["description"],
            "name": result.resource_name,
            "title": check["title"],
            "types": check["check_type"],
            "uid": result.uid,
        },
        "resources": [
            {
                "cloud_partition": "aws",
                "region": result.region,
                "data": {"details": "", "metadata": metadata},
                "group": {"name": check["service"]},
                "labels": [f"{k}:{v}" for k, v in result.tags.items()],
                "name": result.resource_name,
                "type": result.resource_type,
                "uid": result.resource_uid,
            }
        ],
        "category_name": "Findings",
        "category_uid": 2,
        "class_name": "Detection Finding",
        "class_uid": 2004,
        "cloud": {
            "account": {
                "type": "AWS Account",
                "type_id": 10,
                "uid": estate.account_id,
                "labels": [],
            },
            "provider": "aws",
            "region": result.region,
        },
        "remediation": {
            "desc": check["remediation_text"],
            "references": [check["remediation_url"]] if check["remediation_url"] else [],
        },
        "risk_details": check["risk"],
        "time": epoch,
        "time_dt": scan_time.isoformat(),
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
    }
    return finding


# prowler/lib/outputs/csv/csv.py at 5.45.0 (unchanged since 5.44.0), in order.
FINDINGS_CSV_COLUMNS = (
    "AUTH_METHOD",
    "TIMESTAMP",
    "ACCOUNT_UID",
    "ACCOUNT_NAME",
    "ACCOUNT_EMAIL",
    "ACCOUNT_ORGANIZATION_UID",
    "ACCOUNT_ORGANIZATION_NAME",
    "ACCOUNT_TAGS",
    "FINDING_UID",
    "PROVIDER",
    "CHECK_ID",
    "CHECK_TITLE",
    "CHECK_TYPE",
    "STATUS",
    "STATUS_EXTENDED",
    "MUTED",
    "SERVICE_NAME",
    "SUBSERVICE_NAME",
    "SEVERITY",
    "RESOURCE_TYPE",
    "RESOURCE_UID",
    "RESOURCE_NAME",
    "RESOURCE_DETAILS",
    "RESOURCE_TAGS",
    "PARTITION",
    "REGION",
    "DESCRIPTION",
    "RISK",
    "RELATED_URL",
    "REMEDIATION_RECOMMENDATION_TEXT",
    "REMEDIATION_RECOMMENDATION_URL",
    "REMEDIATION_CODE_NATIVEIAC",
    "REMEDIATION_CODE_TERRAFORM",
    "REMEDIATION_CODE_CLI",
    "REMEDIATION_CODE_OTHER",
    "COMPLIANCE",
    "CATEGORIES",
    "DEPENDS_ON",
    "RELATED_TO",
    "NOTES",
    "PROWLER_VERSION",
    "ADDITIONAL_URLS",
    "ACCOUNT_OU_UID",
    "ACCOUNT_OU_NAME",
)


def _sanitize_csv_value(value: Any) -> Any:
    """Prowler 5.45.0's sanitize_csv_value (prowler/lib/outputs/utils.py), as it writes it."""
    if not isinstance(value, str) or not (
        value.startswith(("\t", "\r")) or value.lstrip().startswith(("=", "+", "-", "@"))
    ):
        return value
    try:
        number = float(value)
    except ValueError:
        return f"'{value}"
    if math.isfinite(number) and value == value.strip():
        return value
    return f"'{value}"


class _QuotingWriter(csv.DictWriter):  # type: ignore[type-arg]
    """csv.DictWriter as Prowler 5.45.0's CSV writers use it: every cell sanitized."""

    def writerow(self, rowdict: Any) -> Any:
        return super().writerow({k: _sanitize_csv_value(v) for k, v in rowdict.items()})


def _findings_csv(results: list[Result], estate: EstateDay, scan_time: datetime) -> str:
    buffer = io.StringIO()
    writer = _QuotingWriter(buffer, fieldnames=FINDINGS_CSV_COLUMNS, delimiter=";")
    writer.writeheader()
    for r in results:
        check = catalog()["checks"][r.check_id]
        code = check["remediation_code"]
        writer.writerow(
            {
                "AUTH_METHOD": "profile: argus",
                "TIMESTAMP": scan_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                "ACCOUNT_UID": estate.account_id,
                "FINDING_UID": r.uid,
                "PROVIDER": "aws",
                "CHECK_ID": r.check_id,
                "CHECK_TITLE": check["title"],
                "CHECK_TYPE": " | ".join(check["check_type"]),
                "STATUS": r.status,
                "STATUS_EXTENDED": _extended(check, r),
                "MUTED": r.muted,
                "SERVICE_NAME": check["service"],
                "SEVERITY": check["severity"],
                "RESOURCE_TYPE": r.resource_type,
                "RESOURCE_UID": r.resource_uid,
                "RESOURCE_NAME": r.resource_name,
                "RESOURCE_TAGS": " | ".join(f"{k}={v}" for k, v in r.tags.items()),
                "PARTITION": "aws",
                "REGION": r.region,
                "DESCRIPTION": check["description"],
                "RISK": check["risk"],
                "RELATED_URL": check["related_url"],
                "REMEDIATION_RECOMMENDATION_TEXT": check["remediation_text"],
                "REMEDIATION_RECOMMENDATION_URL": check["remediation_url"],
                "REMEDIATION_CODE_NATIVEIAC": code["native_iac"],
                "REMEDIATION_CODE_TERRAFORM": code["terraform"],
                "REMEDIATION_CODE_CLI": code["cli"],
                "REMEDIATION_CODE_OTHER": code["other"],
                "CATEGORIES": " | ".join(check["categories"]),
                "NOTES": check["notes"],
                "PROWLER_VERSION": TOOL_VERSION,
                "ADDITIONAL_URLS": " | ".join(check["additional_urls"]),
            }
        )
    return buffer.getvalue()


CIS_COLUMNS = (
    "PROVIDER",
    "DESCRIPTION",
    "ACCOUNTID",
    "REGION",
    "ASSESSMENTDATE",
    "REQUIREMENTS_ID",
    "REQUIREMENTS_DESCRIPTION",
    "REQUIREMENTS_ATTRIBUTES_SECTION",
    "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
    "REQUIREMENTS_ATTRIBUTES_PROFILE",
    "REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS",
    "REQUIREMENTS_ATTRIBUTES_DESCRIPTION",
    "REQUIREMENTS_ATTRIBUTES_RATIONALESTATEMENT",
    "REQUIREMENTS_ATTRIBUTES_IMPACTSTATEMENT",
    "REQUIREMENTS_ATTRIBUTES_REMEDIATIONPROCEDURE",
    "REQUIREMENTS_ATTRIBUTES_AUDITPROCEDURE",
    "REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION",
    "REQUIREMENTS_ATTRIBUTES_DEFAULTVALUE",
    "REQUIREMENTS_ATTRIBUTES_REFERENCES",
    "STATUS",
    "STATUSEXTENDED",
    "RESOURCEID",
    "RESOURCENAME",
    "CHECKID",
    "MUTED",
    "FRAMEWORK",
    "NAME",
)
THREATSCORE_COLUMNS = (
    "PROVIDER",
    "DESCRIPTION",
    "ACCOUNTID",
    "REGION",
    "ASSESSMENTDATE",
    "REQUIREMENTS_ID",
    "REQUIREMENTS_DESCRIPTION",
    "REQUIREMENTS_ATTRIBUTES_TITLE",
    "REQUIREMENTS_ATTRIBUTES_SECTION",
    "REQUIREMENTS_ATTRIBUTES_SUBSECTION",
    "REQUIREMENTS_ATTRIBUTES_ATTRIBUTEDESCRIPTION",
    "REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION",
    "REQUIREMENTS_ATTRIBUTES_LEVELOFRISK",
    "REQUIREMENTS_ATTRIBUTES_WEIGHT",
    "STATUS",
    "STATUSEXTENDED",
    "RESOURCEID",
    "RESOURCENAME",
    "CHECKID",
    "MUTED",
    "FRAMEWORK",
    "NAME",
)


def _compliance_csv(name: str, results: list[Result], account_id: str, scan_time: datetime) -> str:
    fw = catalog()["frameworks"][name]
    columns = CIS_COLUMNS if name.startswith("cis_") else THREATSCORE_COLUMNS
    by_check: dict[str, list[Result]] = {}
    for r in results:
        by_check.setdefault(r.check_id, []).append(r)
    buffer = io.StringIO()
    writer = _QuotingWriter(buffer, fieldnames=columns, delimiter=";", lineterminator="\r\n")
    writer.writeheader()
    for req in fw["requirements"]:
        attrs = req["attributes"]
        base = {
            "PROVIDER": "aws",
            "DESCRIPTION": fw["description"],
            "ACCOUNTID": account_id,
            "ASSESSMENTDATE": scan_time.isoformat(),
            "REQUIREMENTS_ID": req["id"],
            "REQUIREMENTS_DESCRIPTION": req["description"],
            "FRAMEWORK": fw["framework"],
            "NAME": fw["name"],
        }
        for key, value in attrs.items():
            column = f"REQUIREMENTS_ATTRIBUTES_{key.upper()}"
            if column in columns:
                base[column] = value if not isinstance(value, list) else ", ".join(value)
        rows = [r for check in req["checks"] for r in by_check.get(check, [])]
        if not rows:
            writer.writerow(
                {
                    **base,
                    "REGION": "",
                    "STATUS": "MANUAL",
                    "STATUSEXTENDED": "Manual check",
                    "RESOURCEID": "manual_check",
                    "RESOURCENAME": "Manual check",
                    "CHECKID": "manual",
                    "MUTED": False,
                }
            )
            continue
        for r in rows:
            writer.writerow(
                {
                    **base,
                    "REGION": r.region,
                    "STATUS": r.status,
                    "STATUSEXTENDED": f"{r.resource_name}: {r.status}",
                    "RESOURCEID": r.resource_uid,
                    "RESOURCENAME": r.resource_name,
                    "CHECKID": r.check_id,
                    "MUTED": r.muted,
                }
            )
    return buffer.getvalue()


def _compliance_ocsf(name: str, results: list[Result], scan_time: datetime) -> str:
    by_check: dict[str, list[Result]] = {}
    for r in results:
        by_check.setdefault(r.check_id, []).append(r)
    items: list[dict[str, Any]] = []
    for req in catalog()["frameworks"][name]["requirements"]:
        rows = [r for check in req["checks"] for r in by_check.get(check, [])]
        info = {"desc": req["description"], "title": req["id"]}
        if not rows:
            items.append(
                {
                    "finding_info": {**info, "uid": f"manual-{req['id']}"},
                    "metadata": {"event_code": "manual"},
                    "status_code": "MANUAL",
                    "time_dt": scan_time.isoformat(),
                }
            )
        for r in rows:
            items.append(
                {
                    "finding_info": {**info, "uid": f"{r.uid}-{req['id']}"},
                    "metadata": {"event_code": r.check_id},
                    "status_code": r.status,
                    "resources": [{"region": r.region, "uid": r.resource_uid}],
                    "time_dt": scan_time.isoformat(),
                }
            )
    return json.dumps(items, indent=4)


def write(
    out_dir: Path,
    estate: EstateDay,
    model: Estate,
    scan_time: datetime,
    scan_id: str,
    *,
    drop_share: float,
    failed: bool,
) -> int:
    """Writes the OCSF file, the findings CSV, both compliance CSVs and one compliance OCSF
    file. drop_share removes that share of checks (what throttling does to a real run);
    failed leaves the OCSF array unterminated, as when the process is killed mid-write.
    Returns the number of findings written."""
    results = evaluate(estate, model)
    if drop_share:
        results = [
            r for r in results if u(estate.account_id, estate.day, r.check_id, "drop") >= drop_share
        ]
    stamp = scan_time.strftime("%Y%m%d%H%M%S")
    stem = f"prowler-output-{estate.account_id}-{stamp}"
    body = ",".join(json.dumps(_ocsf(r, estate, scan_time, scan_id), indent=4) for r in results)
    ocsf = f"[{body}]"
    if failed:
        ocsf = ocsf[: len(ocsf) // 3]
    (out_dir / f"{stem}.ocsf.json").write_text(ocsf)
    if not failed:
        (out_dir / f"{stem}.csv").write_text(_findings_csv(results, estate, scan_time))
        (out_dir / "compliance").mkdir()
        for name in FRAMEWORKS:
            (out_dir / "compliance" / f"{stem}_{name}.csv").write_text(
                _compliance_csv(name, results, estate.account_id, scan_time)
            )
        (out_dir / "compliance" / f"{stem}_{FRAMEWORKS[0]}.ocsf.json").write_text(
            _compliance_ocsf(FRAMEWORKS[0], results, scan_time)
        )
    return len(results)


def scan_time_for(estate: EstateDay, minute_offset: int) -> datetime:
    return datetime.combine(estate.day, time(2, 0), tzinfo=UTC).replace(minute=minute_offset % 60)
