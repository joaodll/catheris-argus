"""The AWS Inspector adapter (ADR-0042): one AWS vulnerabilities run's Steampipe export ->
typed records. Pure.

On AWS the vulnerabilities tool reads Inspector, the scanner `aws-inspector`. Package and code
vulnerabilities become findings of the tool "vulnerabilities", with what a vulnerability adds
(the package and its fixed version, CVSS, EPSS, exploit and fix available) alongside. Network
reachability findings are left out: exposure is Argus's own verdict (the internet rules), and
two competing verdicts would confuse. They are counted in `skipped`.

The plugin fills `resource_id` and `resource_type` only from a query qualifier, so the
resource is read from the first entry of `resources`:
- an EC2 instance id, which ingest resolves with the region to the instance ARN;
- a Lambda function ARN without its version or alias, as the inventory names the function;
- an ECR image, attached to its repository (Argus has no image inventory); the image digest and
  tags are kept with the vulnerability.

Rows of another account (the export filters by account; this is the second line) are dropped
and counted. Inspector's text is redacted like any tool output. Files are read line by line: an
account can hold tens of thousands of open CVEs.
"""

import json
import math
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from argus.core.rawstore import RawRun
from argus.core.redaction import redact_text
from argus.findings.model import (
    SEVERITIES,
    CheckText,
    Coverage,
    FindingResult,
    Vulnerability,
    VulnerabilityBatch,
    VulnerabilityKind,
)

# The Steampipe export binary's version (plugin 1.34.0), the same pin as the inventory's.
SUPPORTED_VERSIONS = frozenset({"1.34.0"})
FINDINGS_FILE = "aws_inspector2_finding.jsonl"
COVERAGE_FILE = "aws_inspector2_coverage.jsonl"
SCANNER = "aws-inspector"
# Inspector's finding types and scan types -> the vulnerability kinds. Network reachability
# (a finding type and a scan type) is left out: exposure is Argus's own verdict.
_KINDS: dict[str, VulnerabilityKind] = {
    "PACKAGE_VULNERABILITY": "package",
    "CODE_VULNERABILITY": "code",
}
_SCAN_TYPES: dict[str, VulnerabilityKind] = {"PACKAGE": "package", "CODE": "code"}
MAX_TEXT = 20000
MAX_DETAIL = 4000
MAX_TITLE = 1000
MAX_ID = 200
_NEVER = datetime.min.replace(tzinfo=UTC)
# Inspector's resource types -> (service, resource type), in Prowler's vocabulary like every
# tool's filter columns (findings.model).
_RESOURCE_KINDS = {
    "AWS_EC2_INSTANCE": ("ec2", "AwsEc2Instance"),
    "AWS_LAMBDA_FUNCTION": ("lambda", "AwsLambdaFunction"),
    "AWS_ECR_CONTAINER_IMAGE": ("ecr", "AwsEcrRepository"),
    "AWS_ECR_REPOSITORY": ("ecr", "AwsEcrRepository"),
}


class UnsupportedVersionError(ValueError):
    pass


def _decode(value: Any) -> Any:
    """JSON columns may arrive as JSON text."""
    if isinstance(value, str) and value[:1] in ("[", "{"):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _get(obj: Any, name: str) -> Any:
    """A field of a nested AWS structure, whichever case the plugin serialised it in."""
    if not isinstance(obj, dict):
        return None
    if name in obj:
        return obj[name]
    return obj.get(name[:1].lower() + name[1:])


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return redact_text(value.strip())[:limit]


def _url(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith(("https://", "http://")) and len(value) < 2000:
        return value
    return None


def _number(value: Any, high: float) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0 <= number <= high else None


def _version(value: Any) -> str | None:
    """Inspector writes "NotAvailable" when no fixed version exists."""
    text = _text(value, MAX_ID)
    return None if text in (None, "NotAvailable") else text


def _cvss(entries: Any) -> float | None:
    """The NVD CVSS v3 base score when Inspector has one, else the highest it lists."""
    scores: list[tuple[bool, float]] = []
    for entry in entries if isinstance(entries, list) else []:
        score = _number(_get(entry, "BaseScore"), 10)
        if score is not None:
            preferred = str(_get(entry, "Source")).upper() == "NVD" and str(
                _get(entry, "Version")
            ).startswith("3")
            scores.append((preferred, score))
    if not scores:
        return None
    return max(scores)[1]


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _lambda_uid(arn: str) -> str:
    """arn:aws:lambda:<region>:<account>:function:<name>[:<version or alias>] -> the function."""
    return ":".join(arn.split(":")[:7])


def _repository_uid(image_id: str, details: Any) -> str | None:
    """arn:aws:ecr:<region>:<account>:repository/<name>/sha256:<digest> -> the repository. A
    repository name can hold slashes, so the image part is cut at its digest."""
    if not image_id.startswith("arn:"):
        return None
    head, _, path = image_id.partition(":repository/")
    if not path:
        return None
    name = _get(details, "RepositoryName")
    if not isinstance(name, str) or not name:
        name = path.rsplit("/sha256:", 1)[0]
    return f"{head}:repository/{name}"


def _resource(row: dict[str, Any]) -> tuple[str, str, Any] | None:
    """(resource uid or short id, Inspector's resource type, the resource's details)."""
    resources = _decode(row.get("resources"))
    first = resources[0] if isinstance(resources, list) and resources else None
    kind, rid = _get(first, "Type"), _get(first, "Id")
    if not isinstance(kind, str) or not isinstance(rid, str) or not rid:
        return None
    details = _get(first, "Details")
    if kind == "AWS_LAMBDA_FUNCTION" and rid.startswith("arn:"):
        return _lambda_uid(rid), kind, details
    if kind == "AWS_ECR_CONTAINER_IMAGE":
        repository = _repository_uid(rid, _get(details, "AwsEcrContainerImage"))
        return (repository, kind, details) if repository else None
    return rid, kind, details


def _image(kind: str, details: Any) -> tuple[str | None, tuple[str, ...]]:
    if kind != "AWS_ECR_CONTAINER_IMAGE":
        return None, ()
    image = _get(details, "AwsEcrContainerImage")
    digest = _get(image, "ImageHash")
    tags = _get(image, "ImageTags")
    return (
        digest if isinstance(digest, str) else None,
        tuple(t for t in tags if isinstance(t, str))[:20] if isinstance(tags, list) else (),
    )


def _rows(run: RawRun, name: str) -> Iterator[dict[str, Any]]:
    with run.path(name).open() as lines:
        for line in lines:
            if line.strip():
                yield json.loads(line)


def _finding(
    row: dict[str, Any], uid: str, resource: tuple[str, str, Any]
) -> tuple[FindingResult, Vulnerability, CheckText]:
    kind = _KINDS[row["type"]]
    title = _text(row.get("title"), MAX_TITLE) or uid
    cve = _text(row.get("vulnerability_id"), MAX_ID)
    check_id = cve if kind == "package" and cve else f"code:{title}"[:MAX_ID]
    resource_uid, resource_kind, details = resource
    service, resource_type = _RESOURCE_KINDS.get(resource_kind, (None, None))
    packages = _decode(row.get("vulnerable_packages"))
    package = packages[0] if isinstance(packages, list) and packages else None
    name, installed = _text(_get(package, "Name"), MAX_ID), _text(_get(package, "Version"), MAX_ID)
    fixed = _version(_get(package, "FixedInVersion"))
    digest, tags = _image(resource_kind, details)
    severity = str(row.get("severity") or "").lower()
    remediation = _text(row.get("remediation_recommendation_text"), MAX_TEXT)
    detail = None
    if name and installed:
        detail = f"{name} {installed} is affected" + (f"; fixed in {fixed}." if fixed else ".")
    result = FindingResult(
        finding_uid=uid,
        check_id=check_id,
        status="FAIL",
        muted=row.get("status") == "SUPPRESSED",
        severity=severity if severity in SEVERITIES else "informational",
        region=str(row.get("region") or "global"),
        resource_uid=resource_uid,
        title=title,
        remediation_text=remediation,
        remediation_url=_url(row.get("remediation_recommendation_url")),
        compliance={},
        service=service,
        resource_type=resource_type,
        categories=("vulnerability",),
        detail=detail[:MAX_DETAIL] if detail else None,
        resource_name=_get(_get(details, "AwsLambdaFunction"), "FunctionName"),
    )
    vulnerability = Vulnerability(
        kind=kind,
        vulnerability_id=cve if kind == "package" else None,
        package_name=name,
        package_manager=_text(_get(package, "PackageManager"), MAX_ID),
        installed_version=installed,
        fixed_version=fixed,
        cvss_score=_cvss(_decode(row.get("cvss"))),
        epss_score=_number(row.get("epss_score"), 1),
        scanner_score=_number(row.get("inspector_score"), 10),
        exploit_available=row.get("exploit_available") == "YES",
        fix_available=row.get("fix_available")
        if row.get("fix_available") in ("YES", "NO", "PARTIAL")
        else None,
        image_digest=digest,
        image_tags=tags,
        reference_url=_url(row.get("source_url")),
    )
    links = tuple(u for u in (_url(row.get("source_url")), result.remediation_url) if u)
    check = CheckText(
        check_id=check_id,
        description=_text(row.get("description"), MAX_TEXT),
        links=links,
        notes=remediation,
    )
    return result, vulnerability, check


def _coverage(row: dict[str, Any]) -> Coverage | None:
    rid, kind = row.get("resource_id"), row.get("resource_type")
    scan_type, status = _SCAN_TYPES.get(str(row.get("scan_type"))), row.get("scan_status_code")
    if scan_type is None or not (
        isinstance(rid, str) and isinstance(kind, str) and isinstance(status, str)
    ):
        return None
    if not (rid and status):
        return None
    if kind == "AWS_LAMBDA_FUNCTION" and rid.startswith("arn:"):
        uid: str | None = _lambda_uid(rid)
    elif kind == "AWS_ECR_CONTAINER_IMAGE":
        uid = _repository_uid(rid, {"RepositoryName": row.get("ecr_repository_name")})
    else:
        uid = rid
    if uid is None:
        return None
    reason = row.get("scan_status_reason")
    return Coverage(
        resource_uid=uid,
        region=str(row.get("region") or "global"),
        scan_type=scan_type,
        active=status == "ACTIVE",
        status_code=status,
        status_reason=reason if isinstance(reason, str) and reason else None,
        last_scanned_at=_timestamp(row.get("last_scanned_at")),
    )


def _merge(coverage: dict[tuple[str, str], Coverage], item: Coverage) -> None:
    """Several images of one repository: the repository is scanned when any image is, and was
    last scanned when its latest image was."""
    key = (item.resource_uid, item.scan_type)
    seen = coverage.get(key)
    if (
        seen is None
        or (not seen.active and item.active)
        or (
            item.active == seen.active
            and (item.last_scanned_at or _NEVER) > (seen.last_scanned_at or _NEVER)
        )
    ):
        coverage[key] = item


def _left_out(row: dict[str, Any], account: str) -> str | None:
    """Why a findings row is not a finding of this account, or None when it is one."""
    uid = row.get("arn")
    if not isinstance(uid, str) or not uid:
        return "no finding ARN"
    if row.get("finding_account_id") != account:
        return "another account"
    if row.get("status") == "CLOSED":
        return "closed"
    if row.get("type") not in _KINDS:
        return f"type {str(row.get('type'))[:40]}"
    return None


def parse_inspector(run: RawRun) -> VulnerabilityBatch:
    manifest = run.manifest
    if manifest.tool != "vulnerabilities" or manifest.provider != "aws":
        raise ValueError(f"not an AWS vulnerabilities run: {manifest.tool} {manifest.provider}")
    if manifest.tool_version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersionError(f"steampipe export {manifest.tool_version} not supported")
    files = {f.path for f in manifest.files}
    account = manifest.account_id
    skipped: dict[str, int] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    findings: list[FindingResult] = []
    vulnerabilities: dict[str, Vulnerability] = {}
    checks: dict[str, CheckText] = {}
    if FINDINGS_FILE in files:
        for row in _rows(run, FINDINGS_FILE):
            uid = str(row.get("arn"))
            if reason := _left_out(row, account):
                skip(reason)
            elif (resource := _resource(row)) is None:
                skip("no resource")
            elif uid not in vulnerabilities:
                result, vulnerability, check = _finding(row, uid, resource)
                findings.append(result)
                vulnerabilities[uid] = vulnerability
                checks.setdefault(check.check_id, check)
    coverage: dict[tuple[str, str], Coverage] = {}
    if COVERAGE_FILE in files:
        for row in _rows(run, COVERAGE_FILE):
            if row.get("source_account_id") not in (None, account):
                continue
            if item := _coverage(row):
                _merge(coverage, item)
    incomplete = set(manifest.incomplete_tables)
    return VulnerabilityBatch(
        scanner=SCANNER,
        findings=findings,
        vulnerabilities=vulnerabilities,
        checks=checks,
        coverage=list(coverage.values()),
        complete=manifest.status == "complete"
        and FINDINGS_FILE in files
        and "aws_inspector2_finding" not in incomplete,
        coverage_complete=manifest.status != "failed"
        and COVERAGE_FILE in files
        and "aws_inspector2_coverage" not in incomplete,
        tool_version=manifest.tool_version,
        skipped=skipped,
    )
