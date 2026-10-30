"""The Prowler adapter: OCSF findings and compliance CSVs -> typed records. Pure.

Only FAIL and MANUAL results become finding rows; PASS results are counted (they feed the
check-result metrics) and define which checks ran in which regions, which is the scope a
complete run may resolve findings in. Resource metadata embedded in OCSF is never kept, so the
secrets it can carry (for example Lambda environments) never reach Postgres.

Each check's own text (description, risk, links) comes from the OCSF file; its remediation code
only from the findings CSV, of which nothing else is read (RESOURCE_DETAILS can hold secrets).

Only the top-level OCSF file holds findings. Prowler also writes compliance/<stem>_<framework>
.ocsf.json for its universal frameworks (CIS Controls, CMMC, ...) whatever the output formats:
one item per finding and requirement, titled with the requirement id. Those are never read.
"""

import csv
import io
import json
import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from typing import Any

from argus.core.rawstore import RawRun
from argus.core.redaction import redact_text
from argus.findings.model import SEVERITIES, CheckText, FindingResult

SUPPORTED_VERSIONS = frozenset({"5.44.0", "5.45.0"})
# From 5.45.0 Prowler's CSV writers quote a cell a spreadsheet would read as a formula
# (prowler/lib/outputs/utils.py sanitize_csv_value), and the adapter reads the value Prowler
# meant. Listed: the versions that never quoted, so a later version unquotes by default.
CSV_UNQUOTED_VERSIONS = frozenset({"5.44.0"})
# Prowler's checks that call a resource exposed to the internet, read from the pinned Prowler in
# the worker image (the same list in 5.44.0 and 5.45.0). Each judges an instance, an RDS
# instance or a load balancer, every one a type Argus's internet rules judge too, so each
# finding carries Argus's own verdict (ADR-0035, sixth amendment). The security-group checks
# judge a group, not a door, and are not here.
EXPOSURE_CHECKS: tuple[str, ...] = (
    "ec2_instance_internet_facing_with_instance_profile",
    "ec2_instance_public_ip",
    *(
        f"ec2_instance_port_{name}_exposed_to_internet"
        for name in (
            "cassandra", "cifs", "elasticsearch_kibana", "ftp", "kafka", "kerberos", "ldap",
            "memcached", "mongodb", "mysql", "oracle", "postgresql", "rdp", "redis", "sqlserver",
            "ssh", "telnet",
        )
    ),
    "elb_internet_facing",
    "elbv2_internet_facing",
    "rds_instance_no_public_access",
)  # fmt: skip
_VERSION_RE = re.compile(r"_(\d+(?:\.\d+)+)_")
MAX_LINKS = 20
MAX_TEXT = 20000
MAX_DETAIL = 4000
# The findings CSV's remediation code columns -> CheckText fields.
_CODE_COLUMNS = {
    "REMEDIATION_CODE_CLI": "code_cli",
    "REMEDIATION_CODE_NATIVEIAC": "code_native_iac",
    "REMEDIATION_CODE_TERRAFORM": "code_terraform",
    "REMEDIATION_CODE_OTHER": "code_other",
}


class UnsupportedVersionError(ValueError):
    pass


@dataclass(frozen=True)
class RequirementResult:
    framework: str
    version: str
    requirement_id: str
    description: str
    title: str | None
    section: str | None
    level_of_risk: int | None
    weight: int | None
    status: int  # 1 FAIL, 2 MANUAL, 3 PASS
    passed: int
    failed: int


@dataclass(frozen=True)
class FrameworkInfo:
    """A compliance framework as Prowler names it in its CSV (FRAMEWORK, NAME columns)."""

    framework: str  # the key, from the file name: cis_6.0_aws
    version: str
    family: str | None  # CIS, ProwlerThreatScore, ...
    name: str | None  # CIS Amazon Web Services Foundations Benchmark v6.0.0


@dataclass
class ProwlerBatch:
    findings: list[FindingResult]
    executed: frozenset[tuple[str, str]]  # (check_id, region) pairs this run evaluated
    counts: Counter[tuple[str, str, bool]]  # (status_code, severity, muted) -> results
    requirements: list[RequirementResult]
    complete: bool
    checks: dict[str, CheckText] = field(default_factory=dict)  # by check id
    tool_version: str = ""
    frameworks: list[FrameworkInfo] = field(default_factory=list)


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def _unquote(value: str) -> str:
    """The cell as Prowler meant it, before its CSV writer prefixed "'" to stop a spreadsheet
    reading it as a formula: a tab or carriage return first, or "=", "+", "-" or "@" after leading
    spaces, unless the cell is a plain finite number. Only a prefix that rule would have added is
    removed. A value that itself began with that "'" reads the same, and cannot be told apart."""
    if not value.startswith("'"):
        return value
    rest = value[1:]
    if not (rest.startswith(("\t", "\r")) or rest.lstrip().startswith(("=", "+", "-", "@"))):
        return value
    try:
        number = float(rest)
    except ValueError:
        return rest
    return value if math.isfinite(number) and rest == rest.strip() else rest


def _rows(text: str, *, quoted: bool) -> Iterator[dict[str, str]]:
    """A Prowler CSV's rows, each cell as Prowler meant it."""
    for row in csv.DictReader(io.StringIO(text), delimiter=";"):
        yield (
            {k: _unquote(v) if isinstance(v, str) else v for k, v in row.items()} if quoted else row
        )


def _first(row: dict[str, str], *columns: str) -> str | None:
    """The first non-empty value among the columns; frameworks name the same idea differently."""
    return next((v.strip() for c in columns if (v := row.get(c) or "").strip()), None)


def _section(row: dict[str, str]) -> str | None:
    section = _first(row, "REQUIREMENTS_ATTRIBUTES_SECTION")
    if section:
        return section
    # MITRE ATT&CK has no section: its tactics ("Initial Access|Persistence") group it, and a
    # technique sits under its first tactic.
    tactics = _first(row, "REQUIREMENTS_TACTICS")
    if tactics:
        return re.split(r"\s*[|,]\s*", tactics)[0] or None
    return _first(row, "REQUIREMENTS_ATTRIBUTES_CATEGORY", "REQUIREMENTS_ATTRIBUTES_CATEGORIA")


def _requirements(
    name: str, text: str, *, quoted: bool
) -> tuple[FrameworkInfo, list[RequirementResult]]:
    version_match = _VERSION_RE.search(f"_{name}_")
    version = version_match.group(1) if version_match else ""
    grouped: dict[str, list[dict[str, str]]] = {}
    family = full_name = None
    for row in _rows(text, quoted=quoted):
        grouped.setdefault(row["REQUIREMENTS_ID"], []).append(row)
        family = family or (row.get("FRAMEWORK") or "").strip()[:200] or None
        full_name = full_name or (row.get("NAME") or "").strip()[:500] or None
    out = []
    for req_id, rows in grouped.items():
        statuses = Counter(r["STATUS"] for r in rows)
        passed, failed = statuses.get("PASS", 0), statuses.get("FAIL", 0)
        status = 1 if failed else (3 if passed else 2)
        first = rows[0]
        out.append(
            RequirementResult(
                framework=name,
                version=version,
                requirement_id=req_id,
                description=first.get("REQUIREMENTS_DESCRIPTION", ""),
                title=_first(
                    first,
                    "REQUIREMENTS_ATTRIBUTES_TITLE",
                    "REQUIREMENTS_NAME",
                    "REQUIREMENTS_ATTRIBUTES_NAME",
                ),
                section=_section(first),
                level_of_risk=_int(first.get("REQUIREMENTS_ATTRIBUTES_LEVELOFRISK")),
                weight=_int(first.get("REQUIREMENTS_ATTRIBUTES_WEIGHT")),
                status=status,
                passed=passed,
                failed=failed,
            )
        )
    return FrameworkInfo(name, version, family, full_name), out


def _text(value: object) -> str | None:
    return value[:MAX_TEXT] if isinstance(value, str) and value.strip() else None


def _links(*values: object) -> tuple[str, ...]:
    """The http(s) URLs among the values (strings or lists of strings), each once, in order."""
    found: list[str] = []
    for value in values:
        for url in value if isinstance(value, list) else [value]:
            if (
                isinstance(url, str)
                and url.startswith(("https://", "http://"))
                and len(url) <= 2000
                and url not in found
            ):
                found.append(url)
    return tuple(found[:MAX_LINKS])


def _check(item: dict[str, Any]) -> CheckText:
    info = item.get("finding_info", {})
    unmapped = item.get("unmapped", {})
    return CheckText(
        check_id=item["metadata"]["event_code"],
        description=_text(info.get("desc")),
        risk=_text(item.get("risk_details")),
        links=_links(
            item.get("remediation", {}).get("references") or [],
            unmapped.get("related_url"),
            unmapped.get("additional_urls") or [],
        ),
        notes=_text(unmapped.get("notes")),
    )


def _code(text: str, *, quoted: bool) -> dict[str, dict[str, str]]:
    """Each check's remediation code from the findings CSV. Only CHECK_ID and the code columns
    are read; every other column, the resource details among them, is skipped."""
    unquote = _unquote if quoted else str
    code: dict[str, dict[str, str]] = {}
    for row in csv.DictReader(io.StringIO(text), delimiter=";"):
        check_id = unquote(row.get("CHECK_ID") or "")
        if not check_id or check_id in code:
            continue
        code[check_id] = {
            name: unquote(value)[:MAX_TEXT]
            for column, name in _CODE_COLUMNS.items()
            if (value := row.get(column) or "").strip()
        }
    return code


def _with_code(check: CheckText, code: dict[str, str]) -> CheckText:
    return replace(
        check,
        code_cli=code.get("code_cli"),
        code_native_iac=code.get("code_native_iac"),
        code_terraform=code.get("code_terraform"),
        code_other=code.get("code_other"),
    )


def _finding(item: dict[str, Any]) -> FindingResult:
    resource = (item.get("resources") or [{}])[0]
    info = item.get("finding_info", {})
    references = item.get("remediation", {}).get("references") or []
    unmapped = item.get("unmapped", {})
    return FindingResult(
        finding_uid=info["uid"],
        check_id=item["metadata"]["event_code"],
        status=item["status_code"],
        muted=item.get("status") == "Suppressed",
        severity=str(item.get("severity", "informational")).lower(),
        region=resource.get("region") or item.get("cloud", {}).get("region") or "global",
        resource_uid=resource.get("uid", ""),
        title=info.get("title", ""),
        remediation_text=item.get("remediation", {}).get("desc"),
        remediation_url=references[0] if references else None,
        compliance=unmapped.get("compliance") or {},
        service=resource.get("group", {}).get("name") or info.get("analytic", {}).get("category"),
        resource_type=resource.get("type") or None,
        categories=tuple(unmapped.get("categories") or ()),
        # status_extended can quote what it found: redacted like any tool output.
        detail=redact_text(item["message"])[:MAX_DETAIL] if item.get("message") else None,
        resource_name=str(resource["name"])[:1000] if resource.get("name") else None,
    )


def parse_prowler(run: RawRun) -> ProwlerBatch:
    manifest = run.manifest
    if manifest.tool != "prowler":
        raise ValueError(f"not a prowler run: {manifest.tool}")
    if manifest.tool_version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersionError(f"prowler {manifest.tool_version} not supported")
    quoted = manifest.tool_version not in CSV_UNQUOTED_VERSIONS
    findings: list[FindingResult] = []
    executed: set[tuple[str, str]] = set()
    counts: Counter[tuple[str, str, bool]] = Counter()
    requirements: list[RequirementResult] = []
    frameworks: list[FrameworkInfo] = []
    checks: dict[str, CheckText] = {}
    code: dict[str, dict[str, str]] = {}
    for file in manifest.files:
        if "/" not in file.path and file.path.endswith(".ocsf.json"):
            for item in json.loads(run.path(file.path).read_text()):
                result = _finding(item)
                if result.check_id not in checks:
                    checks[result.check_id] = _check(item)
                executed.add((result.check_id, result.region))
                severity = result.severity if result.severity in SEVERITIES else "informational"
                counts[(item["status_code"], severity, result.muted)] += 1
                if item["status_code"] in ("FAIL", "MANUAL"):
                    findings.append(result)
        elif "/" not in file.path and file.path.endswith(".csv"):
            code.update(_code(run.path(file.path).read_text(), quoted=quoted))
        elif file.path.startswith("compliance/") and file.path.endswith(".csv"):
            # prowler-output-<account>-<timestamp>_<framework>.csv: the prefix holds no "_",
            # so the framework (cis_6.0_aws, prowler_threatscore_aws, ...) follows the first.
            stem = file.path.removeprefix("compliance/").removesuffix(".csv")
            if "_" not in stem:
                continue
            info, rows = _requirements(
                stem.split("_", 1)[1], run.path(file.path).read_text(), quoted=quoted
            )
            frameworks.append(info)
            requirements += rows
    return ProwlerBatch(
        findings=findings,
        executed=frozenset(executed),
        counts=counts,
        requirements=requirements,
        frameworks=frameworks,
        complete=manifest.status == "complete",
        tool_version=manifest.tool_version,
        checks={
            check_id: _with_code(check, code.get(check_id, {}))
            for check_id, check in checks.items()
        },
    )
