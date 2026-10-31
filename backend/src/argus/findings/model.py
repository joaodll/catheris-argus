"""Records every finding adapter produces, whatever the tool."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

SEVERITIES = ("critical", "high", "medium", "low", "informational")
# The provider-neutral vulnerabilities collector (ADR-0042, amended 2026-10-31): its findings
# are CVEs, counted apart from Prowler's and CloudFox's.
VULNERABILITY_TOOL = "vulnerabilities"


@dataclass(frozen=True)
class FindingResult:
    finding_uid: str
    check_id: str
    status: str  # FAIL | MANUAL
    muted: bool
    severity: str
    region: str
    resource_uid: str
    title: str
    remediation_text: str | None
    remediation_url: str | None
    compliance: dict[str, list[str]]
    # Filter columns, in Prowler's vocabulary for every tool (service "awslambda", resource
    # type "AwsLambdaFunction", categories "secrets"); None or empty when the tool gives none.
    service: str | None = None
    resource_type: str | None = None
    categories: tuple[str, ...] = ()
    # What the tool says about this resource (Prowler's status_extended), redacted; and the name
    # it reported for the resource, shown when the resource is not in the inventory.
    detail: str | None = None
    resource_name: str | None = None


@dataclass(frozen=True)
class CheckText:
    """What a tool says about one of its checks, the same for every result of it. `links` are
    http(s) URLs only; the code is remediation a human may apply, never run by Argus."""

    check_id: str
    description: str | None = None
    risk: str | None = None
    links: tuple[str, ...] = ()
    code_cli: str | None = None
    code_native_iac: str | None = None
    code_terraform: str | None = None
    code_other: str | None = None
    notes: str | None = None


VulnerabilityKind = Literal["package", "code"]


@dataclass(frozen=True)
class Vulnerability:
    """What a vulnerability finding adds to a finding (finding_vulnerability), whichever
    provider's scanner reported it."""

    kind: VulnerabilityKind
    vulnerability_id: str | None  # the CVE; None for a code vulnerability
    package_name: str | None = None
    package_manager: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    scanner_score: float | None = None  # the scanner's own 0-10 score, when it has one
    exploit_available: bool = False
    fix_available: str | None = None  # YES | NO | PARTIAL
    image_digest: str | None = None
    image_tags: tuple[str, ...] = ()
    reference_url: str | None = None


@dataclass(frozen=True)
class Coverage:
    """Whether the scanner scans one resource, for one scan type (vulnerability_coverage).
    `active` is the scanner adapter's verdict; the status words stay the scanner's own."""

    resource_uid: str
    region: str
    scan_type: VulnerabilityKind
    active: bool
    status_code: str
    status_reason: str | None
    last_scanned_at: datetime | None


@dataclass
class VulnerabilityBatch:
    """One vulnerabilities run, parsed by its provider's scanner adapter."""

    scanner: str  # aws-inspector
    findings: list[FindingResult]
    vulnerabilities: dict[str, Vulnerability]  # by finding_uid
    checks: dict[str, CheckText]
    coverage: list[Coverage]
    # Resolves only when the findings table is complete; replaces coverage only when the
    # coverage table is.
    complete: bool
    coverage_complete: bool
    tool_version: str
    skipped: dict[str, int] = field(default_factory=dict)
