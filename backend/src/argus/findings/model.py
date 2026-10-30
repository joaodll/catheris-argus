"""Records every finding adapter produces, whatever the tool."""

from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low", "informational")


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
