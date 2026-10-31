"""Investigate -> Findings: Prowler checks, CloudFox attacker findings and the vulnerabilities
tool's CVEs (ADR-0042) in one list. Read-only: changing a finding's state waits for roles."""

from datetime import date
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from argus import findings, ingest, inventory
from argus.api.deps import Db, Viewer
from argus.api.types import Provider
from argus.core.db import SEARCH_COUNT_CAP

router = APIRouter(tags=["findings"])

TOOLS = ["prowler", "cloudfox", "vulnerabilities"]


class VulnerabilityOut(BaseModel):
    """What a vulnerability finding adds (ADR-0042): the vulnerable package and its fix. A code
    vulnerability has no CVE and no package."""

    scanner: str  # the provider's scanner that reported it (aws-inspector)
    kind: Literal["package", "code"]
    vulnerability_id: str | None  # the CVE
    package_name: str | None
    package_manager: str | None
    installed_version: str | None
    fixed_version: str | None  # null: no fixed version yet
    cvss_score: float | None
    epss_score: float | None  # 0 to 1: the chance of exploitation in the next 30 days
    scanner_score: float | None  # the scanner's own 0-10 score, when it has one
    exploit_available: bool
    fix_available: Literal["YES", "NO", "PARTIAL"] | None
    image_digest: str | None  # a container finding's image (it is shown on its repository)
    image_tags: list[str]
    reference_url: str | None  # http(s) only


class FindingOut(BaseModel):
    id: int
    finding_uid: str
    tool: str
    check_id: str
    connection_id: int
    connection: str
    # The cloud of the finding's connection.
    provider: Provider
    region: str
    resource_uid: str
    # The resource in the inventory; null when the uid matches none ("Not in inventory").
    resource_id: int | None
    # Its name in the inventory (or native id when it has none); when it is not in the
    # inventory, the name the tool reported; null when neither is known.
    resource_name: str | None
    severity: str
    status: str
    muted: bool
    title: str
    remediation_text: str | None
    remediation_url: str | None
    # Prowler's names, for CloudFox findings too; null or empty on a finding not rescanned
    # since these were added (2026-10-07).
    service: str | None
    resource_type: str | None
    categories: list[str]
    state: str
    # CloudFox's public endpoints and Prowler's exposure checks (ADR-0035, sixth amendment):
    # what Argus's internet rules say about the resource. confirmed: traffic can arrive;
    # restricted: security groups, routing, a network ACL, auth or an address list keep the
    # internet out, or (Prowler) the rules judged it and found no way in; unknown: data the
    # verdict needs is missing; not_covered: no rule judges it. Null on every other finding.
    reach: findings.FindingReach | None
    # Why, as a code: the door's reason (not_running, nacl_blocks, no_internet_route,
    # no_public_address, sg_no_public_source, cidr_allowlist, iam_auth), for an unknown door
    # inspection_route or missing_data; with no door, no_door or not_in_inventory. Null when
    # the door gives none (a confirmed door) and on every finding without a reach.
    reach_reason: str | None
    first_seen: date
    last_seen: date
    resolved_on: date | None
    # Vulnerability findings only; null on every other tool's.
    vulnerability: VulnerabilityOut | None = None
    # What the tool says about this resource: Prowler's status_extended ("Root account does
    # not have a hardware MFA device enabled"). Null or empty when the tool gives none, or for
    # a finding not rescanned since 2026-10-07.
    detail: str | None = None


class RemediationCode(BaseModel):
    """Remediation a human may apply, as the tool wrote it. Argus never runs it."""

    cli: str | None
    native_iac: str | None  # CloudFormation, as Prowler's NativeIaC
    terraform: str | None
    other: str | None  # console steps


class CommandOut(BaseModel):
    """A CloudFox loot command shown on this resource (ADR-0038). Argus never runs it."""

    label: Literal["check", "reads_data", "acts_on_target"]
    command: str
    note: str | None
    source: str


class FindingDetail(FindingOut):
    """One finding with what the tool says about it: about the check, the same for each of its
    findings (`detail`, about this resource, is in the list too)."""

    description: str | None
    risk: str | None
    links: list[str]  # http(s) only
    # CloudFox's loot commands for this finding's resource; empty for a resource with none.
    commands: list[CommandOut]
    remediation_code: RemediationCode
    notes: str | None


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int  # findings matching the filters, for the page count
    # True when a text search matched more than `total` (the count stops at 10,000): the UI
    # says "10,000+ records".
    total_capped: bool
    # The scan time the list reflects (newest day ingested); null when nothing is ingested.
    data_through: date | None


class FindingGroupOut(BaseModel):
    """One check of the findings matching the filters (the Findings list by check)."""

    tool: str
    check_id: str
    title: str
    severity: str  # the worst of its findings
    # Findings, not distinct resources (a check rarely fires twice on one resource): the
    # exact count of distinct resources is too slow over every open finding.
    findings: int
    connections: int
    last_seen: date


class FindingGroupPage(BaseModel):
    items: list[FindingGroupOut]
    total: int  # checks matching the filters, for the page count
    # The scan time the list reflects (newest day ingested); null when nothing is ingested.
    data_through: date | None


class CheckFacet(BaseModel):
    tool: str
    check_id: str


class FindingFacets(BaseModel):
    regions: list[str]
    services: list[str]
    resource_types: list[str]
    categories: list[str]
    checks: list[CheckFacet]


Severity = Literal["critical", "high", "medium", "low", "informational"]
# A value the data offers (a region, service, type, category or check id): short, plain text.
Facet = Annotated[str, Field(min_length=1, max_length=128)]


def _many() -> Any:
    return Field(default_factory=list, max_length=50)


class FindingQuery(BaseModel):
    """The Findings list's query parameters. A list parameter repeats (`severity=high&
    severity=critical`) and matches any of its values; absent, it does not filter."""

    limit: int = Field(20, ge=1, le=200)
    offset: int = Field(0, ge=0)
    connection_id: list[int] = _many()
    severity: list[Severity] = _many()
    tool: list[Literal["prowler", "cloudfox", "vulnerabilities"]] = _many()
    provider: list[Provider] = Field(default_factory=list, max_length=3)
    # open = open and reopened, the findings still to fix.
    state: findings.FindingState = "open"
    region: list[Facet] = _many()
    service: list[Facet] = _many()
    resource_type: list[Facet] = _many()
    check_id: list[Facet] = _many()
    category: list[Facet] = _many()
    status: list[Literal["FAIL", "MANUAL"]] = _many()
    # What Argus's internet rules say (reach above); a finding with none never matches.
    reach: list[findings.FindingReach] = Field(default_factory=list, max_length=4)
    muted: findings.MutedFilter = "any"
    # Only findings first seen in their latest scan.
    new: bool = False
    resource_id: int | None = None
    # Matches the title, check id or resource uid anywhere, in any case.
    q: str | None = Field(None, max_length=200)
    order: findings.FindingOrder = "severity"


def _filters(query: FindingQuery) -> findings.FindingFilters:
    return findings.FindingFilters(
        connection_ids=tuple(query.connection_id),
        severities=tuple(query.severity),
        tools=tuple(query.tool),
        providers=tuple(query.provider),
        state=query.state,
        regions=tuple(query.region),
        services=tuple(query.service),
        resource_types=tuple(query.resource_type),
        check_ids=tuple(query.check_id),
        categories=tuple(query.category),
        statuses=tuple(query.status),
        reaches=tuple(query.reach),
        muted=query.muted,
        new=query.new,
        resource_id=query.resource_id,
        q=query.q or None,
    )


@router.get("/findings")
def list_findings(conn: Db, _user: Viewer, query: Annotated[FindingQuery, Query()]) -> FindingPage:
    rows, total = findings.list_findings(
        conn, limit=query.limit, offset=query.offset, filters=_filters(query), order=query.order
    )
    # Only a search count is capped (core.db.count_sql); any other count is exact.
    capped = bool(query.q) and total > SEARCH_COUNT_CAP
    linked = sorted({r["resource_id"] for r in rows if r["resource_id"] is not None})
    names = inventory.resource_names(conn, linked)
    facts = findings.vulnerability_facts(
        conn, [r["id"] for r in rows if r["tool"] == findings.VULNERABILITY_TOOL]
    )
    return FindingPage(
        items=[FindingOut.model_validate(_named(r, names, facts)) for r in rows],
        total=SEARCH_COUNT_CAP if capped else total,
        total_capped=capped,
        data_through=ingest.data_through(
            conn, connection_ids=query.connection_id, tools=query.tool or TOOLS
        ),
    )


# Before /findings/{finding_id}, which would otherwise take "groups" as an id.
@router.get("/findings/groups")
def finding_groups(
    conn: Db, _user: Viewer, query: Annotated[FindingQuery, Query()]
) -> FindingGroupPage:
    """The Findings list by check, with the list's filters: one row per tool and check id,
    worst severity first, then the checks with the most findings."""
    rows, total = findings.finding_groups(
        conn, limit=query.limit, offset=query.offset, filters=_filters(query), order=query.order
    )
    return FindingGroupPage(
        items=[FindingGroupOut.model_validate(r) for r in rows],
        total=total,
        data_through=ingest.data_through(
            conn, connection_ids=query.connection_id, tools=query.tool or TOOLS
        ),
    )


@router.get("/findings/facets")
def finding_facets(
    conn: Db,
    _user: Viewer,
    connection_id: Annotated[list[int], Query(max_length=50)] = [],  # noqa: B006 - FastAPI copies
) -> FindingFacets:
    """The options of the Findings filters that come from the data."""
    facets = findings.finding_facets(conn, connection_ids=tuple(connection_id))
    return FindingFacets(
        regions=facets.regions,
        services=facets.services,
        resource_types=facets.resource_types,
        categories=facets.categories,
        checks=[CheckFacet(tool=t, check_id=c) for t, c in facets.checks],
    )


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, conn: Db, _user: Viewer) -> FindingDetail:
    """One finding, whatever its state, with what the tool says about it: what a finding's own
    link opens, and the list's details row. Its scan time is `last_seen`."""
    row = findings.get_finding(conn, finding_id)
    if row is None:
        raise LookupError(finding_id)
    names = inventory.resource_names(conn, [row["resource_id"]] if row["resource_id"] else [])
    ids = [finding_id] if row["tool"] == findings.VULNERABILITY_TOOL else []
    facts = findings.vulnerability_facts(conn, ids)
    return FindingDetail.model_validate(
        {
            **_named(row, names, facts),
            "links": row["links"] or [],
            "remediation_code": {
                "cli": row["code_cli"],
                "native_iac": row["code_native_iac"],
                "terraform": row["code_terraform"],
                "other": row["code_other"],
            },
            "commands": [
                vars(c)
                for c in findings.commands_for_resource(
                    conn, connection_id=row["connection_id"], resource_uid=row["resource_uid"]
                )
            ],
        }
    )


def _named(
    row: dict[str, Any],
    names: dict[int, str],
    facts: dict[int, findings.VulnerabilityFacts],
) -> dict[str, Any]:
    """The row with its resource's name (the inventory's, else the one the tool reported) and,
    for a vulnerability finding, its vulnerability."""
    name = names.get(row["resource_id"]) if row["resource_id"] is not None else None
    vulnerability = facts.get(row["id"])
    return {
        **row,
        "resource_name": name or row["reported_resource_name"],
        "vulnerability": vars(vulnerability) if vulnerability else None,
    }
