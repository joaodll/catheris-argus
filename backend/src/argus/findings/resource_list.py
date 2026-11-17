"""The Resources list's filters and its per-resource facts, shared by the list (the API) and its
report (argus.reports), so both count alike.

The list is the inventory narrowed by sets other modules export: open CVEs and open
misconfigurations (this module), the internet reach (this module), role use (inventory) and
workloads (relationships). This is the one place those sets are chosen from the list's filters.
It owns no table: it composes exported SQL constants only (ADR-0026)."""

from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import Connection

from argus.findings.queries import (
    INTERNET_REACHABLE_RESOURCES_SQL,
    MISCONFIGURED_RESOURCES_SQL,
    MisconfigurationLevel,
)
from argus.findings.vulnerabilities import (
    VULNERABLE_RESOURCES_SQL,
    VulnerabilityCount,
    VulnerabilityLevel,
    scanned_resources,
    scanner_for,
    vulnerability_counts,
)
from argus.inventory import UNUSED_ROLES_SQL, ResourceFilters, RoleUnused
from argus.relationships import NO_WORKLOAD_ROLES_SQL


@dataclass(frozen=True)
class ResourceListFilters:
    """Every filter of the Resources list. The first fields are the inventory's own
    (inventory.ResourceFilters); the rest keep only the resources in another module's set."""

    connection_ids: tuple[int, ...] = ()
    resource_types: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    q: str | None = None
    include_deleted: bool = False
    assets: bool = False
    first_seen_from: date | None = None
    first_seen_to: date | None = None
    deleted_from: date | None = None
    deleted_to: date | None = None
    # Only resources with open CVEs: any, high or critical, or with a public exploit.
    vulnerabilities: VulnerabilityLevel | None = None
    # Only resources with open misconfigurations (open, FAIL, not muted): any, or critical or high.
    misconfigurations: MisconfigurationLevel | None = None
    # Only resources with an open misconfiguration Argus's rules confirm is reachable.
    internet: bool = False
    # Only IAM roles AWS records no use of in the last 90, 180 or 365 days.
    role_unused: RoleUnused | None = None
    # Only IAM roles no workload runs as.
    no_workload: bool = False

    def within(self) -> tuple[str, ...]:
        """The other modules' exported resource sets these filters keep, all of them applied."""
        sets: list[str] = []
        if self.vulnerabilities:
            sets.append(VULNERABLE_RESOURCES_SQL[self.vulnerabilities])
        if self.misconfigurations:
            sets.append(MISCONFIGURED_RESOURCES_SQL[self.misconfigurations])
        if self.internet:
            sets.append(INTERNET_REACHABLE_RESOURCES_SQL)
        if self.role_unused:
            sets.append(UNUSED_ROLES_SQL[self.role_unused])
        if self.no_workload:
            sets.append(NO_WORKLOAD_ROLES_SQL)
        return tuple(sets)

    def inventory_filters(self) -> ResourceFilters:
        return ResourceFilters(
            connection_ids=self.connection_ids,
            resource_types=self.resource_types,
            regions=self.regions,
            q=self.q,
            include_deleted=self.include_deleted,
            assets=self.assets,
            first_seen_from=self.first_seen_from,
            first_seen_to=self.first_seen_to,
            deleted_from=self.deleted_from,
            deleted_to=self.deleted_to,
            within=self.within(),
        )


@dataclass(frozen=True)
class VulnerabilitySummary:
    """A resource's open CVEs, suppressed ones left out: the Vulnerabilities cell."""

    open: int
    worst: str | None
    exploitable: int
    # The provider's scanner scans the resource (an active scan); false: "Not scanned".
    scanned: bool


def vulnerability_summaries(
    conn: Connection, rows: list[dict[str, Any]], *, collected: set[int]
) -> dict[int, VulnerabilitySummary]:
    """For one batch of resources (id, provider, type, connection_id): the Vulnerabilities cell
    of those a scanner scans the provider and type of, on the `collected` connections (those
    with a vulnerabilities run, which ingest knows). A resource left out is "not covered"."""
    ids = [
        r["id"]
        for r in rows
        if r["connection_id"] in collected and scanner_for(r["provider"], r["type"])
    ]
    counts = vulnerability_counts(conn, ids)
    scanned = scanned_resources(conn, ids)
    empty = VulnerabilityCount(0, None, 0)
    return {
        i: VulnerabilitySummary(
            open=counts.get(i, empty).open,
            worst=counts.get(i, empty).worst,
            exploitable=counts.get(i, empty).exploitable,
            scanned=i in scanned,
        )
        for i in ids
    }
