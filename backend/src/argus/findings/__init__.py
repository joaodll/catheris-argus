"""Findings: misconfigurations with a lifecycle, and compliance history.

Owns finding, finding_facet, finding_snapshot, finding_event, compliance_requirement,
compliance_snapshot, compliance_framework, compliance_rollup, finding_vulnerability,
vulnerability_coverage.
Public interface:
    parse_prowler()     the Prowler adapter: one run's raw files -> ProwlerBatch (pure)
    load_prowler()      lifecycle + day snapshots for one connection and day
    list_findings(), finding_facets(), open_finding_counts()   the read side (Findings page)
    finding_groups()    the Findings list by check
    open_finding_counts_by_tool()   per-tool counts for the Resource map
    open_exposure_counts()   open Prowler exposure findings per resource (the front doors)
    framework_catalog(), list_requirements()                   the read side (Compliance page)
    carry_forward_compliance(), rederive_scores()              a failed Prowler run (ingest)
    set_reach()         CloudFox's public endpoints and Prowler's exposure checks
                        (PROWLER_EXPOSURE_CHECKS), checked against Argus's rules (ADR-0035)
    remove_compliance_items()   migration 0023: findings read from Prowler's compliance OCSF
    parse_vulnerabilities(), load_vulnerabilities()   the vulnerabilities tool's CVEs, from
                        each provider's scanner (AWS Inspector today; ADR-0042)
    scanner_for(), vulnerability_counts(), scanned_resources(), resource_vulnerabilities(),
    resource_coverage(), vulnerability_facts()   their read side (Resources, Findings)
    VULNERABLE_RESOURCES_SQL   resource ids with open CVEs, for the Resources filter
"""

from argus.findings.commands import (
    ResolvedCommand,
    ResourceCommand,
    commands_for_resource,
    load_commands,
)
from argus.findings.compliance import (
    Framework,
    RequirementPage,
    RequirementStatus,
    framework_catalog,
    list_requirements,
)
from argus.findings.lifecycle import (
    ANY_CHECK,
    ANY_REGION,
    carry_forward_compliance,
    load_prowler,
    load_tool_findings,
    set_reach,
)
from argus.findings.metrics import ADDITIVE as FINDING_ADDITIVE_METRICS
from argus.findings.metrics import put_findings_metrics, rederive_scores
from argus.findings.model import (
    SEVERITIES,
    VULNERABILITY_TOOL,
    FindingResult,
    VulnerabilityBatch,
)
from argus.findings.prowler import EXPOSURE_CHECKS as PROWLER_EXPOSURE_CHECKS
from argus.findings.prowler import SUPPORTED_VERSIONS, ProwlerBatch, parse_prowler
from argus.findings.queries import (
    FAILING_FINDINGS_SQL,
    FindingFacets,
    FindingFilters,
    FindingOrder,
    FindingReach,
    FindingState,
    MutedFilter,
    finding_facets,
    finding_groups,
    get_finding,
    list_findings,
    open_exposure_counts,
    open_finding_counts,
    open_finding_counts_by_tool,
)
from argus.findings.repair import remove_compliance_items
from argus.findings.vulnerabilities import (
    VULNERABLE_RESOURCES_SQL,
    CoverageRow,
    ResourceVulnerabilities,
    VulnerabilityCount,
    VulnerabilityFacts,
    VulnerabilityLevel,
    load_vulnerabilities,
    parse_vulnerabilities,
    resource_coverage,
    resource_vulnerabilities,
    scanned_resources,
    scanner_for,
    vulnerability_counts,
    vulnerability_facts,
)

__all__ = [
    "ANY_CHECK",
    "ANY_REGION",
    "FAILING_FINDINGS_SQL",
    "FINDING_ADDITIVE_METRICS",
    "PROWLER_EXPOSURE_CHECKS",
    "SEVERITIES",
    "SUPPORTED_VERSIONS",
    "VULNERABILITY_TOOL",
    "VULNERABLE_RESOURCES_SQL",
    "CoverageRow",
    "FindingFacets",
    "FindingFilters",
    "FindingOrder",
    "FindingReach",
    "FindingResult",
    "FindingState",
    "Framework",
    "MutedFilter",
    "ProwlerBatch",
    "RequirementPage",
    "RequirementStatus",
    "ResolvedCommand",
    "ResourceCommand",
    "ResourceVulnerabilities",
    "VulnerabilityBatch",
    "VulnerabilityCount",
    "VulnerabilityFacts",
    "VulnerabilityLevel",
    "carry_forward_compliance",
    "commands_for_resource",
    "finding_facets",
    "finding_groups",
    "framework_catalog",
    "get_finding",
    "list_findings",
    "list_requirements",
    "load_commands",
    "load_prowler",
    "load_tool_findings",
    "load_vulnerabilities",
    "open_exposure_counts",
    "open_finding_counts",
    "open_finding_counts_by_tool",
    "parse_prowler",
    "parse_vulnerabilities",
    "put_findings_metrics",
    "rederive_scores",
    "remove_compliance_items",
    "resource_coverage",
    "resource_vulnerabilities",
    "scanned_resources",
    "scanner_for",
    "set_reach",
    "vulnerability_counts",
    "vulnerability_facts",
]
