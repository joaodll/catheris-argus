"""Findings: misconfigurations with a lifecycle, and compliance history.

Owns finding, finding_facet, finding_snapshot, finding_event, compliance_requirement,
compliance_snapshot, compliance_framework, compliance_rollup, finding_vulnerability,
vulnerability_coverage, finding_tag_key, finding_tag_value.
Public interface:
    parse_prowler()     the Prowler adapter: one run's raw files -> ProwlerBatch (pure)
    load_prowler()      lifecycle + day snapshots for one connection and day
    list_findings(), finding_facets(), open_finding_counts(),
    confirmed_reach_resources()   the read side (Findings page)
    iter_findings()     every finding matching the list's filters, in id batches (reports)
    tag_keys(), tag_values()   the Tag filter's options; refresh_tag_facets() rebuilds them after
                        an inventory load (ingest), as a findings load does itself
    check_texts()       each listed check's risk, description and fix code (reports)
    finding_groups()    the Findings list by check
    framework_catalog(), list_requirements()                   the read side (Compliance page)
    carry_forward_compliance(), rederive_scores()              a failed Prowler run (ingest)
    set_reach()         CloudFox's public endpoints and Prowler's exposure checks
                        (PROWLER_EXPOSURE_CHECKS), checked against Argus's rules (ADR-0035)
    remove_compliance_items()   migration 0023: findings read from Prowler's compliance OCSF
    parse_vulnerabilities(), load_vulnerabilities()   the vulnerabilities tool's CVEs, from
                        each provider's scanner (AWS Inspector today; ADR-0042)
    scanner_for(), vulnerability_counts(), scanned_resources(), resource_vulnerabilities(),
    resource_coverage(), vulnerability_facts()   their read side (Resources, Findings)
    FAILING_FINDINGS_SQL, failing_resources(), exploitable_resources()   what the attack-path
                        kinds and steps read (ADR-0052)
    VULNERABLE_RESOURCES_SQL, MISCONFIGURED_RESOURCES_SQL, INTERNET_REACHABLE_RESOURCES_SQL
                        resource ids with open CVEs, open misconfigurations, or an open
                        misconfiguration reachable from the internet, for the Resources filters
    ResourceListFilters, vulnerability_summaries()   the Resources list's filters and its
                        Vulnerabilities cell, shared by the list and its report (resource_list.py)
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
from argus.findings.metrics import (
    MISCONFIGURATION_METRICS,
    put_findings_metrics,
    put_misconfiguration_metrics,
    put_vulnerability_metrics,
    rederive_scores,
)
from argus.findings.model import (
    MISCONFIGURATION_TOOLS,
    SEVERITIES,
    VULNERABILITY_TOOL,
    FindingResult,
    VulnerabilityBatch,
)
from argus.findings.prowler import EXPOSURE_CHECKS as PROWLER_EXPOSURE_CHECKS
from argus.findings.prowler import SUPPORTED_VERSIONS, ProwlerBatch, parse_prowler
from argus.findings.queries import (
    FAILING_FINDINGS_SQL,
    INTERNET_REACHABLE_RESOURCES_SQL,
    MISCONFIGURED_RESOURCES_SQL,
    FindingFacets,
    FindingFilters,
    FindingOrder,
    FindingReach,
    FindingState,
    FixFilter,
    MisconfigurationLevel,
    MutedFilter,
    check_texts,
    confirmed_reach_resources,
    exploitable_resources,
    failing_resources,
    finding_facets,
    finding_groups,
    get_finding,
    iter_findings,
    list_findings,
    open_finding_counts,
    open_finding_severities,
)
from argus.findings.repair import remove_compliance_items
from argus.findings.resource_list import (
    ResourceListFilters,
    VulnerabilitySummary,
    vulnerability_summaries,
)
from argus.findings.tags import (
    TAG_VALUES_LISTED,
    TagKey,
    refresh_tag_facets,
    tag_keys,
    tag_values,
)
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
    "INTERNET_REACHABLE_RESOURCES_SQL",
    "MISCONFIGURATION_METRICS",
    "MISCONFIGURATION_TOOLS",
    "MISCONFIGURED_RESOURCES_SQL",
    "PROWLER_EXPOSURE_CHECKS",
    "SEVERITIES",
    "SUPPORTED_VERSIONS",
    "TAG_VALUES_LISTED",
    "VULNERABILITY_TOOL",
    "VULNERABLE_RESOURCES_SQL",
    "CoverageRow",
    "FindingFacets",
    "FindingFilters",
    "FindingOrder",
    "FindingReach",
    "FindingResult",
    "FindingState",
    "FixFilter",
    "Framework",
    "MisconfigurationLevel",
    "MutedFilter",
    "ProwlerBatch",
    "RequirementPage",
    "RequirementStatus",
    "ResolvedCommand",
    "ResourceCommand",
    "ResourceListFilters",
    "ResourceVulnerabilities",
    "TagKey",
    "VulnerabilityBatch",
    "VulnerabilityCount",
    "VulnerabilityFacts",
    "VulnerabilityLevel",
    "VulnerabilitySummary",
    "carry_forward_compliance",
    "check_texts",
    "commands_for_resource",
    "confirmed_reach_resources",
    "exploitable_resources",
    "failing_resources",
    "finding_facets",
    "finding_groups",
    "framework_catalog",
    "get_finding",
    "iter_findings",
    "list_findings",
    "list_requirements",
    "load_commands",
    "load_prowler",
    "load_tool_findings",
    "load_vulnerabilities",
    "open_finding_counts",
    "open_finding_severities",
    "parse_prowler",
    "parse_vulnerabilities",
    "put_findings_metrics",
    "put_misconfiguration_metrics",
    "put_vulnerability_metrics",
    "rederive_scores",
    "refresh_tag_facets",
    "remove_compliance_items",
    "resource_coverage",
    "resource_vulnerabilities",
    "scanned_resources",
    "scanner_for",
    "set_reach",
    "tag_keys",
    "tag_values",
    "vulnerability_counts",
    "vulnerability_facts",
    "vulnerability_summaries",
]
