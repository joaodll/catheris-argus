"""Each resource's open findings, reduced to the facts Risk combines (ADR-0049).

One grouped read of one connection's open findings: the CVEs (open or reopened, not suppressed
in the scanner) and the misconfigurations (OPEN_MISCONFIGURATION). Only resources with at least
one fact Risk can use come back, so the result is bounded by what is at risk, not by the
inventory.
"""

from dataclasses import dataclass

from sqlalchemy import Connection, text

from argus.findings.model import OPEN_MISCONFIGURATION, SEVERITIES, VULNERABILITY_TOOL

_OPEN_CVE = f"f.tool = '{VULNERABILITY_TOOL}' AND f.state IN ('open', 'reopened') AND NOT f.muted"
_HIGH = "f.severity IN ('critical', 'high')"
# The fixed-version facts the Vulnerabilities list's fix=available filter reads.
_FIX = "v.fix_available IN ('YES', 'PARTIAL')"


@dataclass(frozen=True)
class FindingFacts:
    """One resource's open findings, as Risk counts them.

    `high_misconfigurations` and `worst_misconfiguration` are every open misconfiguration, as the
    Misconfigurations list filtered to the resource shows them. `other_high_misconfigurations`
    leaves out the checks the caller names as facts of their own (the exposure checks, which say
    why a resource is reachable, and the secret check), so a combination never counts one
    finding twice."""

    exploitable_cves: int
    exploitable_fixable_cves: int
    high_cves: int
    max_epss: float | None
    high_misconfigurations: int
    other_high_misconfigurations: int
    worst_misconfiguration: str | None
    secret: bool


def resource_finding_facts(
    conn: Connection,
    *,
    connection_id: int,
    own_fact_checks: tuple[str, ...],
    secret_check: str,
) -> dict[int, FindingFacts]:
    """Each resource of one connection with an open CVE that has a public exploit or is
    critical or high, an open critical or high misconfiguration, or the open secret check."""
    rank = " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES))
    rows = conn.execute(
        text(f"""
            SELECT f.resource_id,
                   count(*) FILTER (WHERE {_OPEN_CVE} AND v.exploit_available) AS exploitable,
                   count(*) FILTER (WHERE {_OPEN_CVE} AND v.exploit_available AND {_FIX})
                     AS exploitable_fixable,
                   count(*) FILTER (WHERE {_OPEN_CVE} AND {_HIGH}) AS high_cves,
                   max(v.epss_score) FILTER (WHERE {_OPEN_CVE}) AS max_epss,
                   count(*) FILTER (WHERE {OPEN_MISCONFIGURATION} AND {_HIGH})
                     AS high_misconfigurations,
                   count(*) FILTER (WHERE {OPEN_MISCONFIGURATION} AND {_HIGH}
                                      AND f.check_id <> ALL(CAST(:own AS text[])))
                     AS other_high_misconfigurations,
                   min(CASE f.severity {rank} END)
                     FILTER (WHERE {OPEN_MISCONFIGURATION}) AS worst,
                   coalesce(bool_or({OPEN_MISCONFIGURATION} AND f.check_id = :secret), false)
                     AS secret
            FROM finding f LEFT JOIN finding_vulnerability v ON v.finding_id = f.id
            WHERE f.connection_id = :c AND f.resource_id IS NOT NULL
              AND (({_OPEN_CVE}) OR ({OPEN_MISCONFIGURATION}))
            GROUP BY f.resource_id
            HAVING count(*) FILTER (WHERE {_OPEN_CVE} AND (v.exploit_available OR {_HIGH})) > 0
                OR count(*) FILTER (WHERE {OPEN_MISCONFIGURATION} AND {_HIGH}
                                      AND f.check_id <> ALL(CAST(:own AS text[]))) > 0
                OR bool_or({OPEN_MISCONFIGURATION} AND f.check_id = :secret)
        """),  # noqa: S608 - fixed fragments and constants only
        {"c": connection_id, "own": [*own_fact_checks, secret_check], "secret": secret_check},
    )
    return {
        r.resource_id: FindingFacts(
            exploitable_cves=r.exploitable,
            exploitable_fixable_cves=r.exploitable_fixable,
            high_cves=r.high_cves,
            max_epss=None if r.max_epss is None else float(r.max_epss),
            high_misconfigurations=r.high_misconfigurations,
            other_high_misconfigurations=r.other_high_misconfigurations,
            worst_misconfiguration=None if r.worst is None else SEVERITIES[r.worst],
            secret=r.secret,
        )
        for r in rows
    }
