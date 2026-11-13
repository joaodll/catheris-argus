"""The named combinations Risk ranks (ADR-0049, version 1 of the set).

Every fact is on one resource. Nothing here follows an edge to another resource (ADR-0045; the
owner, 2026-11-12). A combination matches when all its facts hold; a resource's tier is the
worst tier it matches.
"""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

TIERS = ("critical", "high", "medium")  # worst first
TIER_RANK = {"critical": 3, "high": 2, "medium": 1}


@dataclass(frozen=True)
class Facts:
    """What Argus knows about one resource, as Risk reads it.

    `door`: the resource has a confirmed internet door (Argus's rules), or a held one (section 5:
    it turned unknown while the resource was already at risk through it). `admin`: the principal
    is an administrator or can make itself one. `credentials`: the IAM user's credentials that
    work from anywhere (access_key, console_password_no_mfa)."""

    door: bool
    admin: bool
    credentials: tuple[str, ...]
    exploitable_cves: int
    exploitable_fixable_cves: int
    high_cves: int
    max_epss: float | None
    high_misconfigurations: int  # every open critical or high one, as its list shows them
    other_high_misconfigurations: int  # the exposure and secret checks left out
    worst_misconfiguration: str | None
    secret: bool


@dataclass(frozen=True)
class Combination:
    id: str
    version: int
    tier: str
    title: str
    description: str
    matches: Callable[[Facts], bool]


COMBINATIONS: tuple[Combination, ...] = (
    Combination(
        "reachable-exploitable",
        1,
        "critical",
        "Open to the internet with an exploitable CVE",
        "Argus's rules confirm traffic from the internet can reach it, and it has an open CVE "
        "with a public exploit.",
        lambda f: f.door and f.exploitable_cves > 0,
    ),
    Combination(
        "admin-user-long-lived-credential",
        1,
        "high",
        "Admin user that can sign in from anywhere",
        "An IAM user that is an administrator, or can make itself one, with an active access key "
        "or a console password without MFA. It does not mean a key has leaked.",
        lambda f: f.admin and bool(f.credentials),
    ),
    Combination(
        "reachable-critical-cve",
        1,
        "high",
        "Open to the internet with a critical or high CVE",
        "Argus's rules confirm traffic from the internet can reach it, and it has an open "
        "critical or high CVE, none with a public exploit.",
        lambda f: f.door and f.high_cves > 0 and f.exploitable_cves == 0,
    ),
    Combination(
        "reachable-misconfigured",
        1,
        "high",
        "Open to the internet and misconfigured",
        "Argus's rules confirm traffic from the internet can reach it, and it has an open "
        "critical or high misconfiguration other than the exposure itself.",
        lambda f: f.door and f.other_high_misconfigurations > 0,
    ),
    Combination(
        "reachable-secret",
        1,
        "high",
        "Open to the internet with a secret in its configuration",
        "Argus's rules confirm traffic from the internet can reach it, and CloudFox found a "
        "secret in its environment variables.",
        lambda f: f.door and f.secret,
    ),
    Combination(
        "exploitable-fixable",
        1,
        "medium",
        "Exploitable CVE with a fix available",
        "It has an open CVE with a public exploit and a fixed version available, and no "
        "confirmed internet door of its own.",
        lambda f: not f.door and f.exploitable_fixable_cves > 0,
    ),
)
BY_ID = {c.id: c for c in COMBINATIONS}
COMBINATION_IDS = tuple(c.id for c in COMBINATIONS)
# Whether a combination needs the door: a held door keeps only these.
DOOR_COMBINATIONS = frozenset(c.id for c in COMBINATIONS if c.id.startswith("reachable-"))


def combination_set() -> str:
    """What a refresh was computed with: a SHA-256 of every combination's id and version
    (risk_load.combination_set). A release that changes it refreshes every connection once."""
    names = sorted(f"{c.id}@{c.version}" for c in COMBINATIONS)
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


def matched(facts: Facts) -> tuple[str, ...]:
    """The combinations a resource matches, in the set's order."""
    return tuple(c.id for c in COMBINATIONS if c.matches(facts))


def tier_of(combinations: tuple[str, ...]) -> str:
    return max((BY_ID[c].tier for c in combinations), key=TIER_RANK.__getitem__)


_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}


def sort_key(combinations: tuple[str, ...], facts: Facts) -> int:
    """The list's order as one number, larger first (ADR-0049 section 2): tier, how many
    combinations, CVEs with a public exploit, the highest EPSS, the worst misconfiguration.
    Each part is capped to its digits so no part spills into the one before it."""
    epss = 0 if facts.max_epss is None else round(min(max(facts.max_epss, 0.0), 1.0) * 1000)
    return (
        TIER_RANK[tier_of(combinations)] * 10**11
        + min(len(combinations), 99) * 10**9
        + min(facts.exploitable_cves, 9999) * 10**5
        + epss * 10
        + _SEVERITY_RANK.get(facts.worst_misconfiguration or "", 0)
    )
