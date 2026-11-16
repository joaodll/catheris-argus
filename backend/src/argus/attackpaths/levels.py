"""How sure Argus is of one step of an attack route, and so of the route (ADR-0052 §5).

A step has a level, weakest first:

    blocked     Argus checked the door and it is closed (PUBLIC_RESTRICTED): a latent route
    unknown     data the verdict needs is missing (PUBLIC_UNVERIFIED)
    candidate   an assumption Argus can't check: one tool's claim, a trust condition, a name-level
                permission, a foothold, a cross-account identity
    supported   the configuration is there; IAM conditions, SCPs and boundaries are not evaluated
    confirmed   analysed: Argus's internet rules checked the network, or CloudFox the policies

and a reason key, which the screen turns into words. A route's class is derived from its steps
(route_class): Blocked, then Not enough data, then by how many assumptions it makes. Each
candidate step counts one assumption; a step with no evidence at all (compromise_assumed,
data_auth_assumed) counts two.
"""

from collections.abc import Iterable
from typing import Any, Literal

Level = Literal["blocked", "unknown", "candidate", "supported", "confirmed"]
LEVELS: tuple[Level, ...] = ("blocked", "unknown", "candidate", "supported", "confirmed")
RouteClass = Literal["blocked", "unknown", "potential", "conditional", "confirmed"]
# Weakest first; a route list ranks the strongest first.
CLASSES: tuple[RouteClass, ...] = ("blocked", "unknown", "potential", "conditional", "confirmed")
INTERNET = "internet"
# Reasons whose step has no evidence at all: two assumptions.
DOUBLE = frozenset({"compromise_assumed", "data_auth_assumed"})
# The walk's own steps, which no edge stands for.
FOOTHOLD = "FOOTHOLD"
AUTHENTICATES = "AUTHENTICATES"
# Moves through a permission's name or an assumption: candidate, and why.
_NAMED = {
    "CAN_CONNECT_TO": "lateral",
    "CAN_ESCALATE_TO": "escalation",
    "CAN_RUN_ON": "ssm",
    "HAS_CREDENTIAL": "credential",
    # The store's own policy (resource side) is not evaluated (P1 R0).
    "ACCESSES": "resource_side_unevaluated",
    # Whoever can feed the source triggers the target; who can is not evaluated (P1 R0).
    "TRIGGERS": "trigger_input",
}


def _entry(type_: str, origin: str, attributes: dict[str, Any]) -> tuple[Level, str]:
    if type_ == "PUBLIC_RESTRICTED":
        return "blocked", f"internet_restricted:{attributes.get('reason') or 'control'}"
    if type_ == "ROUTES_TO" and origin.startswith("rule:"):
        return "confirmed", "internet_rule"
    if type_ == "PUBLIC_UNVERIFIED":
        return "unknown", "internet_unknown"
    if type_ == "OUTSIDER":
        return (
            ("supported", "anyone")
            if attributes.get("kind") == "anyone"
            else (
                "candidate",
                "outsider",
            )
        )
    if type_ == "HAS_CREDENTIAL":
        return "candidate", "credential"
    if origin == "manual":
        return "supported", "manual"
    return "candidate", "internet_cloudfox"


def edge_level(  # noqa: PLR0911 - one return per rule of the level table (P1 R0 §5)
    type_: str,
    origin: str,
    attributes: dict[str, Any] | None,
    source_uid: str,
    *,
    cross_account: bool = False,
) -> tuple[Level, str]:
    """One edge's level and reason key. `cross_account`: a trust whose principal is in another
    account than the role (never better than candidate: Argus reads the trust, not the
    principal's own policy)."""
    attributes = attributes or {}
    if source_uid == INTERNET:
        return _entry(type_, origin, attributes)
    if type_ in ("IS_ADMIN", "CAN_PRIVESC_TO") and origin == "cloudfox":
        return "confirmed", "cloudfox_analysis"
    if type_ == "IS_ADMIN" and origin.startswith("rule:"):
        return "supported", "admin_policy"
    if type_ == "CAN_ASSUME":
        if attributes.get("condition"):
            return "candidate", "trust_condition"
        if attributes.get("external_id"):
            return "candidate", "trust_external_id"
        if cross_account:
            return "candidate", "cross_account_trust"
        return "supported", "trust"
    if type_ in _NAMED:
        return "candidate", _NAMED[type_]
    if origin == "manual":
        return "supported", "manual"
    if type_ == "ROUTES_TO" and origin.startswith("rule:apigw-"):
        return "supported", "api_integration"
    return "supported", "configuration"


def assumptions(steps: Iterable[tuple[Level, str]]) -> int:
    return sum(2 if reason in DOUBLE else 1 for level, reason in steps if level == "candidate")


def route_class(steps: list[tuple[Level, str]]) -> RouteClass:
    """The skill's five classes (ADR-0052 §5), from the steps' levels and reasons."""
    levels = {level for level, _ in steps}
    if "blocked" in levels:
        return "blocked"
    if "unknown" in levels:
        return "unknown"
    n = assumptions(steps)
    return "potential" if n >= 2 else "conditional" if n == 1 else "confirmed"
