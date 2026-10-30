"""How sure Argus is of one step of an attack path, and so of the path (ADR-0037).

Five levels, weakest first. A path is as strong as its weakest step.

    confirmed   analysed: Argus's internet rules checked security groups, routing and ACLs
                (ROUTES_TO from the internet), or CloudFox analysed a role's policies
                (IS_ADMIN, CAN_PRIVESC_TO)
    supported   the configuration is there (routing, triggers, a role a workload runs as, a
                principal's data access, a trust without conditions, an administrator's
                policy, a role anyone may assume); IAM conditions, SCPs and permission
                boundaries are not evaluated: Argus has no IAM evaluator of its own
    candidate   one tool's claim or an assumption: CloudFox alone calls an endpoint public, a
                trust has conditions or needs an external id, a key is assumed to open a
                neighbour, an outsider is hostile, a user's credential leaks, a permission
                name matches an escalation or Systems Manager
    unknown     data the verdict needs is missing (PUBLIC_UNVERIFIED, ADR-0035)
    blocked     Argus checked the door and it is closed (PUBLIC_RESTRICTED): what one change
                would open, a latent path (ADR-0037, amended 2026-10-21)
"""

from typing import Any, Literal

Confidence = Literal["blocked", "unknown", "candidate", "supported", "confirmed"]
# Weakest first: a path's confidence is the lowest index of its steps.
LEVELS: tuple[Confidence, ...] = ("blocked", "unknown", "candidate", "supported", "confirmed")
# What keeps the internet out of a restricted door (ADR-0035), in the words of a path's step.
BLOCKED_BY = {
    "sg_no_public_source": "its security groups admit no internet source on a port it serves",
    "no_internet_route": "its subnets have no route to an internet gateway",
    "nacl_blocks": "a network ACL keeps the internet out",
    "cidr_allowlist": "it admits only listed source addresses",
    "iam_auth": "it requires IAM authentication",
    "no_public_address": "it has no public address",
    "not_running": "it is not running",
    "block_public_access": "S3 Block Public Access keeps anonymous requests out",
}
INTERNET = "internet"

_WHY = {
    "internet_rule": "Argus checked its security groups, routing and network ACLs: the internet "
    "reaches it.",
    "internet_unknown": "Data Argus needs to judge its reach is missing: it could be reachable.",
    "internet_cloudfox": "Only CloudFox calls it public; no Argus rule confirms it.",
    "cloudfox_analysis": "CloudFox analysed the role's policies.",
    "trust_condition": "The trust policy has conditions Argus does not evaluate.",
    "trust_external_id": "The trust requires an external id the attacker must know.",
    "lateral": "Assumes a key, password or exploit from the first instance opens the second.",
    "escalation": "Matches a documented escalation method by permission name; which "
    "resources, conditions, boundaries and SCPs are not evaluated.",
    "ssm": "May run commands through Systems Manager; which instances the permission names is "
    "not evaluated.",
    "manual": "A person drew this connection.",
    "outsider": "Assumes whoever controls this principal outside the account is hostile.",
    "anyone": "Anyone in any AWS account; only conditions Argus does not evaluate can stop them.",
    "credential": "Assumes the credential leaks: an active access key or a console password "
    "without MFA.",
    "admin_policy": "Its policies allow every action on every resource; a Deny, a permission "
    "boundary or an SCP is not evaluated.",
    "configuration": "The configuration is there; IAM conditions, SCPs and permission boundaries "
    "are not evaluated.",
}
# CloudFox edges name no file; the module follows from the edge type (aws/role-trusts.go,
# aws/endpoints.go), so the evidence can say where a step came from without re-keying edges.
_CLOUDFOX_MODULE = {
    "CAN_ASSUME": "role-trusts",
    "IS_ADMIN": "role-trusts",
    "CAN_PRIVESC_TO": "role-trusts",
    "INTERNET_REACHABLE": "endpoints",
}


def _entry_confidence(
    type_: str, origin: str, attributes: dict[str, Any]
) -> tuple[Confidence, str]:
    """The step in from the internet: Argus's own check, a gap in its data, a door Argus found
    closed, or CloudFox alone."""
    if type_ == "PUBLIC_RESTRICTED":
        control = BLOCKED_BY.get(str(attributes.get("reason")), "a control keeps the internet out")
        return "blocked", f"Blocked: {control}. One change would open this path."
    if type_ == "ROUTES_TO" and origin.startswith("rule:"):
        return "confirmed", _WHY["internet_rule"]
    if type_ == "PUBLIC_UNVERIFIED":
        return "unknown", _WHY["internet_unknown"]
    if type_ == "OUTSIDER":
        if attributes.get("kind") == "anyone":
            return "supported", _WHY["anyone"]
        return "candidate", _WHY["outsider"]
    if type_ == "HAS_CREDENTIAL":
        return "candidate", _WHY["credential"]
    if origin == "manual":
        return "supported", _WHY["manual"]
    return "candidate", _WHY["internet_cloudfox"]


# Moves Argus draws from an assumption or a permission's name (ADR-0037 second amendment, wave
# 3): Candidate, and why.
_NAMED_MOVES = {"CAN_CONNECT_TO": "lateral", "CAN_ESCALATE_TO": "escalation", "CAN_RUN_ON": "ssm"}


def edge_confidence(
    type_: str, origin: str, attributes: dict[str, Any], source_uid: str
) -> tuple[Confidence, str]:
    """One step's level and why, in words."""
    if source_uid == INTERNET:
        return _entry_confidence(type_, origin, attributes)
    if type_ in ("IS_ADMIN", "CAN_PRIVESC_TO") and origin == "cloudfox":
        return "confirmed", _WHY["cloudfox_analysis"]
    if type_ == "IS_ADMIN" and origin.startswith("rule:"):
        return "supported", _WHY["admin_policy"]
    if type_ == "CAN_ASSUME":
        if attributes.get("condition"):
            return "candidate", _WHY["trust_condition"]
        if attributes.get("external_id"):
            return "candidate", _WHY["trust_external_id"]
    if type_ in _NAMED_MOVES:
        return "candidate", _WHY[_NAMED_MOVES[type_]]
    if origin == "manual":
        return "supported", _WHY["manual"]
    return "supported", _WHY["configuration"]


def weakest(levels: list[Confidence]) -> Confidence:
    return min(levels, key=LEVELS.index) if levels else "unknown"


def source_label(type_: str, origin: str, attributes: dict[str, Any] | None = None) -> str:
    """Where a step's evidence comes from: "rule internet-entry@3", "CloudFox role-trusts",
    "manual". A CloudFox edge that names its module (network-ports) says so."""
    if origin.startswith("rule:"):
        return f"rule {origin.removeprefix('rule:')}"
    if origin == "cloudfox":
        module = (attributes or {}).get("module") or _CLOUDFOX_MODULE.get(type_)
        return f"CloudFox {module}" if module else "CloudFox"
    return origin
