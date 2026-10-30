"""How sure Argus is of each attack-path step (ADR-0037): one table, read by the search and the
API alike."""

import pytest

from argus.attackpaths import LEVELS, edge_confidence, source_label
from argus.attackpaths.confidence import weakest


@pytest.mark.parametrize(
    ("type_", "origin", "attributes", "source", "level"),
    [
        ("ROUTES_TO", "rule:internet-entry@3", {}, "internet", "confirmed"),
        ("PUBLIC_UNVERIFIED", "rule:internet-unverified@1", {}, "internet", "unknown"),
        ("INTERNET_REACHABLE", "cloudfox", {}, "internet", "candidate"),
        ("ROUTES_TO", "manual", {}, "internet", "supported"),
        (
            "PUBLIC_RESTRICTED",
            "rule:internet-restricted@4",
            {"reason": "no_internet_route"},
            "internet",
            "blocked",
        ),
        ("CAN_PRIVESC_TO", "cloudfox", {}, "arn:aws:iam::1:role/a", "confirmed"),
        ("IS_ADMIN", "cloudfox", {}, "arn:aws:iam::1:role/a", "confirmed"),
        ("CAN_ASSUME", "rule:role-trust@1", {"condition": {}}, "arn:aws:iam::1:root", "supported"),
        (
            "CAN_ASSUME",
            "rule:role-trust@1",
            {"condition": {"StringEquals": {"sts:ExternalId": "x"}}},
            "arn:aws:iam::1:root",
            "candidate",
        ),
        ("CAN_ASSUME", "cloudfox", {"external_id": True}, "arn:aws:iam::2:root", "candidate"),
        ("CAN_CONNECT_TO", "rule:lateral-network@1", {"ports": [22]}, "arn:i-a", "candidate"),
        (
            "CAN_ESCALATE_TO",
            "rule:privilege-escalation@1",
            {},
            "arn:aws:iam::1:user/u",
            "candidate",
        ),
        ("CAN_RUN_ON", "rule:ssm-command@1", {}, "arn:aws:iam::1:role/r", "candidate"),
        ("RUNS_AS", "rule:instance-role@1", {}, "arn:i-a", "supported"),
        ("ACCESSES", "rule:role-accesses@1", {}, "arn:role", "supported"),
        # Wave 2 (ADR-0037, second amendment): more ways in, administrators from configuration.
        (
            "OUTSIDER",
            "rule:outsider-trust@1",
            {"kind": "other_account"},
            "internet",
            "candidate",
        ),
        ("OUTSIDER", "rule:outsider-trust@1", {"kind": "anyone"}, "internet", "supported"),
        (
            "HAS_CREDENTIAL",
            "rule:exposed-user-credential@1",
            {"credentials": ["access_key"]},
            "internet",
            "candidate",
        ),
        ("IS_ADMIN", "rule:principal-admin@1", {}, "arn:aws:iam::1:user/u", "supported"),
        (
            "PUBLIC_RESTRICTED",
            "rule:internet-restricted@6",
            {"reason": "block_public_access"},
            "internet",
            "blocked",
        ),
    ],
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_each_step_gets_a_level_and_a_reason(
    type_: str, origin: str, attributes: dict, source: str, level: str
) -> None:
    got, why = edge_confidence(type_, origin, attributes, source)
    assert got == level and why.endswith(".")


def test_a_path_is_as_sure_as_its_weakest_step_and_names_its_sources() -> None:
    assert LEVELS == ("blocked", "unknown", "candidate", "supported", "confirmed")
    assert weakest(["blocked", "confirmed"]) == "blocked"
    assert weakest(["confirmed", "supported", "confirmed"]) == "supported"
    assert weakest([]) == "unknown"
    assert source_label("ROUTES_TO", "rule:internet-entry@3") == "rule internet-entry@3"
    assert source_label("CAN_PRIVESC_TO", "cloudfox") == "CloudFox role-trusts"
    assert source_label("INTERNET_REACHABLE", "cloudfox") == "CloudFox endpoints"
    assert source_label("ROUTES_TO", "manual") == "manual"
