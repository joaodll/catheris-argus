import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from check_readonly import CfnLoader, check_template

TEMPLATE = Path(__file__).resolve().parents[2] / "scanner-role.yaml"


@pytest.fixture
def template() -> dict[str, Any]:
    return yaml.load(TEMPLATE.read_text(), Loader=CfnLoader)  # noqa: S506


def _allow(tpl: dict[str, Any]) -> list[str]:
    return tpl["Resources"]["CloudFoxAdditionsPolicy"]["Properties"]["PolicyDocument"]["Statement"][
        0
    ]["Action"]


def test_scanner_role_template_is_read_only(template: dict[str, Any]) -> None:
    assert check_template(template) == []


@pytest.mark.parametrize(
    "action",
    [
        "ec2:TerminateInstances",
        "s3:PutObject",
        "iam:*",
        "*",
        "securityhub:BatchImportFindings",
        "ecr:BatchGetImage",
        "logs:FilterLogEvents",
    ],
)
def test_write_or_wildcard_action_fails(template: dict[str, Any], action: str) -> None:
    _allow(template).append(action)
    assert any(action in e for e in check_template(template))


def test_read_verb_wildcard_passes(template: dict[str, Any]) -> None:
    _allow(template).append("ec2:Describe*")
    assert check_template(template) == []


def test_not_action_fails(template: dict[str, Any]) -> None:
    doc = template["Resources"]["CloudFoxAdditionsPolicy"]["Properties"]["PolicyDocument"]
    stmt = doc["Statement"][0]
    stmt["NotAction"] = stmt.pop("Action")
    assert any("NotAction" in e for e in check_template(template))


@pytest.mark.parametrize(
    ("statement", "action"),
    [(0, "secretsmanager:GetSecretValue"), (1, "lambda:GetFunction"), (1, "ecr:BatchGetImage")],
)
def test_weakened_deny_fails(template: dict[str, Any], statement: int, action: str) -> None:
    deny = template["Resources"]["DenySecretReadsPolicy"]["Properties"]["PolicyDocument"]
    deny["Statement"][statement]["Action"].remove(action)
    assert any("does not attach a policy denying" in e for e in check_template(template))


def test_admin_managed_policy_fails(template: dict[str, Any]) -> None:
    arns = template["Resources"]["ScannerRole"]["Properties"]["ManagedPolicyArns"]
    arns.append({"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess"})
    assert any("AdministratorAccess" in e for e in check_template(template))


def test_trust_without_external_id_fails(template: dict[str, Any]) -> None:
    role = copy.deepcopy(template["Resources"]["ScannerRole"])
    role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0].pop("Condition")
    template["Resources"]["ScannerRole"] = role
    assert any("ExternalId" in e for e in check_template(template))


def test_inline_role_policy_is_checked(template: dict[str, Any]) -> None:
    template["Resources"]["ScannerRole"]["Properties"]["Policies"] = [
        {
            "PolicyName": "sneaky",
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "ec2:CreateTags", "Resource": "*"}]
            },
        }
    ]
    assert any("ec2:CreateTags" in e for e in check_template(template))


@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["a", "b"]}, {"Service": "ec2.amazonaws.com"}])
def test_trust_principal_must_be_one_named_aws_principal(
    template: dict[str, Any], principal: object
) -> None:
    template["Resources"]["ScannerRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0][
        "Principal"
    ] = principal
    assert any("exactly one AWS principal" in e for e in check_template(template))


@pytest.mark.parametrize(
    "path",
    ["arn:*:apigateway:*::/apikeys", "arn:*:apigateway:*::/usageplans/*/keys/*"],
)
def test_api_key_values_must_stay_denied(template: dict[str, Any], path: str) -> None:
    """GET on these paths returns API key values; dropping one from the Deny fails the check."""
    deny = template["Resources"]["DenySecretReadsPolicy"]["Properties"]["PolicyDocument"]
    statement = next(s for s in deny["Statement"] if s.get("Sid") == "DenyApiKeyValues")
    statement["Resource"].remove(path)
    assert any("does not attach a policy denying" in e for e in check_template(template))


def test_printed_policies_fit_a_managed_policy_and_keep_the_deny(template: dict[str, Any]) -> None:
    """The documents an IAM user or permission set is given (print_policies.py) are the
    template's own, each small enough for one customer managed policy."""
    from print_policies import MANAGED_POLICY_LIMIT, compact, policies

    documents = policies(template)
    assert set(documents) == {
        "ProwlerAdditionsPolicy",
        "CloudFoxAdditionsPolicy",
        "DenySecretReadsPolicy",
    }
    assert all(len(compact(d)) <= MANAGED_POLICY_LIMIT for d in documents.values())
    sids = {s.get("Sid") for s in documents["DenySecretReadsPolicy"]["Statement"]}
    assert {"DenySecretAndDataReads", "DenyCodeImageAndLogContent", "DenyApiKeyValues"} <= sids
