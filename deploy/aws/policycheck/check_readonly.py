"""Fail if any IAM policy in the given CloudFormation templates could change a scanned account.

The read-only rule (CLAUDE.md): Argus never changes anything in a cloud it scans. This check
makes that rule a build failure instead of a review comment. For every template it enforces:

1. Every Allow action is a read: a read verb prefix (optionally ending in a single trailing
   wildcard), or one of the few read actions that do not follow the verb convention.
   `*`, `service:*`, NotAction and NotResource are refused.
2. Only the two AWS managed policies Argus relies on may be attached.
3. Every role attaches a policy whose Deny covers the secret and data-plane reads, and the
   API Gateway paths that return API key values.
4. Every role's trust policy allows only sts:AssumeRole, from one named AWS principal (never a
   wildcard), and requires an ExternalId.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

READ_VERB = re.compile(r"^[a-z0-9-]+:(Get|List|Describe|BatchGet|Search|Lookup|View)[A-Za-z0-9]*\*?$")

# Read-only actions that do not start with a read verb. Each is named exactly, with its reason.
READ_EXCEPTIONS = {
    "apigateway:GET",  # API Gateway uses HTTP verbs as actions; GET reads configuration.
    "iam:SimulatePrincipalPolicy",  # Evaluates policies; changes nothing (CloudFox).
}

REQUIRED_DENY = {
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "s3:GetObject",
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    # ADR-0018: no bulk reads of code, images or log content.
    "ecr:BatchGetImage",
    "ecr:GetDownloadUrlForLayer",
    "lambda:GetFunction",
    "lambda:GetLayerVersion",
    "logs:FilterLogEvents",
    "logs:GetLogEvents",
}

# Denied on these resources only: apigateway:GET reads configuration everywhere else, but these
# paths return API key values (GetApiKeys with includeValues, GetUsagePlanKeys).
REQUIRED_RESOURCE_DENY = {
    "apigateway:GET": {
        "arn:*:apigateway:*::/apikeys",
        "arn:*:apigateway:*::/apikeys/*",
        "arn:*:apigateway:*::/usageplans/*/keys",
        "arn:*:apigateway:*::/usageplans/*/keys/*",
    },
}

ALLOWED_AWS_MANAGED = {"SecurityAudit", "job-function/ViewOnlyAccess"}


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that keeps CloudFormation short-form intrinsics (!Ref, !Sub, ...) as dicts."""


def _intrinsic(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)  # type: ignore[arg-type]
    name = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
    return {name: value}


CfnLoader.add_multi_constructor("!", _intrinsic)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _statements(document: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield from _as_list(document.get("Statement", []))


def check_template(template: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    resources: dict[str, Any] = template.get("Resources", {})
    deny_policies: set[str] = set()

    def check_permission_document(where: str, document: dict[str, Any]) -> set[str]:
        """The actions the document denies: on every resource, or (REQUIRED_RESOURCE_DENY) on
        at least the resources that must be denied."""
        denied: set[str] = set()
        for stmt in _statements(document):
            sid = stmt.get("Sid", "?")
            if "NotAction" in stmt or "NotResource" in stmt:
                errors.append(f"{where}/{sid}: NotAction/NotResource is not allowed")
            actions = [str(a) for a in _as_list(stmt.get("Action", []))]
            if stmt.get("Effect") == "Deny":
                resources = {str(r) for r in _as_list(stmt.get("Resource", []))}
                for action in actions:
                    if "*" in resources or REQUIRED_RESOURCE_DENY.get(action, {"*"}) <= resources:
                        denied.add(action)
                continue
            for action in actions:
                if action not in READ_EXCEPTIONS and not READ_VERB.match(action):
                    errors.append(f"{where}/{sid}: not a read action: {action}")
                if action in REQUIRED_DENY:
                    errors.append(f"{where}/{sid}: allows an action that must be denied: {action}")
        return denied

    for name, res in resources.items():
        rtype = res.get("Type")
        props = res.get("Properties", {})
        if rtype in ("AWS::IAM::ManagedPolicy", "AWS::IAM::Policy"):
            denied = check_permission_document(name, props.get("PolicyDocument", {}))
            if REQUIRED_DENY | set(REQUIRED_RESOURCE_DENY) <= denied:
                deny_policies.add(name)
        elif rtype == "AWS::IAM::Role":
            for inline in props.get("Policies", []):
                check_permission_document(
                    f"{name}/{inline.get('PolicyName', '?')}", inline.get("PolicyDocument", {})
                )
        elif rtype is not None and rtype.startswith("AWS::IAM::") and rtype not in (
            "AWS::IAM::Role",
        ):
            errors.append(f"{name}: unexpected IAM resource type {rtype}")

    for name, res in resources.items():
        if res.get("Type") != "AWS::IAM::Role":
            continue
        props = res.get("Properties", {})
        refs: set[str] = set()
        for arn in props.get("ManagedPolicyArns", []):
            if isinstance(arn, dict) and "Ref" in arn:
                refs.add(arn["Ref"])
                continue
            text = arn.get("Fn::Sub", "") if isinstance(arn, dict) else str(arn)
            match = re.search(r":iam::aws:policy/(.+)$", str(text))
            if not match or match.group(1) not in ALLOWED_AWS_MANAGED:
                errors.append(f"{name}: managed policy not allowed: {text}")
        if not refs & deny_policies:
            required = sorted(REQUIRED_DENY | set(REQUIRED_RESOURCE_DENY))
            errors.append(f"{name}: does not attach a policy denying {required}")

        for stmt in _statements(props.get("AssumeRolePolicyDocument", {})):
            sid = stmt.get("Sid", "trust")
            if stmt.get("Effect") != "Allow":
                continue
            if [str(a) for a in _as_list(stmt.get("Action", []))] != ["sts:AssumeRole"]:
                errors.append(f"{name}/{sid}: trust must allow only sts:AssumeRole")
            principal = stmt.get("Principal")
            aws = principal.get("AWS") if isinstance(principal, dict) else None
            if aws is None or isinstance(aws, list) or "*" in str(aws) or set(principal) != {"AWS"}:
                errors.append(f"{name}/{sid}: trust must name exactly one AWS principal, no wildcard")
            condition = stmt.get("Condition", {}).get("StringEquals", {})
            if "sts:ExternalId" not in condition:
                errors.append(f"{name}/{sid}: trust must require sts:ExternalId")
    return errors


def main(paths: list[str]) -> int:
    if not paths:
        print("usage: check_readonly.py TEMPLATE...", file=sys.stderr)
        return 2
    failed = False
    for path in paths:
        template = yaml.load(Path(path).read_text(), Loader=CfnLoader)  # noqa: S506 - SafeLoader subclass
        errors = check_template(template)
        for error in errors:
            print(f"{path}: {error}", file=sys.stderr)
        failed = failed or bool(errors)
        if not errors:
            print(f"{path}: read-only OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
