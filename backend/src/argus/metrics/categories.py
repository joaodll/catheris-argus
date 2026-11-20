"""Assets by category: the one taxonomy every screen and report groups inventory types by.

The Overview's Inventory card, the Resources Summary and the Map's start and glyphs read it from
here (round 5, 2026-11-10, palace frontend/1d636dd5; moved from the frontend 2026-11-19, when the
PDF reports also counted assets by category, until 2026-11-20). The API carries a type's category
beside the type; the frontend holds no copy.

Types are matched by their service segment (`aws_<service>_...`): every configuration table is
inventoried, so they are not listed one by one. EC2 holds both instances and their network: its
compute types are Compute, the rest Network. A service listed nowhere is Other.
"""

import re

OTHER = "Other"

_SERVICES: dict[str, tuple[str, ...]] = {
    "Compute": (
        "lambda", "batch", "elastic", "lightsail", "app", "appstream", "workspaces",
        "serverlessapplicationrepository", "amplify",
    ),
    "Containers": ("ecs", "eks", "ecr", "ecrpublic"),
    "Storage": (
        "s3", "s3tables", "ebs", "efs", "fsx", "glacier", "backup", "dlm", "drs", "datasync",
        "transfer", "media",
    ),
    "Database": (
        "rds", "dynamodb", "docdb", "neptune", "dax", "memorydb", "elasticache", "keyspaces",
        "timestreamwrite", "redshift", "redshiftserverless", "dms",
    ),
    "Network": (
        "vpc", "ec2", "route53", "cloudfront", "api", "globalaccelerator", "directconnect",
        "service",
    ),
    "Identity": (
        "iam", "identitystore", "ssoadmin", "cognito", "rolesanywhere", "organizations",
        "directory", "ram",
    ),
    "Security": (
        "kms", "acm", "acmpca", "secretsmanager", "accessanalyzer", "guardduty", "inspector",
        "inspector2", "macie2", "securityhub", "securitylake", "shield", "waf", "wafregional",
        "wafv2", "fms", "networkfirewall", "auditmanager",
    ),
    "Analytics": (
        "athena", "glue", "lakeformation", "emr", "kinesis", "kinesisanalyticsv2", "msk",
        "mskconnect", "opensearch", "elasticsearch", "cloudsearch", "quicksight", "sagemaker",
        "bedrock",
    ),
    "Integration": (
        "sns", "sqs", "eventbridge", "pipes", "scheduler", "sfn", "mq", "appsync", "ses",
        "pinpoint",
    ),
    "Management": (
        "cloudformation", "cloudtrail", "cloudwatch", "config", "ssm", "ssmincidents",
        "servicecatalog", "servicequotas", "account", "oam", "resource", "region", "synthetics",
        "appconfig", "mgn", "codeartifact", "codebuild", "codecommit", "codedeploy",
        "codepipeline", "codestar",
    ),
}  # fmt: skip

# The categories in their fixed order, Other last.
ASSET_CATEGORIES: tuple[str, ...] = (*_SERVICES, OTHER)
_CATEGORY_OF = {service: name for name, services in _SERVICES.items() for service in services}
_EC2_COMPUTE = re.compile(
    r"^aws_ec2_(instance|ami|autoscaling|launch|fleet|spot|capacity|placement|key_pair)"
)


def asset_category(resource_type: str | None) -> str | None:
    """A type's category; None when there is no type (a resource outside the inventory)."""
    if not resource_type:
        return None
    if _EC2_COMPUTE.match(resource_type):
        return "Compute"
    parts = resource_type.split("_")
    return _CATEGORY_OF.get(parts[1] if len(parts) > 1 else "", OTHER)
