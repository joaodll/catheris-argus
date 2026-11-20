"""The asset taxonomy (metrics.categories): the one the screens group by. Its
cases came with it from the frontend (assetTypes.test.ts, 2026-11-10) on 2026-11-19."""

import pytest

from argus.metrics import ASSET_CATEGORIES, asset_category

CASES = [
    ("aws_ec2_instance", "Compute"),
    ("aws_ec2_launch_template", "Compute"),
    ("aws_lambda_function", "Compute"),
    ("aws_eks_cluster", "Containers"),
    ("aws_ecr_repository", "Containers"),
    ("aws_s3_bucket", "Storage"),
    ("aws_ebs_volume", "Storage"),
    ("aws_rds_db_instance", "Database"),
    ("aws_dynamodb_table", "Database"),
    ("aws_ec2_application_load_balancer", "Network"),
    ("aws_ec2_network_interface", "Network"),
    ("aws_vpc_security_group", "Network"),
    ("aws_api_gatewayv2_api", "Network"),
    ("aws_iam_role", "Identity"),
    ("aws_kms_key", "Security"),
    ("aws_wafv2_web_acl", "Security"),
    ("aws_glue_job", "Analytics"),
    ("aws_bedrock_agent", "Analytics"),
    ("aws_sqs_queue", "Integration"),
    ("aws_cloudtrail_trail", "Management"),
    ("aws_codebuild_project", "Management"),
    ("aws_iot_thing", "Other"),
    ("aws_something_new", "Other"),
    ("aws", "Other"),
]


@pytest.mark.parametrize(("resource_type", "category"), CASES, ids=[c[0] for c in CASES])
def test_a_type_is_placed_by_its_service_and_ec2_by_what_it_is(
    resource_type: str, category: str
) -> None:
    assert asset_category(resource_type) == category


def test_no_type_has_no_category() -> None:
    assert asset_category(None) is None
    assert asset_category("") is None


def test_eleven_categories_other_last() -> None:
    assert ASSET_CATEGORIES == (
        "Compute",
        "Containers",
        "Storage",
        "Database",
        "Network",
        "Identity",
        "Security",
        "Analytics",
        "Integration",
        "Management",
        "Other",
    )
