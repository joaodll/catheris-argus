"""Any table of the list is inventoried (argus_v8: every configuration table), and a partial
run is complete for every table it did not list as incomplete."""

from pathlib import Path

from tests.ingest.test_steampipe_json_text import ACCOUNT, _run

from argus.inventory import is_asset, parse_steampipe

KEY_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"
TOPIC_ARN = f"arn:aws:sns:us-east-1:{ACCOUNT}:alerts"


def test_a_table_without_an_override_uses_arn_then_akas(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            "aws_sns_topic": [
                {
                    "topic_arn": TOPIC_ARN,
                    "title": "alerts",
                    "akas": [TOPIC_ARN],
                    "region": "us-east-1",
                },
            ],
            "aws_ecr_repository": [
                {
                    "arn": f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/web",
                    "name": "web",
                    "region": "us-east-1",
                    "tags": {"team": "a"},
                },
                {"name": "no-arn", "title": "no-arn", "region": "us-east-1"},
            ],
        },
    )
    batch = parse_steampipe(run)
    by_type = {r.type: r for r in batch.resources}
    topic = by_type["aws_sns_topic"]
    assert (topic.uid, topic.native_id, topic.name) == (TOPIC_ARN, "alerts", "alerts")
    repo = by_type["aws_ecr_repository"]
    assert (repo.native_id, repo.name, repo.tags) == ("web", "web", {"team": "a"})
    assert batch.skipped == ["aws_ecr_repository:no-arn"]  # reported, never dropped silently


def test_an_arn_two_tables_report_belongs_to_the_one_that_owns_it(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            "aws_kms_key_rotation": [
                {"key_arn": KEY_ARN, "akas": [KEY_ARN], "region": "us-east-1"}
            ],
            "aws_kms_key": [{"arn": KEY_ARN, "id": "0f1e2d3c", "region": "us-east-1"}],
        },
    )
    batch = parse_steampipe(run)
    assert [(r.uid, r.type) for r in batch.resources] == [(KEY_ARN, "aws_kms_key")]
    assert batch.skipped == [f"aws_kms_key_rotation:{KEY_ARN} (also in aws_kms_key)"]


def test_a_partial_run_is_complete_for_its_other_tables(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            "aws_sns_topic": [{"topic_arn": TOPIC_ARN, "akas": [TOPIC_ARN]}],
            "aws_kms_key": [{"arn": KEY_ARN, "id": "k"}],
        },
    )
    partial = run.manifest.model_copy(
        update={"status": "partial", "incomplete_tables": ["aws_kms_key", "aws_s3_bucket"]}
    )
    batch = parse_steampipe(run.__class__(manifest=partial, root=run.root))
    assert batch.complete_types == {"aws_sns_topic"}
    assert batch.carry_types == {"aws_kms_key", "aws_s3_bucket"}

    # A partial manifest that names no table (older runs, synthetic throttling): nothing is
    # complete, everything carries forward.
    older = run.manifest.model_copy(update={"status": "partial"})
    batch = parse_steampipe(run.__class__(manifest=older, root=run.root))
    assert batch.complete_types == frozenset() and batch.carry_types is None


def test_a_complete_run_carries_the_tables_not_used_in_the_account(tmp_path: Path) -> None:
    """ADR-0012, second amendment: a table whose service is not used here, or that a resource
    refused, is carried forward, and the run stays complete."""
    run = _run(tmp_path, {"aws_sns_topic": [{"topic_arn": TOPIC_ARN, "akas": [TOPIC_ARN]}]})
    complete = run.manifest.model_copy(
        update={
            "incomplete_tables": ["aws_timestreamwrite_table"],
            "not_applicable_tables": ["aws_timestreamwrite_table"],
        }
    )
    batch = parse_steampipe(run.__class__(manifest=complete, root=run.root))
    assert batch.complete and batch.complete_types == {"aws_sns_topic"}
    assert batch.carry_types == {"aws_timestreamwrite_table"}


def test_parts_settings_and_links_are_not_assets() -> None:
    assert is_asset("aws_ec2_instance") and is_asset("aws_iam_policy")
    for part in (
        "aws_vpc_security_group_rule",
        "aws_kms_key_rotation",
        "aws_lambda_version",
        "aws_iam_policy_attachment",
        "aws_vpc_security_group_vpc_association",
    ):
        assert not is_asset(part), part
