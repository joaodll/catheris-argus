"""steampipe_export_aws writes JSON columns as JSON text, not as objects (first real scan,
2026-10-06). The adapter decodes them before it reads or redacts a row."""

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import uuid4

from argus.core.manifest import Manifest, ManifestFile
from argus.core.rawstore import RawRun
from argus.core.redaction import REDACTED
from argus.inventory import parse_steampipe

ACCOUNT = "123456789012"
TG_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:targetgroup/web/0123456789abcdef"
FN_ARN = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:billing"
RULE_ARN = f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group-rule/sgr-0123456789abcdef0"


def _run(tmp_path: Path, tables: dict[str, list[dict[str, object]]]) -> RawRun:
    files = []
    for table, rows in tables.items():
        data = "".join(json.dumps(row) + "\n" for row in rows).encode()
        (tmp_path / f"{table}.jsonl").write_bytes(data)
        files.append(
            ManifestFile(
                path=f"{table}.jsonl", bytes=len(data), sha256=hashlib.sha256(data).hexdigest()
            )
        )
    now = datetime.now(UTC)
    manifest = Manifest(
        run_uid=uuid4(),
        tool="steampipe",
        tool_version="1.34.0",
        account_id=ACCOUNT,
        source="aws",
        snapshot_date=date(2026, 10, 6),
        region_scope=["us-east-1"],
        started_at=now,
        finished_at=now,
        status="complete",
        exit_code=0,
        throttle_events=0,
        files=files,
    )
    return RawRun(manifest=manifest, root=tmp_path)


def test_json_text_columns_are_decoded(tmp_path: Path) -> None:
    health = [
        {"Target": {"Id": "i-0123456789abcdef0", "Port": 80}, "TargetHealth": {"State": "healthy"}}
    ]
    run = _run(
        tmp_path,
        {
            "aws_ec2_target_group": [
                {
                    "target_group_arn": TG_ARN,
                    "target_group_name": "web",
                    "region": "us-east-1",
                    "target_health_descriptions": json.dumps(health),
                    "tags": json.dumps({"team": "payments"}),
                }
            ],
            # The uid column itself can be JSON text.
            "aws_vpc_security_group_rule": [
                {
                    "akas": json.dumps([RULE_ARN]),
                    "security_group_rule_id": "sgr-0123456789abcdef0",
                    "region": "us-east-1",
                }
            ],
        },
    )
    batch = parse_steampipe(run)
    assert batch.skipped == []
    group, rule = sorted(batch.resources, key=lambda r: r.type)
    assert group.tags == {"team": "payments"}
    # Health is volatile and dropped; the registered target is kept.
    assert group.config["target_health_descriptions"] == [
        {"Target": {"Id": "i-0123456789abcdef0", "Port": 80}}
    ]
    assert rule.uid == RULE_ARN


def test_text_that_is_not_json_is_kept(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            "aws_lambda_function": [
                {"arn": FN_ARN, "name": "billing", "description": "[legacy] {billing}"}
            ]
        },
    )
    (function,) = parse_steampipe(run).resources
    assert function.config["description"] == "[legacy] {billing}"


def test_secrets_in_json_text_are_redacted_per_key(tmp_path: Path) -> None:
    variables = {"Variables": {"DB_PASSWORD": "pw-hunter2", "STAGE": "prod"}}
    run = _run(
        tmp_path,
        {
            "aws_lambda_function": [
                {
                    "arn": FN_ARN,
                    "name": "billing",
                    "environment_variables": json.dumps(variables),
                }
            ]
        },
    )
    (function,) = parse_steampipe(run).resources
    blob = json.dumps(function.config)
    assert "pw-hunter2" not in blob and "prod" not in blob
    # The shape survives: which variables exist is configuration, their values are not.
    assert function.config["environment_variables"] == {
        "Variables": {"DB_PASSWORD": REDACTED, "STAGE": REDACTED}
    }
