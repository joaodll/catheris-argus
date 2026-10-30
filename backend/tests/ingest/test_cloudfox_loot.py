"""The CloudFox loot adapter (ADR-0038): parsing the allowlisted files into labelled commands,
tied to a resource, with no secret value reaching the batch. Pure; no database."""

import hashlib
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from argus.attackpaths.cloudfox import (
    ACTS_ON_TARGET,
    CHECK,
    READS_DATA,
    _classify,
    parse_cloudfox,
)
from argus.core.manifest import Manifest, ManifestFile
from argus.core.rawstore import RawRun

ACCOUNT = "123456789012"
BUCKET = "prod-web-assets"
INSTANCE = "i-0abc1234def56789a"
PUBLIC_IP = "54.12.34.56"


def _run(tmp_path: Path, loot: dict[str, str]) -> RawRun:
    (tmp_path / "loot").mkdir(parents=True)
    files = []
    for name, body in loot.items():
        data = body.encode()
        (tmp_path / "loot" / name).write_bytes(data)
        files.append(
            ManifestFile(
                path=f"loot/{name}", bytes=len(data), sha256=hashlib.sha256(data).hexdigest()
            )
        )
    now = datetime.now(UTC)
    manifest = Manifest(
        run_uid=uuid4(),
        tool="cloudfox",
        tool_version="2.0.5",
        account_id=ACCOUNT,
        source="aws",
        snapshot_date=date(2026, 10, 14),
        region_scope=["us-east-1"],
        started_at=now,
        finished_at=now,
        status="complete",
        exit_code=0,
        throttle_events=0,
        files=files,
    )
    return RawRun(manifest=manifest, root=tmp_path)


def test_classify_table_and_fail_closed() -> None:
    assert _classify("aws --profile $p s3 ls s3://b/") == CHECK
    assert (
        _classify("aws --profile $p --region us-east-1 lambda get-function --function-name f")
        == CHECK
    )
    assert _classify("aws --profile $p --region us-east-1 eks update-kubeconfig --name c") == CHECK
    assert _classify("sudo nmap -Pn -sV -p 22 1.2.3.4") == CHECK
    assert _classify("curl -X GET https://api.example.com/orders") == CHECK
    assert _classify("aws --profile $p s3 cp s3://b/ ./out --recursive") == READS_DATA
    assert (
        _classify("aws --profile $p --region us-east-1 sqs receive-message --queue-url u")
        == READS_DATA
    )
    # A session, a write and an unknown operation all act on the target.
    assert (
        _classify("aws --profile $p --region us-east-1 ssm start-session --target i-1")
        == ACTS_ON_TARGET
    )
    assert _classify("aws --profile $p sns publish --topic-arn a --message m") == ACTS_ON_TARGET
    assert _classify("aws --profile $p ec2 some-new-operation --flag x") == ACTS_ON_TARGET
    assert _classify("curl -X POST https://api.example.com/orders") == ACTS_ON_TARGET


@pytest.mark.parametrize(
    ("command", "label"),
    [
        ("aws --profile $p s3 ls s3://b/ && aws --profile $p s3 rm s3://b/x", ACTS_ON_TARGET),
        ("aws --profile $p s3 ls s3://b/ | grep key", ACTS_ON_TARGET),
        ("aws --profile $p s3 ls s3://b/; nmap -Pn 1.2.3.4", CHECK),
        ("aws --profile $p s3 ls $(cat bucket)", ACTS_ON_TARGET),
        ("docker pull 1.dkr.ecr.us-east-1.amazonaws.com/repo:tag", READS_DATA),
        ("docker push 1.dkr.ecr.us-east-1.amazonaws.com/repo:tag", ACTS_ON_TARGET),
        ("docker run --rm repo", ACTS_ON_TARGET),
        ("curl https://h.example.com/", CHECK),
        ("curl -o out https://h.example.com/file", READS_DATA),
        ("curl -X POST -o out https://h.example.com/", ACTS_ON_TARGET),
        ("curl -XPOST https://h.example.com/", ACTS_ON_TARGET),
        ("curl --request PUT https://h.example.com/", ACTS_ON_TARGET),
        ("curl -d a=b https://h.example.com/", ACTS_ON_TARGET),
        ("curl --data-raw x https://h.example.com/", ACTS_ON_TARGET),
        ("wget https://h.example.com/file", READS_DATA),
        ("wget --post-data=a https://h.example.com/", ACTS_ON_TARGET),
        ("AWS_PROFILE=p aws s3 ls s3://b/", CHECK),
        ("", ACTS_ON_TARGET),
    ],
    ids=[f"case-{i}" for i in range(18)],
)
def test_classify_judges_every_part_and_fails_closed(command: str, label: str) -> None:
    assert _classify(command) == label


def test_commands_are_labelled_and_tied_to_their_resource(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            "bucket-commands.txt": (
                f"# Bucket: {BUCKET}\n"
                f"aws --profile $profile s3 ls --recursive s3://{BUCKET}/\n"
                "# Download the whole bucket\n"
                f"aws --profile $profile s3 cp s3://{BUCKET}/ ./out --recursive\n"
            ),
            "instances-ssmCommands.txt": (
                "-----------------------------------------------------------------------\n"
                f"############## Instance: {INSTANCE}  ##############\n"
                "-----------------------------------------------------------------------\n"
                f"aws --profile $profile --region us-east-1 ssm start-session --target {INSTANCE}\n"
            ),
            "network-ports-public-ipv4.txt": (
                "#############################################\n"
                "# The network services may have various ingress rules.\n"
                "#############################################\n"
                f"sudo nmap -Pn -sV -p 22,443 {PUBLIC_IP}\n"
            ),
        },
    )
    commands = parse_cloudfox(run).commands
    by_label = {(c.label, c.source) for c in commands}
    assert (CHECK, "bucket-commands.txt") in by_label
    assert (READS_DATA, "bucket-commands.txt") in by_label
    assert (ACTS_ON_TARGET, "instances-ssmCommands.txt") in by_label
    assert (CHECK, "network-ports-public-ipv4.txt") in by_label

    ls = next(c for c in commands if c.label == CHECK and c.source == "bucket-commands.txt")
    assert ls.resource_uid == f"arn:aws:s3:::{BUCKET}"
    cp = next(c for c in commands if c.label == READS_DATA)
    assert cp.note is not None and "Download" in cp.note  # CloudFox's comment is kept
    ssm = next(c for c in commands if c.source == "instances-ssmCommands.txt")
    assert ssm.resource_uid == f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/{INSTANCE}"
    nmap = next(c for c in commands if c.source == "network-ports-public-ipv4.txt")
    assert nmap.resource_host == PUBLIC_IP  # resolved to its owner at load time


def test_excluded_loot_is_never_read_and_credentials_are_masked(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            # Not on the allowlist: a secret-bearing file is never opened.
            "env-vars.txt": "Lambda status DB_PASSWORD=super-secret-value\n",
            "instance-userdata.txt": "export TOKEN=another-secret\n",
            # Allowlisted, but a credential slipped into a URL: it is masked before storage.
            "bucket-commands.txt": (
                "# Bucket: b\n"
                "aws --profile $profile s3 ls s3://b/\n"
                "# See https://user:hunter2@internal.example.com/creds\n"
                "aws --profile $profile s3 cp s3://b/ ./out --recursive\n"
            ),
        },
    )
    commands = parse_cloudfox(run).commands
    blob = "\n".join(c.command + " " + (c.note or "") for c in commands)
    assert "super-secret-value" not in blob
    assert "another-secret" not in blob
    assert "hunter2" not in blob
    assert all("DB_PASSWORD" not in c.command for c in commands)
