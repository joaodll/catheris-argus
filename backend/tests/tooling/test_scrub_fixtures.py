"""The scrubber is the only path from raw scan output into git, so its guarantees are tested
against a hand-made run that shares identities across all three tools."""

import csv
import gzip
import io
import json
import re
import stat
from pathlib import Path

import pytest
from tests.tooling import scrub_fixtures
from tests.tooling.scrub_fixtures import scrub_run

from argus.core.redaction import REDACTED

ACCOUNT = "246813579024"
ROLE = "PhoenixDeployRole"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/{ROLE}"
BUCKET = "acme-payroll-exports"
BUCKET_ARN = f"arn:aws:s3:::{BUCKET}"
FUNCTION_ARN = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:status"
INSTANCE = "i-0abc1234def567890"
EMAIL = "jane.doe@acme-corp.com"
PUBLIC_IP = "54.12.34.56"
PUBLIC_IP6 = "2600:1f18:abcd:1200::42"
USER_DATA = "IyEvYmluL2Jhc2gKZXhwb3J0IERCX1BBU1M9czNjcjN0"
PRIVATE_IP = "10.0.1.5"
TAG_VALUE = "Project Phoenix"
# Assembled at runtime so no secret-shaped literal sits in the repository.
ACCESS_KEY = "AKIA" + "QX7R" * 4
USER_KEY = "AKIA" + "MZ4P" * 4  # an IAM user's key id, listed by Steampipe
IAM_USER = "deploy-bot"
PASSWORD_LINE = "pass" + "word=" + "hunter2hunter2"

ENV_VALUE = "postgres://app:" + "Sup3rS3cret" + "@db.internal/app"

ORIGINALS = [
    ACCOUNT,
    ROLE,
    BUCKET,
    INSTANCE,
    EMAIL,
    PUBLIC_IP,
    PUBLIC_IP6,
    TAG_VALUE,
    ACCESS_KEY,
    USER_KEY,
    IAM_USER,
    USER_DATA,
    ENV_VALUE,
]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


DAY_DIR = Path("2026", "10", "02")  # <YYYY>/<MM>/<DD>; one 2026-10-02 folder before 2026-10-06


def _make_run(spike: Path, run_id: str, day_dir: Path = DAY_DIR) -> None:
    def run_dir(tool: str) -> Path:
        return spike / "raw" / tool / "aws" / "sandbox" / day_dir / run_id

    _write(
        run_dir("prowler") / "output" / "prowler-output.ocsf.json",
        json.dumps(
            [
                {
                    "cloud": {"account": {"uid": ACCOUNT}},
                    "resources": [
                        {"uid": ROLE_ARN, "name": ROLE, "tags": {"Project": TAG_VALUE}},
                        {"uid": BUCKET_ARN, "name": BUCKET},
                        {"uid": f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/{INSTANCE}"},
                    ],
                    "status_code": "FAIL",
                    "resource_details": {
                        "metadata": {"Environment": {"Variables": {"DB_URL": ENV_VALUE}}}
                    },
                    "unmapped": {"owner": EMAIL, "account_number": int(ACCOUNT)},
                }
            ]
        ),
    )
    _write(
        run_dir("prowler") / "output" / "compliance" / "cis_4.0_aws.csv",
        f"ACCOUNTID;RESOURCEID;STATUS\n{ACCOUNT};{ROLE_ARN};FAIL\n".replace(";", ","),
    )
    cf = run_dir("cloudfox")  # the archived layout: CloudFox's wrapper folders removed
    _write(cf / "csv" / "role-trusts.csv", f"Role Arn,Trusted Principal\n{ROLE_ARN},{ROLE_ARN}\n")
    _write(
        cf / "csv" / "env-vars.csv",
        f"Service,Name,Key,Value\nLambda,{FUNCTION_ARN},AWS_KEY,{ACCESS_KEY}\nLambda,status,DB,secretvalue\n",
    )
    _write(cf / "loot" / "env-vars.txt", f"{PASSWORD_LINE}\n")
    _write(
        cf / "loot" / "instance-userdata.txt", f"Instance: {INSTANCE}\nUser Data:\n{USER_DATA}\n"
    )
    _write(cf / "loot" / "cloudformation-data.txt", f"{PASSWORD_LINE}\n")
    # Loot without secret values is scrubbed and kept, like any other text file.
    _write(cf / "loot" / "route53-A-records-public-Zones.txt", "www.example.com.\n")
    sp = run_dir("steampipe")
    _write(
        sp / "aws_iam_role.jsonl",
        json.dumps(
            {"arn": ROLE_ARN, "name": ROLE, "account_id": ACCOUNT, "tags": {"Project": TAG_VALUE}}
        )
        + "\n",
    )
    _write(
        sp / "aws_lambda_function.jsonl",
        json.dumps(
            {
                "arn": FUNCTION_ARN,
                "name": "status",
                "status": "Active",
                "environment_variables": {"DB_URL": ENV_VALUE},
            }
        )
        + "\n",
    )
    _write(
        sp / "aws_iam_access_key.jsonl",
        json.dumps(
            {
                "access_key_id": USER_KEY,
                "user_name": IAM_USER,
                "status": "Active",
                "access_key_last_used_date": "2026-09-30T12:00:00Z",
                "account_id": ACCOUNT,
                "akas": [f"arn:aws:iam::{ACCOUNT}:user/{IAM_USER}/accesskey/{USER_KEY}"],
            }
        )
        + "\n",
    )
    _write(
        sp / "aws_ec2_instance.jsonl",
        json.dumps(
            {
                "instance_id": INSTANCE,
                "public_ip_address": PUBLIC_IP,
                "private_ip_address": PRIVATE_IP,
                "ipv6_address": PUBLIC_IP6,
                "user_data": USER_DATA,
            }
        )
        + "\n",
    )


@pytest.fixture
def scrubbed(tmp_path: Path) -> tuple[Path, Path, list[str]]:
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "run-1")
    dropped = scrub_run(spike, "run-1", out)
    return spike, out, dropped


def _all_text(out: Path) -> str:
    return "\n".join(f"{p}\n{p.read_text()}" for p in out.rglob("*") if p.is_file())


def _jsonl(path: Path) -> dict[str, object]:
    return json.loads(path.read_text().splitlines()[0])


def test_no_original_value_survives(scrubbed: tuple[Path, Path, list[str]]) -> None:
    _, out, _ = scrubbed
    text = _all_text(out)
    for original in ORIGINALS:
        assert original not in text, original


def test_one_identity_across_tools(scrubbed: tuple[Path, Path, list[str]]) -> None:
    _, out, _ = scrubbed
    role_uid = _jsonl(out / "steampipe" / "aws_iam_role.jsonl")["arn"]
    prowler = json.loads((out / "prowler" / "output" / "prowler-output.ocsf.json").read_text())
    trusts = next((out / "cloudfox").rglob("role-trusts.csv")).read_text()

    assert prowler[0]["resources"][0]["uid"] == role_uid
    assert str(role_uid) in trusts
    assert str(role_uid).startswith("arn:aws:iam::1000000000")


def test_json_keys_survive_a_resource_named_like_a_key(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    _, out, _ = scrubbed
    function = _jsonl(out / "steampipe" / "aws_lambda_function.jsonl")
    assert set(function) == {"arn", "name", "status", "environment_variables"}
    assert function["status"] == "Active"
    assert function["name"] != "status"


def test_numeric_account_ids_are_scrubbed(scrubbed: tuple[Path, Path, list[str]]) -> None:
    _, out, _ = scrubbed
    prowler = json.loads((out / "prowler" / "output" / "prowler-output.ocsf.json").read_text())
    number = prowler[0]["unmapped"]["account_number"]
    assert isinstance(number, int)
    assert str(number) == prowler[0]["cloud"]["account"]["uid"]


def test_csv_headers_kept_and_env_var_values_blanked(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    _, out, dropped = scrubbed
    rows = list(csv.reader(io.StringIO(next((out / "cloudfox").rglob("env-vars.csv")).read_text())))
    assert rows[0] == ["Service", "Name", "Key", "Value"]
    assert {row[3] for row in rows[1:]} == {REDACTED}
    assert any("env-vars.txt" in d for d in dropped)
    assert not list((out / "cloudfox").rglob("env-vars.txt"))


def test_secret_bearing_loot_dropped_other_loot_kept(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    # CloudFox's user data and stack data loot hold secret values in free text (2026-10-14).
    _, out, dropped = scrubbed
    for name in ("instance-userdata.txt", "cloudformation-data.txt"):
        assert any(name in d for d in dropped)
        assert not list(out.rglob(name))
    assert list((out / "cloudfox").rglob("route53-A-records-public-Zones.txt"))
    assert not any(USER_DATA in p.read_text() for p in out.rglob("*") if p.is_file())


def test_public_ips_replaced_private_ips_kept(scrubbed: tuple[Path, Path, list[str]]) -> None:
    _, out, _ = scrubbed
    instance = _jsonl(out / "steampipe" / "aws_ec2_instance.jsonl")
    assert instance["private_ip_address"] == PRIVATE_IP
    assert str(instance["public_ip_address"]).rsplit(".", 1)[0] in {
        "192.0.2",
        "198.51.100",
        "203.0.113",
    }


def test_mapping_is_private_and_stable_across_runs(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    spike, out, _ = scrubbed
    mapping = spike / "scrub-mapping.json"
    assert stat.S_IMODE(mapping.stat().st_mode) == 0o600
    first = _jsonl(out / "steampipe" / "aws_iam_role.jsonl")["arn"]

    _make_run(spike, "run-2")
    scrub_run(spike, "run-2", out)

    assert _jsonl(out / "steampipe" / "aws_iam_role.jsonl")["arn"] == first


def test_each_tool_can_have_its_own_run_id(tmp_path: Path) -> None:
    """The worker gives every run its own id, so the three tools' runs differ."""
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "shared")
    day = Path("aws", "sandbox") / DAY_DIR
    for tool in ("steampipe", "prowler", "cloudfox"):
        (spike / "raw" / tool / day / "shared").rename(spike / "raw" / tool / day / f"{tool}-1")
    scrub_run(spike, ["steampipe-1", "prowler-1", "cloudfox-1"], out)
    assert (out / "steampipe" / "aws_iam_role.jsonl").exists()
    with pytest.raises(SystemExit, match="expected one run directory"):
        scrub_run(spike, ["steampipe-1", "prowler-1"], out)


def test_a_run_in_the_older_date_layout_is_found(tmp_path: Path) -> None:
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "old-1", day_dir=Path("2026-10-02"))
    scrub_run(spike, "old-1", out)
    assert (out / "steampipe" / "aws_iam_role.jsonl").exists()


def test_self_check_refuses_to_write_a_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "run-1")
    monkeypatch.setattr(scrub_fixtures.Scrubber, "scrub_text", lambda self, text: text)

    with pytest.raises(SystemExit, match="original values survived"):
        scrub_run(spike, "run-1", out)
    assert not out.exists()


def test_env_vars_csv_without_value_column_is_refused(tmp_path: Path) -> None:
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "run-1")
    env = next(spike.rglob("env-vars.csv"))
    env.write_text("Service,Name,Secret\nLambda,x,y\n")

    with pytest.raises(ValueError, match="Value column"):
        scrub_run(spike, "run-1", out)


def test_output_of_a_failed_run_is_refused(tmp_path: Path) -> None:
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "run-1")
    next(spike.rglob("aws_iam_role.jsonl")).write_text("[ERROR] no connection data loaded\n")

    with pytest.raises(SystemExit, match="complete runs only"):
        scrub_run(spike, "run-1", out)
    assert not out.exists()


def test_secret_bearing_fields_are_redacted_keeping_shape(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    _, out, _ = scrubbed
    function = _jsonl(out / "steampipe" / "aws_lambda_function.jsonl")
    instance = _jsonl(out / "steampipe" / "aws_ec2_instance.jsonl")
    prowler = json.loads((out / "prowler" / "output" / "prowler-output.ocsf.json").read_text())

    assert function["environment_variables"] == {"DB_URL": REDACTED}
    assert instance["user_data"] == REDACTED
    assert prowler[0]["resource_details"]["metadata"]["Environment"] == {
        "Variables": {"DB_URL": REDACTED}
    }


def test_public_ipv6_replaced_with_documentation_range(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    _, out, _ = scrubbed
    instance = _jsonl(out / "steampipe" / "aws_ec2_instance.jsonl")
    assert str(instance["ipv6_address"]).startswith("2001:db8::")


def test_symlink_in_raw_output_is_refused(tmp_path: Path) -> None:
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "run-1")
    target = tmp_path / "outside.txt"
    target.write_text("not part of the run")
    (next(spike.rglob("aws_iam_role.jsonl")).parent / "link.txt").symlink_to(target)

    with pytest.raises(SystemExit, match="symlink"):
        scrub_run(spike, "run-1", out)


def test_aws_ids_keep_their_shape_and_join_across_tools(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    _, out, _ = scrubbed
    short_id = str(_jsonl(out / "steampipe" / "aws_ec2_instance.jsonl")["instance_id"])
    prowler = json.loads((out / "prowler" / "output" / "prowler-output.ocsf.json").read_text())

    assert re.fullmatch(r"i-[0-9a-f]{17}", short_id)
    assert prowler[0]["resources"][2]["uid"].endswith(f":instance/{short_id}")


def test_an_access_key_id_is_kept_under_one_pseudonym(
    scrubbed: tuple[Path, Path, list[str]],
) -> None:
    """Key ids are identifiers the inventory joins on (the key's uid): each gets one stable
    pseudonym without a credential shape, instead of REDACTED, which would merge every key."""
    _, out, _ = scrubbed
    key = _jsonl(out / "steampipe" / "aws_iam_access_key.jsonl")
    pseudonym = key["access_key_id"]
    assert isinstance(pseudonym, str) and pseudonym.startswith("FIXTUREKEY")
    assert key["akas"] == [
        f"arn:aws:iam::{key['account_id']}:user/{key['user_name']}/accesskey/{pseudonym}"
    ]
    assert key["user_name"] != IAM_USER
    assert key["access_key_last_used_date"] == "2026-09-30T12:00:00Z"  # not secret: kept


def test_a_compressed_run_becomes_plain_fixtures(tmp_path: Path) -> None:
    """Raw output is <file>.gz beside a plain manifest since 2026-10-08."""
    spike, out = tmp_path / "spike", tmp_path / "fixtures"
    _make_run(spike, "gz-1")
    for path in sorted((spike / "raw").rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            path.with_name(path.name + ".gz").write_bytes(gzip.compress(path.read_bytes()))
            path.unlink()
        elif path.name == "manifest.json":
            manifest = json.loads(path.read_text())
            path.write_text(json.dumps({**manifest, "raw_compression": "gzip"}))
    scrub_run(spike, "gz-1", out)
    assert (out / "steampipe" / "aws_iam_role.jsonl").exists()
    assert not list(out.rglob("*.gz"))
    for manifest in out.rglob("manifest.json"):
        assert "raw_compression" not in json.loads(manifest.read_text())


def test_a_secret_arn_is_a_name_and_compact_json_stays_whole() -> None:
    """A Secrets Manager ARN holds "secret:<name>", not a value: it is kept, and a policy that
    names it stays parseable JSON (2026-10-22: the pattern ate the rest of the document)."""
    arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/db-AbCdEf"
    statement = {"Action": ["secretsmanager:getsecretvalue"], "Resource": [arn]}
    policy = json.dumps({"Statement": [statement]}, separators=(",", ":"))
    text = policy
    for pattern in scrub_fixtures.SECRET_PATTERNS:
        text = pattern.sub("REDACTED", text)
    assert json.loads(text)["Statement"][0]["Resource"] == [arn]
    # Free text still loses the value, a comma in it included.
    for value in ("s3cr3t-value", "Ab1,xyz9q", "ab;cdefgh"):
        free = "export " + "PASSWORD=" + value
        for pattern in scrub_fixtures.SECRET_PATTERNS:
            free = pattern.sub("REDACTED", free)
        assert free == "export REDACTED", value
