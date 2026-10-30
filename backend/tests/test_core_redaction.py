import pytest

from argus.core.redaction import (
    ENCODED_OMITTED,
    NOT_SECRET_COLUMNS,
    REDACTED,
    TABLE_ROW_OMITTED,
    is_secret_key,
    mask_url_credentials,
    redact,
    redact_text,
)


@pytest.mark.parametrize(
    "key",
    [
        "environment_variables",
        "Environment",
        "Variables",
        "user_data",
        "UserData",
        "DB_PASSWORD",
        "SessionToken",
        "secret_access_key",
        "SecretAccessKey",
        "private_key",
        "api_key",
        "Credentials",
        # An ExternalId (ADR-0024, amended 2026-10-23): a trust condition, CloudFox's column.
        "sts:ExternalId",
        "ExternalID",
        "external_id",
    ],
)
def test_secret_keys(key: str) -> None:
    assert is_secret_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "HttpTokens",
        "metadata_options",
        "instance_type",
        "arn",
        "security_groups",
        "keys",
        "public_ip_address",
        "tags",
        "ExternalIdentityProvider",
    ],
)
def test_ordinary_keys(key: str) -> None:
    assert not is_secret_key(key)


def test_a_secret_name_value_pair_loses_its_value() -> None:
    """CloudFormation parameters and Beanstalk option settings name a setting in one key and
    hold its value in another; the name decides (argus_v8)."""
    config = {
        "parameters": [
            {"ParameterKey": "DbPassword", "ParameterValue": "pw"},
            {"ParameterKey": "Stage", "ParameterValue": "prod"},
        ],
        "configuration_settings": [
            {
                "Namespace": "aws:elasticbeanstalk:application:environment",
                "OptionName": "API_TOKEN",
                "Value": "t",
            },
            {"Namespace": "aws:autoscaling:asg", "OptionName": "MinSize", "Value": "1"},
        ],
        "tags_src": [{"Key": "owner", "Value": "team-a"}],
    }
    assert redact(config) == {
        "parameters": [
            {"ParameterKey": "DbPassword", "ParameterValue": REDACTED},
            {"ParameterKey": "Stage", "ParameterValue": "prod"},
        ],
        "configuration_settings": [
            {
                "Namespace": "aws:elasticbeanstalk:application:environment",
                "OptionName": "API_TOKEN",
                "Value": REDACTED,
            },
            {"Namespace": "aws:autoscaling:asg", "OptionName": "MinSize", "Value": "1"},
        ],
        "tags_src": [{"Key": "owner", "Value": "team-a"}],
    }


def test_stack_outputs_and_secrets_inside_text_values_are_masked() -> None:
    """Security review, argus_v8: outputs are name/value pairs too, and an inline buildspec
    or an event's input is text a secret can be written into."""
    buildspec = "version: 0.2\nenv:\n  variables:\n    DB_PASSWORD: hunter2\n    STAGE: prod\n"
    config = {
        "outputs": [{"OutputKey": "AdminPassword", "OutputValue": "generated"}],
        "source": {"Type": "GITHUB", "Buildspec": buildspec},
        "targets": [{"Id": "t1", "Input": '{"token": "abc123", "region": "us-east-1"}'}],
        "arn": "arn:aws:iam::123456789012:role/app",
        "description": "Name: web, owner: team-a",
    }
    redacted = redact(config)
    assert redacted["outputs"] == [{"OutputKey": "AdminPassword", "OutputValue": REDACTED}]
    assert "hunter2" not in redacted["source"]["Buildspec"]
    assert "STAGE" in redacted["source"]["Buildspec"]
    assert "abc123" not in redacted["targets"][0]["Input"]
    assert '"region": "us-east-1"' in redacted["targets"][0]["Input"]
    assert redacted["arn"] == config["arn"]  # ordinary text is unchanged
    assert redacted["description"] == config["description"]


def test_redact_keeps_shape_and_configuration() -> None:
    config = {
        "environment_variables": {"DB_PASSWORD": "pw", "STAGE": "prod"},
        "metadata_options": {"HttpTokens": "required"},
        "user_data": "IyEvYmluL2Jhc2g=",
        "nested": [{"Token": "t"}],
    }
    assert redact(config) == {
        "environment_variables": {"DB_PASSWORD": REDACTED, "STAGE": REDACTED},
        "metadata_options": {"HttpTokens": "required"},
        "user_data": REDACTED,
        "nested": [{"Token": REDACTED}],
    }


# ---------------------------------------------------------------- free text (run logs)
# Fake values only, built at runtime so no scanner mistakes them for real credentials.
FAKE_KEY_ID = "AKIA" + "Z" * 16
FAKE_SECRET = "s" * 20 + "/" + "K" * 19


@pytest.mark.parametrize(
    ("line", "leaked"),
    [
        (f"using key {FAKE_KEY_ID} for the session", FAKE_KEY_ID),
        (f"aws_secret_access_key = {FAKE_SECRET}", FAKE_SECRET),
        ("DB_PASSWORD=hunter2-not-real", "hunter2-not-real"),
        ("STRIPE_SK=sk_value_not_real", "sk_value_not_real"),
        ('{"password": "pa ss word"}', "pa ss word"),
        ("Authorization token: abc.def.ghi-not-real", "abc.def.ghi-not-real"),
        ("got eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.c2lnbmF0dXJl back", "eyJzdWIiOiIxMjM0"),
        ("-----BEGIN RSA PRIVATE KEY-----MIIEow", "MIIEow"),
        ("aws sts assume-role --role-arn r --external-id ext-not-real", "ext-not-real"),
        ("mysql --password 'pw not real' --host db", "pw not real"),
        ('{"sts:ExternalId": "ext-json-not-real"}', "ext-json-not-real"),
        # After a "word:" the first match was that word, and the scan went on past its value.
        ("ingest failed: password=pw-mid-not-real", "pw-mid-not-real"),
        ("bad row: AWS_SECRET_ACCESS_KEY=key-mid-not-real", "key-mid-not-real"),
        ("ValueError: config: token: tok-mid-not-real", "tok-mid-not-real"),
    ],
    # Named cases: the fake values must not end up in test ids (pytest caches them on disk,
    # where secret scanners read them).
    ids=[
        "key-id",
        "secret-key",
        "env-password",
        "env-any",
        "json",
        "token",
        "jwt",
        "pem",
        "flag-external-id",
        "flag-password",
        "json-external-id",
        "after-a-word",
        "env-after-a-word",
        "after-two-words",
    ],
)
def test_redact_text_masks_secret_values(line: str, leaked: str) -> None:
    redacted = redact_text(line)
    assert leaked not in redacted
    assert REDACTED in redacted


def test_redact_text_drops_table_rows_whole() -> None:
    # CloudFox env-vars: a variable whose name looks harmless can still hold a secret.
    rows = [
        "│ lambda │ us-east-1 │ billing │ API_URL │ https://x.invalid/?k=opaque │",
        "| lambda | us-east-1 | billing | CONFIG | opaque-value |",
        "lambda\tus-east-1\tbilling\tCONFIG\topaque-value",
    ]
    assert redact_text("\n".join(rows)).split("\n") == [TABLE_ROW_OMITTED] * 3


@pytest.mark.parametrize(
    "line",
    [
        "[synthetic] prowler for account 100000000001 on 2026-10-03",
        "Scanning region=us-east-1 with 12 checks: done",
        "ERROR: AccessDenied when calling DescribeInstances",
        "3 throttling errors; output is incomplete",
    ],
)
def test_redact_text_keeps_diagnostics(line: str) -> None:
    assert redact_text(line) == line


def test_redact_text_removes_terminal_noise() -> None:
    # PostgreSQL text cannot hold NUL: one in a log tail would stop the run being recorded.
    assert redact_text("\x1b[32mscan\x1b[0m done\x00\x07\tok\nnext") == "scan done\tok\nnext"


def test_redact_text_omits_encoded_authorization_messages() -> None:
    blob = "89VnJM7dyOVTkwrRC6Eo5Pt60sipUGnGQ5m-DX2bIwueKps_evreLeP5FkTb2wkCdvtqosfWL" * 3
    line = (
        "api error UnauthorizedOperation: You are not authorized to perform this operation. "
        f"Encoded authorization failure message: {blob}"
    )
    redacted = redact_text(line)
    assert blob[:40] not in redacted
    assert redacted.endswith(f"Encoded authorization failure message: {ENCODED_OMITTED}")
    # The same blob, cut by the start of a log tail, has no label left.
    assert redact_text(f"{blob[17:]}, writing to CHAN") == f"{ENCODED_OMITTED}, writing to CHAN"


def test_only_named_iam_columns_are_kept_at_the_top_level_of_their_table() -> None:
    keep = NOT_SECRET_COLUMNS["aws_iam_access_key"]
    row = {
        "access_key_id": "key-id",
        "access_key_last_used_date": "2026-09-30",
        "secret_access_key": "never-stored",
        "nested": {"access_key_id": "inside"},
    }
    kept = redact(row, keep=keep)
    assert kept["access_key_id"] == "key-id"
    assert kept["access_key_last_used_date"] == "2026-09-30"
    assert kept["secret_access_key"] == REDACTED  # not on the list
    assert kept["nested"] == {"access_key_id": REDACTED}  # top level only
    assert redact(row)["access_key_id"] == REDACTED  # any other table: secret
    assert is_secret_key("access_key_id")  # the rule itself is unchanged


# Credentials inside URLs (2026-10-09): the marker stands for a secret; it must not survive.
MARK = "not-a-real-pw"


@pytest.mark.parametrize(
    ("url", "kept"),
    [
        (
            f"https://svc:{MARK}@hooks.partner.example/in",
            "https://********@hooks.partner.example/in",
        ),
        (f"https://svc:a@{MARK}@hooks.example:8443/x", "https://********@hooks.example:8443/x"),
        (f"postgres://app:{MARK}@db.internal:5432/app", "postgres://********@db.internal:5432/app"),
        (f"https://h.example/in?sig={MARK}&v=2", "https://h.example/in?sig=********&v=2"),
        (f"https://h.example?apikey={MARK}", "https://h.example?apikey=********"),
        (
            f"https://b.s3.amazonaws.com/k?X-Amz-Signature={MARK}&X-Amz-Expires=60",
            "https://b.s3.amazonaws.com/k?X-Amz-Signature=********&X-Amz-Expires=60",
        ),
        (f"https://f.example/api?code={MARK}#top", "https://f.example/api?code=********#top"),
        (f"https://h.example/cb?access_token={MARK}", "https://h.example/cb?access_token=********"),
    ],
    ids=[
        "userinfo",
        "raw-at-in-password",
        "other-scheme",
        "sig",
        "apikey-no-path",
        "presigned",
        "code-fragment",
        "token",
    ],
)
def test_credentials_inside_urls_are_masked(url: str, kept: str) -> None:
    assert mask_url_credentials(url) == kept
    for found in (redact({"integration_uri": url}), redact_text(f"calling {url} now")):
        assert MARK not in str(found)


@pytest.mark.parametrize(
    "text",
    [
        "https://api.partner.example.org/v1/orders?page=2&limit=50",
        "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/x/invocations",
        "mailto:ops@example.org",
        "user@example.org wrote ?key=value outside any URL",
    ],
    ids=["plain-url", "arn", "mailto", "no-url"],
)
def test_urls_without_credentials_are_unchanged(text: str) -> None:
    assert mask_url_credentials(text) == text


def test_a_url_keeps_its_host_for_the_relationship_rules() -> None:
    config = redact({"integration_uri": f"https://svc:{MARK}@hooks.partner.example/in?sig={MARK}"})
    assert config == {"integration_uri": "https://********@hooks.partner.example/in?sig=********"}


def test_a_trust_policy_keeps_its_condition_but_not_the_external_id() -> None:
    """The scanner role's own trust holds Argus's ExternalId (ADR-0024, amended 2026-10-23):
    the condition's shape stays, so the rules still see that one is required."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:role/argus-hub"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "argus-0123456789abcdef"}},
            }
        ]
    }
    redacted = redact({"assume_role_policy": policy})
    [statement] = redacted["assume_role_policy"]["Statement"]
    assert statement["Condition"] == {"StringEquals": {"sts:ExternalId": REDACTED}}
    assert statement["Principal"] == policy["Statement"][0]["Principal"]
    assert "argus-0123456789abcdef" not in str(redacted)


def test_the_mask_keeps_no_character_and_no_length() -> None:
    assert REDACTED == "********"
    short, long = redact({"password": "ab"}), redact({"password": "S" * 64})
    assert short == long == {"password": REDACTED}


def test_flags_keep_their_name_and_the_next_flag() -> None:
    line = "aws sts assume-role --external-id ext-not-real --role-arn arn:aws:iam::1:role/r"
    assert redact_text(line) == (
        f"aws sts assume-role --external-id {REDACTED} --role-arn arn:aws:iam::1:role/r"
    )
    # A flag that is not secret keeps its value; a secret flag without a value is left alone.
    assert redact_text("--region us-east-1 --external-id --profile p") == (
        "--region us-east-1 --external-id --profile p"
    )


def test_an_arn_in_text_is_never_taken_for_an_assignment() -> None:
    """A secret's ARN names a secret, it is not one: rules follow it (code review, 2026-10-23)."""
    arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"
    assert redact({"valueFrom": arn}) == {"valueFrom": arn}
    assert redact({"definition": f"reads {arn} at start"}) == {
        "definition": f"reads {arn} at start"
    }


def test_an_empty_secret_stays_empty() -> None:
    assert redact({"password": "", "ExternalID": "", "token": None}) == {
        "password": "",
        "ExternalID": "",
        "token": None,
    }
