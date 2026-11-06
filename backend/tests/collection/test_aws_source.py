"""The AWS source runs the three tools as the worker image installs them. Here small shell
scripts stand in for them, so each rule ported from the old collector entrypoints is checked
without AWS: read-only command lines, the failures the tools report as success, throttling,
and that a tool never sees Argus's own secrets."""

import os
import re
import stat
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from uuid import uuid4

import pytest

from argus.collection import CollectOptions, CollectTarget, FilesystemRawStore, collect
from argus.collection.aws import AwsAccess, AwsSource
from argus.collection.aws import tools as aws_tools
from argus.connections import AwsAuth
from argus.core.aws import SessionCredentials
from argus.core.config import get_settings
from argus.core.manifest import (
    BLOCKED_ACTION_PATTERN,
    MAX_TABLE_ERROR_CHARS,
    TABLE_ERROR_PATTERN,
    Manifest,
)

DAY = date(2026, 10, 2)
TARGET = CollectTarget(7, "aws", "210987654321")
# Fake values only, built at runtime so no scanner mistakes them for real credentials.
KEY_ID = "AKIA" + "F" * 16
SECRET = "fake-" + "s" * 35
ACCESS = AwsAccess(AwsAuth("access_key", access_key_id=KEY_ID, secret_access_key=SECRET))


def _script(path: Path, body: str) -> str:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture(autouse=True)
def database_password(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ARGUS_DB_PASSWORD", "must-not-reach-a-tool")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def signed_in_to_the_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "argus.collection.aws.source.aws.caller_identity",
        lambda _credentials: (TARGET.account_id, "arn:aws:iam::210987654321:user/scanner"),
    )


@pytest.fixture
def fakes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Each fake records its argv and environment, then behaves as the test sets it up."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = 'echo "$@" >> "$HOME/../argv.txt"; env > "$HOME/../env-$(basename $0).txt"\n'
    monkeypatch.setattr(
        aws_tools,
        "PROWLER",
        _script(
            bin_dir / "prowler",
            record + 'while [ "$1" != "--output-directory" ]; do shift; done\n'
            'echo "[]" > "$2/prowler-output-x.ocsf.json"\n'
            'cat "$HOME/../prowler.out" 2>/dev/null\n'
            'exit "$(cat "$HOME/../prowler.rc" 2>/dev/null || echo 0)"\n',
        ),
    )
    monkeypatch.setattr(aws_tools, "PROWLER_PYTHON", _script(bin_dir / "python", "echo 5.47.0\n"))
    monkeypatch.setattr(
        aws_tools,
        "CLOUDFOX",
        _script(
            bin_dir / "cloudfox",
            'if [ "$1" = "--version" ]; then echo "cloudfox version 2.0.5"; exit 0; fi\n'
            + record
            + 'while [ "$1" != "--outdir" ]; do shift; done\n'
            '[ -f "$HOME/../cloudfox.empty" ] || { mkdir -p "$2/cloudfox-output/aws/argus-1/json"'
            ' && echo "[]" > "$2/cloudfox-output/aws/argus-1/json/endpoints.json"; }\n'
            # CloudFox 2.0.5 caches what it read next to its output, and writes module
            # errors to its own log.
            'mkdir -p "$2/cached-data/aws/210987654321"\n'
            'echo cache > "$2/cached-data/aws/210987654321/lambda-ListFunctions.gob"\n'
            'cat "$HOME/../cloudfox.errors" >> "$HOME/../cloudfox-error.log" 2>/dev/null\n'
            'cat "$HOME/../cloudfox.out" 2>/dev/null; exit 0\n',
        ),
    )
    monkeypatch.setattr(
        aws_tools,
        "STEAMPIPE",
        _script(
            bin_dir / "steampipe",
            'if [ "$1" = "--version" ]; then echo "steampipe_export_aws v1.34.1"; exit 0; fi\n'
            + record
            + 'if grep -qx "$1" "$HOME/../failing.txt" 2>/dev/null; then\n'
            '  echo "[ERROR] AccessDenied" >&2; exit 0; fi\n'
            'if grep -qx "$1" "$HOME/../denied.txt" 2>/dev/null; then\n'
            '  cat "$HOME/../denied.err" >&2; fi\n'
            'echo \'{"arn": "x"}\'\n',
        ),
    )
    # tempfile.mkdtemp() in tool_profile: each run's home sits next to the control files.
    monkeypatch.setattr(aws_tools.tempfile, "tempdir", str(tmp_path / "homes"))
    (tmp_path / "homes").mkdir()
    monkeypatch.setattr(aws_tools, "CLOUDFOX_ERROR_LOG", tmp_path / "homes" / "cloudfox-error.log")
    return tmp_path


# How the tools report a denied call (fake principal and resource ids).
STEAMPIPE_403 = (
    "[WARN]  1791242584446: error channel received aws: operation error EC2: "
    "GetLaunchTemplateData, https response error StatusCode: 403, RequestID: r-1, api error "
    "UnauthorizedOperation: You are not authorized to perform this operation. User: "
    "arn:aws:sts::210987654321:assumed-role/Scanner/argus is not authorized to perform: "
    "ec2:GetLaunchTemplateData on resource: arn:aws:ec2:us-east-1:210987654321:instance/i-0 "
    "because no identity-based policy allows the ec2:GetLaunchTemplateData action. Encoded "
    "authorization failure message: encoded-message-to-drop\n"
)
# The wordings of the first real member-account run (2026-10-16), ids made up.
STEAMPIPE_REFUSED = (
    "[ERROR] 1792187104330: aws_vpc_endpoint_service.listVpcEndpointServicePermissions: "
    'api_error="operation error EC2: DescribeVpcEndpointServicePermissions, https response '
    "error StatusCode: 403, RequestID: r-2, api error UnauthorizedOperation: You are not "
    "authorized to perform this operation. User: arn:aws:iam::210987654321:user/argus is not "
    "authorized to perform: ec2:DescribeVpcEndpointServicePermissions on resource: "
    "arn:aws:ec2:us-east-1:000000000000:vpc-endpoint-service/vpce-svc-0 because no "
    'resource-based policy allows the ec2:DescribeVpcEndpointServicePermissions action."\n'
)
STEAMPIPE_NOT_USED = (
    "[WARN]  1792187026191: error channel received aws: operation error Timestream Write: "
    "ListTables, operation error Timestream Write: DescribeEndpoints, https response error "
    "StatusCode: 403, RequestID: r-3, api error AccessDeniedException: Only existing "
    "Timestream for LiveAnalytics customers can access the service. Reach out to AWS "
    "support, for more information.\n"
    '[ERROR] 1792187026192: aws_timestreamwrite_table.listTimestreamTables: api_error="'
    "operation error Timestream Write: DescribeEndpoints, https response error StatusCode: "
    "403, api error AccessDeniedException: Only existing Timestream for LiveAnalytics "
    'customers can access the service. Reach out to AWS support, for more information."\n'
)
CLOUDFOX_403 = (
    "2026/10/05 lambda: operation error Lambda: ListFunctions, https response error "
    "StatusCode: 403, api error AccessDeniedException: User: "
    "arn:aws:sts::210987654321:assumed-role/Scanner/argus is not authorized to perform: "
    "lambda:ListFunctions\n"
)


def _control(fakes: Path, name: str, content: str) -> None:
    (fakes / name).write_text(content)


def _run(fakes: Path, tool: str, regions: tuple[str, ...] = ()) -> tuple[str, Manifest]:
    store = FilesystemRawStore(fakes / "raw")
    path, manifest = collect(
        AwsSource(),
        store,
        target=TARGET,
        tool=tool,  # type: ignore[arg-type]
        day=DAY,
        run_uid=uuid4(),
        options=CollectOptions(aws_access=ACCESS, aws_regions=regions),
    )
    return path, manifest


def test_prowler_runs_read_only_in_the_regions_set(fakes: Path) -> None:
    _, manifest = _run(fakes, "prowler", ("eu-west-1", "us-east-1"))
    argv = (fakes / "homes" / "argv.txt").read_text()
    assert "aws --profile argus --output-formats json-ocsf csv --output-directory" in argv
    assert argv.rstrip().endswith("--ignore-exit-code-3 --region eu-west-1 us-east-1")
    for flag in ("--fixer", "--security-hub", "--scan-secrets-validate", "--shodan", "--slack"):
        assert flag not in argv
    assert manifest.status == "complete"
    assert manifest.tool_version == "5.47.0"
    assert manifest.region_scope == ["eu-west-1", "us-east-1"]
    # The Runs page shows what ran: the same argv, the run's temporary folder shortened.
    assert manifest.command.startswith("prowler aws --profile argus --output-formats json-ocsf")
    assert "--output-directory <run> " in manifest.command
    assert manifest.command.endswith("--region eu-west-1 us-east-1")
    assert SECRET not in manifest.command


def test_a_tool_sees_its_profile_and_nothing_of_argus(fakes: Path) -> None:
    _run(fakes, "prowler")
    env = (fakes / "homes" / "env-prowler.txt").read_text()
    assert "AWS_PROFILE=argus" in env and "AWS_EC2_METADATA_DISABLED=true" in env
    assert "ARGUS_" not in env and "must-not-reach-a-tool" not in env
    assert SECRET not in env  # in the credentials file, never the environment
    # The temporary home, credentials file included, is gone after the run.
    assert [p.name for p in (fakes / "homes").iterdir() if p.is_dir()] == []


def test_prowler_throttling_makes_the_run_partial_and_a_crash_failed(fakes: Path) -> None:
    _control(fakes / "homes", "prowler.out", "ThrottlingException: Rate exceeded\n")
    _, throttled = _run(fakes, "prowler")
    assert throttled.status == "partial"
    assert throttled.throttle_events == 1
    _control(fakes / "homes", "prowler.rc", "1")
    _, crashed = _run(fakes, "prowler")
    assert crashed.status == "failed"


def test_cloudfox_reporting_success_without_identity_fails(fakes: Path) -> None:
    _, ok = _run(fakes, "cloudfox")
    assert ok.status == "complete"
    assert ok.command.startswith("cloudfox aws all-checks --profile argus --outdir <run>")
    argv = (fakes / "homes" / "argv.txt").read_text()
    assert "aws all-checks --profile argus --outdir" in argv and "--verbosity 1 --yes" in argv
    _control(fakes / "homes", "cloudfox.out", "[-] Could not get caller's identity\n")
    _, no_identity = _run(fakes, "cloudfox")
    assert no_identity.status == "failed"


def test_cloudfox_with_no_output_fails(fakes: Path) -> None:
    _control(fakes / "homes", "cloudfox.empty", "")
    _, manifest = _run(fakes, "cloudfox")
    assert manifest.status == "failed"


def test_a_steampipe_table_logging_an_error_is_dropped_and_the_run_is_partial(
    fakes: Path,
) -> None:
    _control(fakes / "homes", "failing.txt", "aws_s3_bucket\n")
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    files = [f.path for f in manifest.files]
    assert "aws_s3_bucket.jsonl" not in files and "aws_iam_role.jsonl" in files
    assert manifest.status == "partial"
    assert " <table> --connection aws --config-dir <config> --output jsonl" in manifest.command
    assert manifest.command.endswith('regions = ["eu-west-1"])')
    assert "table failed: aws_s3_bucket" in manifest.log_tail
    assert manifest.tool_version == "1.34.1"
    assert manifest.incomplete_tables == ["aws_s3_bucket"]  # the only table out of scope


def test_steampipe_exports_some_tables_narrowed(fakes: Path) -> None:
    """AWS-managed policies, and the columns the role denies or Argus must not hold, are never
    asked for (collection/tables.py)."""
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    assert manifest.status == "complete" and manifest.incomplete_tables == []
    lines = (fakes / "homes" / "argv.txt").read_text().splitlines()
    by_table = {line.split()[0]: line for line in lines if line.startswith("aws_")}
    assert by_table["aws_iam_policy"].endswith("--where is_aws_managed = false")
    selected = by_table["aws_lambda_function"].split("--select ")[1].split(",")
    assert "arn" in selected and not {"code", "tags"} & set(selected)
    assert "template_body" not in by_table["aws_cloudformation_stack"]
    # One denied column (launch_template_data) aborted the whole table on a real account.
    ec2 = set(by_table["aws_ec2_instance"].split("--select ")[1].split()[0].split(","))
    assert {"public_ip_address", "network_interfaces", "security_groups"} <= ec2
    assert not {"launch_template_data", "user_data"} & ec2


def test_a_role_connection_assumes_it_with_the_external_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def fake_assume(**kwargs: object) -> SessionCredentials:
        calls.append(kwargs)
        return SessionCredentials("ASIA" + "T" * 16, "temp", "token")

    monkeypatch.setattr("argus.collection.aws.access.aws.assume_role", fake_assume)
    role = "arn:aws:iam::210987654321:role/ArgusScanner"
    access = AwsAccess(AwsAuth("assume_role", role_arn=role, external_id="x" * 20))
    credentials = access.credentials(session_name="argus-test")
    assert credentials.session_token == "token"
    assert calls[0]["role_arn"] == role and calls[0]["external_id"] == "x" * 20
    assert calls[0]["credentials"] is None  # ambient platform identity


def test_a_role_connection_without_an_external_id_assumes_it_without_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A role whose trust asks for no ExternalId (owner, 2026-11-05): STS gets none, not an
    empty one, which AWS would refuse."""
    sent: list[dict[str, object]] = []

    class FakeSts:
        def assume_role(self, **kwargs: object) -> dict[str, object]:
            sent.append(kwargs)
            creds = {"AccessKeyId": "ASIA" + "T" * 16, "SecretAccessKey": "temp"}
            return {"Credentials": {**creds, "SessionToken": "token"}}

    class FakeSession:
        def client(self, *_args: object, **_kwargs: object) -> FakeSts:
            return FakeSts()

    monkeypatch.setattr("argus.core.aws._session", lambda *_args: FakeSession())
    role = "arn:aws:iam::210987654321:role/ArgusScanner"
    for external_id in (None, ""):
        access = AwsAccess(AwsAuth("assume_role", role_arn=role, external_id=external_id))
        assert access.credentials(session_name="argus-test").session_token == "token"
    with_one = AwsAccess(AwsAuth("assume_role", role_arn=role, external_id="x" * 20))
    with_one.credentials(session_name="argus-test")
    assert ["ExternalId" in call for call in sent] == [False, False, True]
    assert sent[2]["ExternalId"] == "x" * 20 and sent[0]["RoleArn"] == role


def test_a_temporary_key_reaches_the_tools_with_its_session_token() -> None:
    temporary_id = "ASIA" + "F" * 16
    token = "fake-session-" + "t" * 40
    access = AwsAccess(
        AwsAuth(
            "access_key",
            access_key_id=temporary_id,
            secret_access_key=SECRET,
            session_token=token,
        )
    )
    credentials = access.credentials(session_name="argus-test")
    assert credentials == SessionCredentials(temporary_id, SECRET, token)
    with aws_tools.tool_profile(credentials, "eu-west-1") as env:
        written = Path(env["AWS_SHARED_CREDENTIALS_FILE"]).read_text()
    assert f"aws_session_token = {token}" in written
    assert token not in repr(access) and token not in repr(credentials)


@pytest.mark.parametrize("tool", ["steampipe", "prowler", "cloudfox", "vulnerabilities"])
def test_a_key_of_another_account_fails_the_run_before_any_tool(
    fakes: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    monkeypatch.setattr(
        "argus.collection.aws.source.aws.caller_identity",
        lambda _credentials: ("123456789012", "arn:aws:iam::123456789012:user/other"),
    )
    _, manifest = _run(fakes, tool)
    assert manifest.status == "failed"
    assert "account 123456789012" in manifest.log_tail and TARGET.account_id in manifest.log_tail
    assert manifest.files == []
    assert not (fakes / "homes" / "argv.txt").exists()


def test_a_failed_identity_check_fails_the_run_before_any_tool(
    fakes: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_credentials: object) -> tuple[str, str]:
        raise RuntimeError("InvalidClientTokenId: the security token is not valid")

    monkeypatch.setattr("argus.collection.aws.source.aws.caller_identity", refuse)
    _, manifest = _run(fakes, "prowler")
    assert manifest.status == "failed" and "InvalidClientTokenId" in manifest.log_tail


EXTRA_LINE = "\nregion = elsewhere"


@pytest.mark.parametrize(
    "credentials",
    [
        SessionCredentials(KEY_ID, SECRET + EXTRA_LINE),
        SessionCredentials(KEY_ID, SECRET + "\r"),
        SessionCredentials(KEY_ID, SECRET + " x"),
        SessionCredentials(KEY_ID + EXTRA_LINE, SECRET),
        SessionCredentials("ASIA" + "F" * 16, SECRET, "token" + EXTRA_LINE),
    ],
    ids=["secret-newline", "secret-return", "secret-space", "key-id-newline", "token-newline"],
)
def test_a_profile_holds_one_word_per_value(credentials: SessionCredentials) -> None:
    with (
        pytest.raises(ValueError, match="holds a space or a control character") as refused,
        aws_tools.tool_profile(credentials, "eu-west-1"),
    ):
        pytest.fail("the profile was written")
    assert SECRET not in str(refused.value) and EXTRA_LINE not in str(refused.value)


def test_a_stored_value_that_is_not_one_word_fails_the_run_before_any_tool(fakes: Path) -> None:
    """A row stored before the API refused such a value, or written around it."""
    access = AwsAccess(
        AwsAuth("access_key", access_key_id=KEY_ID, secret_access_key=SECRET + EXTRA_LINE)
    )
    _, manifest = collect(
        AwsSource(),
        FilesystemRawStore(fakes / "raw"),
        target=TARGET,
        tool="prowler",
        day=DAY,
        run_uid=uuid4(),
        options=CollectOptions(aws_access=access),
    )
    assert manifest.status == "failed"
    assert "secret access key" in manifest.log_tail and SECRET not in manifest.log_tail
    assert not (fakes / "homes" / "argv.txt").exists()


def test_credentials_never_print() -> None:
    assert SECRET not in repr(ACCESS) and SECRET not in repr(SessionCredentials(KEY_ID, SECRET))
    assert KEY_ID not in repr(SessionCredentials(KEY_ID, SECRET))


def test_the_cloudfox_cache_of_the_account_is_removed(
    fakes: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = fakes / "passwd-home"
    cached = home / ".cloudfox" / "cached-data" / "aws" / TARGET.account_id
    cached.mkdir(parents=True)
    (cached / "lambdas.json").write_text("{}")
    other = home / ".cloudfox" / "cached-data" / "aws" / "100000000010"
    other.mkdir(parents=True)

    class Entry:
        pw_dir = str(home)

    monkeypatch.setattr(aws_tools.pwd, "getpwuid", lambda _uid: Entry())
    _run(fakes, "cloudfox")
    assert not cached.exists() and other.exists()  # another account's run is untouched


def test_os_environ_is_never_inherited() -> None:
    with aws_tools.tool_profile(SessionCredentials(KEY_ID, SECRET), "eu-west-1") as env:
        assert not set(env) & {k for k in os.environ if k.startswith("ARGUS_")}
        credentials = Path(env["AWS_SHARED_CREDENTIALS_FILE"])
        assert stat.S_IMODE(credentials.stat().st_mode) == 0o600
        assert SECRET in credentials.read_text()
    assert not credentials.exists()


@pytest.mark.parametrize(
    ("line", "action"),
    [
        (STEAMPIPE_403, "ec2:GetLaunchTemplateData"),
        (
            "operation error S3: GetBucketPolicy, https response error StatusCode: 403, "
            "api error AccessDenied: Access Denied",
            "s3:GetBucketPolicy",
        ),
        (
            "ClientError: An error occurred (AccessDenied) when calling the GetBucketAcl "
            "operation: Access Denied",
            "GetBucketAcl",
        ),
        (
            "2026-10-16 02:11:09,120 [File: glue_service.py:80] \t[Module: glue_service]\t "
            "ERROR: us-east-1 -- ClientError[69]: An error occurred (AccessDeniedException) "
            "when calling the GetDevEndpoints operation: Access denied",
            "glue:GetDevEndpoints",
        ),
        (
            "2026-10-16 02:11:09,120 [File: awslambda_service.py:40] \t[Module: x]\t ERROR: "
            "ClientError: An error occurred (AccessDenied) when calling the GetPolicy operation",
            "lambda:GetPolicy",
        ),
        (
            "operation error Timestream Write: DescribeEndpoints, https response error "
            "StatusCode: 403, api error AccessDeniedException: Access denied",
            "timestream:DescribeEndpoints",
        ),
        (STEAMPIPE_NOT_USED, None),
        (STEAMPIPE_REFUSED, None),
        (
            "User: arn:aws:iam::210987654321:user/argus is not authorized to perform: "
            "lambda:GetFunction on resource: arn:aws:lambda:us-east-1:210987654321:function:f "
            "with an explicit deny in an identity-based policy",
            None,
        ),
        ("operation error EC2: DescribeInstances, https response error StatusCode: 500", None),
    ],
    ids=[
        "iam-wording",
        "go-sdk",
        "botocore",
        "prowler-module",
        "prowler-mapped",
        "go-sdk-mapped",
        "service-not-used",
        "resource-refused",
        "explicit-deny",
        "not-a-denial",
    ],
)
def test_denied_actions_are_read_from_each_tools_wording(line: str, action: str | None) -> None:
    assert aws_tools.denied_actions(line) == ({action} if action else set())


def test_a_denied_call_that_aborts_the_table_drops_it_and_names_the_action(fakes: Path) -> None:
    """What the pinned plugin did on a real account: the 403 is logged, then the table's
    export stops with [ERROR]. Its rows cannot be trusted, so the table is failed."""
    _control(fakes / "homes", "denied.txt", "aws_ec2_instance\n")
    _control(fakes / "homes", "denied.err", STEAMPIPE_403 + "[ERROR] error channel received\n")
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    assert "aws_ec2_instance.jsonl" not in [f.path for f in manifest.files]
    assert manifest.status == "partial"
    assert manifest.denied_actions == ["ec2:GetLaunchTemplateData"]
    assert manifest.incomplete_tables == ["aws_ec2_instance"]
    assert "table failed: aws_ec2_instance" in manifest.log_tail


def test_a_table_whose_service_is_not_used_is_carried_without_making_the_run_partial(
    fakes: Path,
) -> None:
    _control(fakes / "homes", "denied.txt", "aws_timestreamwrite_table\n")
    _control(fakes / "homes", "denied.err", STEAMPIPE_NOT_USED)
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    assert manifest.status == "complete"
    assert manifest.denied_actions == [] and manifest.refused_actions == []
    assert manifest.not_applicable_tables == ["aws_timestreamwrite_table"]
    assert manifest.incomplete_tables == ["aws_timestreamwrite_table"]
    assert "table not applicable: aws_timestreamwrite_table" in manifest.log_tail


def test_a_table_a_resource_refused_is_carried_and_its_action_reported_apart(
    fakes: Path,
) -> None:
    _control(fakes / "homes", "denied.txt", "aws_vpc_endpoint_service\n")
    _control(fakes / "homes", "denied.err", STEAMPIPE_REFUSED)
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    assert manifest.status == "complete"
    assert manifest.denied_actions == []
    assert manifest.refused_actions == ["ec2:DescribeVpcEndpointServicePermissions"]
    assert manifest.refused_tables == ["aws_vpc_endpoint_service"]
    assert manifest.incomplete_tables == ["aws_vpc_endpoint_service"]


def test_a_denied_steampipe_call_keeps_the_rows_and_makes_the_run_partial(fakes: Path) -> None:
    _control(fakes / "homes", "denied.txt", "aws_ec2_instance\n")
    _control(fakes / "homes", "denied.err", STEAMPIPE_403)
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    assert "aws_ec2_instance.jsonl" in [f.path for f in manifest.files]
    assert manifest.status == "partial"
    assert manifest.denied_actions == ["ec2:GetLaunchTemplateData"]
    assert manifest.incomplete_tables == ["aws_ec2_instance"]
    assert "table partial: aws_ec2_instance (1 denied action(s))" in manifest.log_tail
    assert "1 action(s) denied: ec2:GetLaunchTemplateData" in manifest.log_tail
    assert "encoded-message-to-drop" not in manifest.log_tail


def test_cloudfox_scans_every_region_and_never_archives_its_cache(fakes: Path) -> None:
    _, manifest = _run(fakes, "cloudfox", ("eu-west-1",))
    assert manifest.status == "complete"
    assert manifest.region_scope == [] and manifest.api_regions is None
    assert not [f for f in manifest.files if f.path.startswith("cached-data/")]
    assert not list((fakes / "raw").glob("**/*.gob"))


def test_cloudfox_output_is_archived_without_its_wrapper_folders(fakes: Path) -> None:
    path, manifest = _run(fakes, "cloudfox")
    assert [f.path for f in manifest.files] == ["json/endpoints.json"]
    assert not (fakes / "raw" / path / "cloudfox-output").exists()


def test_cloudfox_output_in_an_unexpected_layout_is_left_as_written(tmp_path: Path) -> None:
    for profile in ("argus-1", "argus-2"):
        (tmp_path / "cloudfox-output" / "aws" / profile / "json").mkdir(parents=True)
    aws_tools._flatten_cloudfox(tmp_path)
    assert sorted(p.name for p in (tmp_path / "cloudfox-output" / "aws").iterdir()) == [
        "argus-1",
        "argus-2",
    ]
    assert not (tmp_path / "json").exists()


def test_a_denied_cloudfox_module_makes_the_run_partial(fakes: Path) -> None:
    log = fakes / "homes" / "cloudfox-error.log"
    log.write_text(CLOUDFOX_403.replace("lambda:ListFunctions", "iam:ListRoles"))  # an older run
    other_account = CLOUDFOX_403.replace("210987654321", "999999999999").replace(
        "lambda:ListFunctions", "sns:ListTopics"
    )
    _control(fakes / "homes", "cloudfox.errors", CLOUDFOX_403 + other_account)
    _, manifest = _run(fakes, "cloudfox")
    assert manifest.status == "partial"
    assert manifest.denied_actions == ["lambda:ListFunctions"]  # this run, this account only
    assert log.exists()  # a concurrent run may still be writing to it


@pytest.mark.parametrize(
    "line",
    [
        # The emulator's (real plugin, moto) Organizations wording.
        'aws_organizations_root.listOrganizationsRoots: api_error="operation error '
        "Organizations: ListRoots, https response error StatusCode: 400, RequestID: r-4, "
        'AWSOrganizationsNotInUseException: Your account is not a member of an organization."',
        STEAMPIPE_NOT_USED.splitlines()[0],
    ],
    ids=["organizations", "timestream"],
)
def test_not_applicable_wordings_match_only_as_the_error_code(line: str) -> None:
    assert aws_tools.NOT_APPLICABLE.search(line)
    # A resource named after the wording is not the error.
    named = "[ERROR] table x: api error AccessDenied: on resource AWSOrganizationsNotInUseException"
    assert not aws_tools.NOT_APPLICABLE.search(named)


# What IAM says when a policy outside the role refused the call (owner, 2026-11-05). The S3 line
# has the shape of the first real scan's VPC endpoint denials, ids made up.
S3_BLOCKED_CALL = (
    "operation error S3: ListBuckets, https response error StatusCode: 403, RequestID: r-5, "
    "HostID: h-5, api error AccessDenied: User: "
    "arn:aws:sts::210987654321:assumed-role/Scanner/argus is not authorized to perform: "
    "s3:ListAllMyBuckets because no VPC endpoint policy allows the s3:ListAllMyBuckets action"
)
STEAMPIPE_BLOCKED = (
    f"[WARN]  1793909735122: error channel received aws: {S3_BLOCKED_CALL}\n"
    f'[ERROR] 1793909735123: aws_s3_bucket.listS3Buckets: api_error="{S3_BLOCKED_CALL}"\n'
)
_IAM_DENIAL = (
    "User: arn:aws:sts::210987654321:assumed-role/Scanner/argus is not authorized to perform: "
    "dynamodb:ListTables on resource: arn:aws:dynamodb:us-east-1:210987654321:table/* "
)
_BLOCKING = (
    "service control policy",
    "resource control policy",
    "permissions boundary",
    "session policy",
    "VPC endpoint policy",
)


def _reason_cases() -> list[tuple[str, str, str]]:
    """(IAM's reason, the class it goes to, the entry), every policy type both ways."""
    cases = [
        ("because no identity-based policy allows the dynamodb:ListTables action", "denied", ""),
        ("with an explicit deny in an identity-based policy", "refused", ""),
        ("because no resource-based policy allows the dynamodb:ListTables action", "refused", ""),
        ("with an explicit deny in a resource-based policy", "refused", ""),
        ("", "denied", ""),  # no reason given: the role is missing it, as before
    ]
    for policy in _BLOCKING:
        entry = f"dynamodb:ListTables ({policy})"
        implicit = f"because no {policy} allows the dynamodb:ListTables action"
        cases.append((implicit, "blocked", entry))
        cases.append((f"with an explicit deny in a {policy}", "blocked", entry))
    return cases


@pytest.mark.parametrize(
    ("reason", "kind", "entry"),
    _reason_cases(),
    ids=[
        "identity-implicit",
        "identity-explicit",
        "resource-implicit",
        "resource-explicit",
        "no-reason",
        *(f"{p.replace(' ', '-')}-{how}" for p in _BLOCKING for how in ("implicit", "explicit")),
    ],
)
def test_each_iam_reason_goes_to_one_class(reason: str, kind: str, entry: str) -> None:
    found = aws_tools.read_denials(_IAM_DENIAL + reason)
    classes = {"denied": found.denied, "refused": found.refused, "blocked": found.blocked}
    assert classes.pop(kind) == {entry or "dynamodb:ListTables"}
    assert not any(classes.values())
    if entry:  # what the manifest will accept
        assert re.fullmatch(BLOCKED_ACTION_PATTERN, entry)


def test_a_table_blocked_outside_the_role_makes_the_run_partial_and_says_where(
    fakes: Path,
) -> None:
    _control(fakes / "homes", "denied.txt", "aws_s3_bucket\n")
    _control(fakes / "homes", "denied.err", STEAMPIPE_BLOCKED)
    _, manifest = _run(fakes, "steampipe", ("us-east-1",))
    assert "aws_s3_bucket.jsonl" not in [f.path for f in manifest.files]
    assert manifest.status == "partial"
    assert manifest.denied_actions == [] and manifest.refused_actions == []
    assert manifest.blocked_actions == ["s3:ListAllMyBuckets (VPC endpoint policy)"]
    assert manifest.incomplete_tables == ["aws_s3_bucket"] and manifest.refused_tables == []
    assert manifest.table_errors == [
        "aws_s3_bucket: S3: ListBuckets (HTTP 403): AccessDenied: User is not authorized to "
        "perform: s3:ListAllMyBuckets because no VPC endpoint policy allows the "
        "s3:ListAllMyBuckets action"
    ]
    assert "blocked outside the role: s3:ListAllMyBuckets (VPC endpoint policy)" in (
        manifest.log_tail
    )


def test_an_explicit_scp_deny_is_blocked_not_refused(fakes: Path) -> None:
    """Before 2026-11-05 an explicit Deny in a service control policy counted as refused on
    purpose, and the run stayed complete. Its data is missing, so now it is partial."""
    _control(fakes / "homes", "denied.txt", "aws_vpc_endpoint_service\n")
    _control(
        fakes / "homes",
        "denied.err",
        STEAMPIPE_REFUSED.replace(
            "because no resource-based policy allows the ec2:DescribeVpcEndpointServicePermissions "
            "action",
            "with an explicit deny in a service control policy",
        ),
    )
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    assert manifest.status == "partial"
    assert manifest.refused_actions == [] and manifest.refused_tables == []
    assert manifest.blocked_actions == [
        "ec2:DescribeVpcEndpointServicePermissions (service control policy)"
    ]


def test_every_table_left_out_keeps_the_reason_aws_gave(fakes: Path) -> None:
    """The first real scan lost why 29 tables failed: only the log's last 4,000 characters were
    kept. Each table left out now carries its own line, whatever its outcome."""
    _control(fakes / "homes", "failing.txt", "aws_sns_topic\n")
    _control(fakes / "homes", "denied.txt", "aws_ec2_instance\naws_timestreamwrite_table\n")
    _control(fakes / "homes", "denied.err", STEAMPIPE_403 + "[ERROR] error channel received\n")
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    reasons = dict(e.split(": ", 1) for e in manifest.table_errors)
    assert (
        sorted(reasons)
        == manifest.incomplete_tables
        == [
            "aws_ec2_instance",
            "aws_sns_topic",
            "aws_timestreamwrite_table",
        ]
    )
    # AWS's answer, not the generic line that stopped the table; no ARN, no encoded message.
    assert reasons["aws_ec2_instance"] == (
        "EC2: GetLaunchTemplateData (HTTP 403): UnauthorizedOperation: You are not authorized "
        "to perform this operation. User is not authorized to perform: "
        "ec2:GetLaunchTemplateData because no identity-based policy allows the "
        "ec2:GetLaunchTemplateData action"
    )
    assert reasons["aws_sns_topic"] == "[ERROR] AccessDenied"
    assert "210987654321" not in " ".join(manifest.table_errors)


def test_a_not_applicable_table_keeps_its_reason_too(fakes: Path) -> None:
    _control(fakes / "homes", "denied.txt", "aws_timestreamwrite_table\n")
    _control(fakes / "homes", "denied.err", STEAMPIPE_NOT_USED)
    _, manifest = _run(fakes, "steampipe", ("eu-west-1",))
    assert manifest.status == "complete"
    assert manifest.table_errors == [
        "aws_timestreamwrite_table: Timestream Write: DescribeEndpoints (HTTP 403): "
        "AccessDeniedException: Only existing Timestream for LiveAnalytics customers can access "
        "the service. Reach out to AWS support, for more information."
    ]


@pytest.mark.parametrize(
    ("errors", "expected"),
    [
        ("", "aws_x: exit code 1, nothing on standard error"),
        ("Plugin.getSchema failed\n", "aws_x: Plugin.getSchema failed"),
        (
            '[ERROR] 1: aws_x.list: api_error="operation error FMS: ListPolicies, https '
            "response error StatusCode: 400, RequestID: r-6, api error "
            'AccessDeniedException: The operation is not allowed for this account"\n',
            "aws_x: FMS: ListPolicies (HTTP 400): AccessDeniedException: The operation is not "
            "allowed for this account",
        ),
        ("[ERROR] 1: " + "word " * 100, None),  # cut to the limit
        (f"[ERROR] 1: DB_PASSWORD={SECRET}\n", None),  # redacted
    ],
    ids=["nothing-printed", "stdout-only", "sdk-answer", "too-long", "secret"],
)
def test_a_table_reason_fits_the_manifest(errors: str, expected: str | None) -> None:
    reason = aws_tools.table_error("aws_x", 1, errors)
    assert re.fullmatch(TABLE_ERROR_PATTERN, reason)
    assert SECRET not in reason
    if expected is not None:
        assert reason == expected
    elif "word" in errors:
        assert len(reason) == len("aws_x: ") + MAX_TABLE_ERROR_CHARS
        assert reason.endswith("…")


def test_prowler_lists_blocked_actions_and_stays_complete(fakes: Path) -> None:
    """Prowler's rule is unchanged: a check whose calls were refused has no result, so it
    resolves nothing, and the run stays complete. What blocked it is listed apart."""
    line = (
        "2026-11-05 20:30:01,000 [File: s3_service.py:40] \t[Module: s3_service]\t ERROR: "
        "ClientError: An error occurred (AccessDenied) when calling the ListBuckets operation: "
        + S3_BLOCKED_CALL.split("api error AccessDenied: ", 1)[1]
        + "\n"
    )
    _control(fakes / "homes", "prowler.out", line)
    _, manifest = _run(fakes, "prowler")
    assert manifest.status == "complete"
    assert manifest.denied_actions == []
    assert manifest.blocked_actions == ["s3:ListAllMyBuckets (VPC endpoint policy)"]


def test_a_blocked_cloudfox_module_makes_the_run_partial(fakes: Path) -> None:
    blocked = CLOUDFOX_403.replace(
        "lambda:ListFunctions\n",
        "lambda:ListFunctions because no permissions boundary allows the lambda:ListFunctions "
        "action\n",
    )
    _control(fakes / "homes", "cloudfox.errors", blocked)
    _, manifest = _run(fakes, "cloudfox")
    assert manifest.status == "partial"
    assert manifest.denied_actions == []
    assert manifest.blocked_actions == ["lambda:ListFunctions (permissions boundary)"]


def test_inspector_exports_this_accounts_open_findings_and_its_coverage(fakes: Path) -> None:
    """The vulnerabilities collector on AWS (ADR-0042, Inspector): the same export binary, two
    tables, each filtered to the connection's account; one failing table makes the run partial
    and is named."""
    _, manifest = _run(fakes, "vulnerabilities")
    assert manifest.tool == "vulnerabilities" and manifest.tool_version == "1.34.1"
    assert manifest.status == "complete"
    assert sorted(f.path for f in manifest.files) == [
        "aws_inspector2_coverage.jsonl",
        "aws_inspector2_finding.jsonl",
    ]
    lines = (fakes / "homes" / "argv.txt").read_text().splitlines()
    findings = next(line for line in lines if line.startswith("aws_inspector2_finding"))
    assert f"--where finding_account_id = '{TARGET.account_id}'" in findings
    assert "--where status <> 'CLOSED'" in findings
    assert "aws_inspector2_finding --connection aws" in manifest.command
    assert manifest.command.endswith('(regions = ["*"])')

    _control(fakes / "homes", "failing.txt", "aws_inspector2_finding\n")
    _, failing = _run(fakes, "vulnerabilities")
    assert failing.status == "partial"
    assert failing.incomplete_tables == ["aws_inspector2_finding"]
