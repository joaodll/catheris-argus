"""The synthetic source stands in for three real tools until the AWS phase, so these tests pin
its output to the tools' real formats (risk R1) and prove the scenarios the MVP gate relies on."""

import csv
import io
import json
from datetime import date, timedelta
from pathlib import Path
from uuid import UUID, uuid5

import pytest

from argus.collection import (
    TOOL_ORDER,
    CollectTarget,
    FilesystemRawStore,
    collect,
    read_run,
    source_for,
    steampipe_tables,
)
from argus.collection.collect import CollectOptions
from argus.collection.synthetic import cloudfox, prowler, steampipe
from argus.collection.synthetic.estate import (
    SCENARIO_INSTANCE,
    SCENARIO_ROLE,
    Estate,
    day_number,
    regression_bucket,
)
from argus.collection.synthetic.source import FAIL_EVERY_DAYS
from argus.collection.tables import TABLE_OPTIONS
from argus.core.rawstore import RawRunError

DAY = date(2026, 10, 2)
PROD = CollectTarget(1, "demo", "100000000010", demo_seed=0)
STAGING = CollectTarget(2, "demo", "100000000011", demo_seed=1)
NO_THROTTLE = CollectOptions(synthetic_throttle_share=0.0)
COLUMNS = json.loads((Path(__file__).parent / "steampipe_columns_aws_1.34.0.json").read_text())


def _uid(*parts: object) -> UUID:
    return uuid5(UUID(int=0), "|".join(map(str, parts)))


def _run(
    root: Path,
    target: CollectTarget,
    tool: str,
    day: date = DAY,
    options: CollectOptions = NO_THROTTLE,
) -> Path:
    store = FilesystemRawStore(root)
    path, _ = collect(
        source_for("demo"),
        store,
        target=target,
        tool=tool,  # type: ignore[arg-type]
        day=day,
        run_uid=_uid(target.account_id, tool, day),
        options=options,
    )
    return read_run(store, path).root


# --------------------------------------------------------------- raw store
def test_every_run_commits_a_manifest_that_matches_its_files(tmp_path: Path) -> None:
    for tool in TOOL_ORDER:
        run_dir = _run(tmp_path, PROD, tool)
        manifest = json.loads((run_dir / "manifest.json").read_text())
        assert manifest["status"] == "complete"
        assert manifest["files"], tool


def test_a_tampered_run_is_refused(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, PROD, "steampipe")
    next(run_dir.glob("*.jsonl")).write_text("{}\n")
    store = FilesystemRawStore(tmp_path)
    with pytest.raises(RawRunError, match="do not match"):
        read_run(store, str(run_dir.relative_to(tmp_path)))


def test_a_run_without_a_manifest_is_refused(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, PROD, "cloudfox")
    (run_dir / "manifest.json").unlink()
    with pytest.raises(RawRunError, match="incomplete"):
        read_run(FilesystemRawStore(tmp_path), str(run_dir.relative_to(tmp_path)))


def test_a_path_outside_the_store_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RawRunError, match="escapes"):
        FilesystemRawStore(tmp_path).open("../../etc")


# --------------------------------------------------------------- determinism
def test_same_seed_same_day_is_byte_identical(tmp_path: Path) -> None:
    for tool in TOOL_ORDER:
        a = _run(tmp_path / "a", PROD, tool)
        b = _run(tmp_path / "b", PROD, tool)
        files_a = {p.relative_to(a): p.read_bytes() for p in a.rglob("*") if p.is_file()}
        files_b = {p.relative_to(b): p.read_bytes() for p in b.rglob("*") if p.is_file()}
        assert files_a == files_b, tool


def test_the_estate_churns_but_keeps_its_structure() -> None:
    model = Estate(PROD.account_id, 0)
    today, later = model.at(DAY), model.at(DAY + timedelta(days=60))
    instances = {r.uid for r in today.resources["aws_ec2_instance"]}
    later_instances = {r.uid for r in later.resources["aws_ec2_instance"]}
    assert instances != later_instances  # compute churns
    assert {r.uid for r in today.resources["aws_vpc"]} == {
        r.uid for r in later.resources["aws_vpc"]
    }


# --------------------------------------------------------------- formats (risk R1)
def test_every_listed_table_exists_in_the_pinned_plugin() -> None:
    assert set(steampipe_tables()) <= set(COLUMNS["tables"])
    assert set(steampipe_tables()) >= steampipe.TABLES


def test_every_selected_column_exists_in_the_pinned_plugin() -> None:
    """A --select naming a column the plugin lacks fails the table on every run."""
    common = {"partition", "region", "account_id"}
    for table, options in TABLE_OPTIONS.items():
        assert table in steampipe_tables(), table
        if "--select" in options:
            selected = set(options[options.index("--select") + 1].split(","))
            unknown = selected - set(COLUMNS["tables"][table]) - common
            assert not unknown, f"{table}: {unknown}"


def test_steampipe_columns_exist_in_the_pinned_plugin(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, PROD, "steampipe")
    for table in sorted(steampipe.TABLES):
        allowed = set(COLUMNS["tables"][table]) | {"partition", "region", "account_id"}
        for line in (run_dir / f"{table}.jsonl").read_text().splitlines():
            unknown = set(json.loads(line)) - allowed
            assert not unknown, f"{table}: {unknown}"


def test_prowler_ocsf_and_compliance_follow_5_44_0(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, PROD, "prowler")
    ocsf = json.loads(next(run_dir.glob("prowler-output-*.ocsf.json")).read_text())
    first = ocsf[0]
    assert {"finding_info", "resources", "cloud", "metadata", "status_code", "unmapped"} <= set(
        first
    )
    check = first["metadata"]["event_code"]
    resource = first["resources"][0]
    assert first["finding_info"]["uid"] == (
        f"prowler-aws-{check}-{PROD.account_id}-{resource['region']}-{resource['name']}"
    )
    assert {f["status_code"] for f in ocsf} <= {"PASS", "FAIL", "MANUAL"}

    for name, columns in (
        ("cis_6.0_aws", prowler.CIS_COLUMNS),
        ("prowler_threatscore_aws", prowler.THREATSCORE_COLUMNS),
    ):
        text = next(run_dir.glob(f"compliance/*_{name}.csv")).read_text()
        reader = csv.DictReader(io.StringIO(text), delimiter=";")
        assert tuple(reader.fieldnames or ()) == columns
        assert {row["STATUS"] for row in reader} <= {"PASS", "FAIL", "MANUAL"}


def test_cloudfox_files_follow_2_0_5(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, PROD, "cloudfox")
    # The layout the AWS source archives: CloudFox's wrapper folders removed.
    assert not (run_dir / "cloudfox-output").exists()
    trusts = json.loads((run_dir / "json" / "role-trusts-services.json").read_text())
    assert set(trusts[0]) == set(cloudfox.ROLE_TRUST_SERVICES)
    assert all(isinstance(v, str) for row in trusts for v in row.values())
    header = (run_dir / "csv" / "env-vars.csv").read_text().splitlines()[0]
    assert header == ",".join(cloudfox.ENV_VARS)


# --------------------------------------------------------------- scenarios
def test_the_attack_path_scenario_is_present_in_prod(tmp_path: Path) -> None:
    prowler_dir = _run(tmp_path, PROD, "prowler")
    ocsf = json.loads(next(prowler_dir.glob("*.ocsf.json")).read_text())
    instance = Estate(PROD.account_id, 0).at(DAY).by_name("aws_ec2_instance", SCENARIO_INSTANCE)
    assert instance is not None
    # Prowler names an instance by its id, as the real tool does, never by its Name tag.
    assert any(
        f["status_code"] == "FAIL"
        and f["metadata"]["event_code"] == "ec2_instance_port_ssh_exposed_to_internet"
        and f["resources"][0]["uid"] == instance.arn
        and f["resources"][0]["name"] == instance.native_id
        and f["finding_info"]["uid"].endswith(f"-{instance.native_id}")
        for f in ocsf
    )

    cloudfox_dir = _run(tmp_path, PROD, "cloudfox")
    trusts = json.loads(next(cloudfox_dir.rglob("json/role-trusts-services.json")).read_text())
    role = next(r for r in trusts if r["Role Name"] == SCENARIO_ROLE)
    assert role["CanPrivEscToAdmin?"] == "YES"


def test_the_regression_bucket_is_fixed_then_reopened() -> None:
    model = Estate(PROD.account_id, 0)
    phases = {}
    for offset in range(0, 90):
        day = DAY + timedelta(days=offset)
        phases[day_number(day) % 90] = model.regression_failing(day)
    assert phases[10] and not phases[40] and phases[80]
    assert model.at(DAY).by_name("aws_s3_bucket", regression_bucket(PROD.account_id)) is not None


def test_two_estates_with_the_same_profile_share_no_resource() -> None:
    # Seeds 0 and 3 both get the prod profile and its fixed scenarios. Real resource ids are
    # unique across accounts (S3 names globally), so the synthetic ones must be too.
    first, second = Estate(PROD.account_id, 0).at(DAY), Estate("100000000013", 3).at(DAY)
    assert {r.uid for r in first.all()}.isdisjoint(r.uid for r in second.all())


def test_staging_prowler_fails_on_schedule_and_leaves_an_unterminated_file(tmp_path: Path) -> None:
    failing_day = next(
        DAY + timedelta(days=i)
        for i in range(FAIL_EVERY_DAYS)
        if day_number(DAY + timedelta(days=i)) % FAIL_EVERY_DAYS == 0
    )
    run_dir = _run(tmp_path, STAGING, "prowler", failing_day)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["status"] == "failed"
    assert manifest["exit_code"] == 1
    with pytest.raises(json.JSONDecodeError):
        json.loads(next(run_dir.glob("*.ocsf.json")).read_text())
    assert not (run_dir / "compliance").exists()


@pytest.mark.parametrize("tool", TOOL_ORDER)
def test_a_throttled_run_is_partial_and_loses_output(tmp_path: Path, tool: str) -> None:
    full = _run(tmp_path / "full", PROD, tool)
    cut = _run(tmp_path / "cut", PROD, tool, options=CollectOptions(synthetic_throttle_share=1.0))
    manifest = json.loads((cut / "manifest.json").read_text())
    assert manifest["status"] == "partial"
    assert manifest["throttle_events"] > 0
    assert "ThrottlingException" in manifest["log_tail"]
    size = lambda d: sum(p.stat().st_size for p in d.rglob("*") if p.name != "manifest.json")  # noqa: E731
    assert size(cut) < size(full)


def test_secret_bearing_fields_are_present_for_redaction_to_handle(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, PROD, "steampipe")
    functions = [
        json.loads(line)
        for line in (run_dir / "aws_lambda_function.jsonl").read_text().splitlines()
    ]
    assert any("DB_PASSWORD" in f["environment_variables"] for f in functions)
    instance = json.loads((run_dir / "aws_ec2_instance.jsonl").read_text().splitlines()[0])
    assert instance["user_data"]
