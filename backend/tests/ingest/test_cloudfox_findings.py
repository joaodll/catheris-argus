"""CloudFox attacker-view findings (2026-10-07): roles that can escalate to administrator,
cross-account root trusts without an ExternalId, public endpoints and secret-like environment
variables, each tagged with Prowler's service, resource type and category names. Pure."""

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import uuid4

from argus.attackpaths.cloudfox import (
    ENV_EXPOSURE_CHECK,
    PRIVESC_CHECK,
    PUBLIC_ENDPOINT_CHECK,
    ROOT_TRUST_CHECK,
    parse_cloudfox,
)
from argus.core.manifest import Manifest, ManifestFile
from argus.core.rawstore import RawRun
from argus.findings import ANY_REGION

ACCOUNT = "123456789012"
OTHER = "210987654321"


def _role(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def _principal(
    name: str, trusted: str, *, admin: bool, escalates: bool, ext: str = ""
) -> dict[str, str]:
    return {
        "Account": ACCOUNT,
        "Role Arn": _role(name),
        "Role Name": name,
        "Trusted Principal": trusted,
        "ExternalID": ext,
        "IsAdmin?": "YES" if admin else "No",
        "CanPrivEscToAdmin?": "YES" if escalates else "No",
    }


def _run(tmp_path: Path, modules: dict[str, list[dict[str, str]]]) -> RawRun:
    (tmp_path / "json").mkdir(parents=True)
    files = []
    for module, rows in modules.items():
        data = json.dumps(rows).encode()
        (tmp_path / "json" / f"{module}.json").write_bytes(data)
        files.append(
            ManifestFile(
                path=f"json/{module}.json",
                bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
    now = datetime.now(UTC)
    manifest = Manifest(
        run_uid=uuid4(),
        tool="cloudfox",
        tool_version="2.0.5",
        account_id=ACCOUNT,
        source="aws",
        snapshot_date=date(2026, 10, 7),
        region_scope=[],
        started_at=now,
        finished_at=now,
        status="complete",
        exit_code=0,
        throttle_events=0,
        files=files,
    )
    return RawRun(manifest=manifest, root=tmp_path)


def test_a_role_that_can_escalate_is_one_finding_per_role(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            "role-trusts-principals": [
                _principal("ci", f"arn:aws:iam::{ACCOUNT}:role/a", admin=False, escalates=True),
                _principal("ci", f"arn:aws:iam::{ACCOUNT}:role/b", admin=False, escalates=True),
                _principal("admin", f"arn:aws:iam::{ACCOUNT}:root", admin=True, escalates=True),
                _principal("app", f"arn:aws:iam::{ACCOUNT}:root", admin=False, escalates=False),
            ],
            "role-trusts-services": [
                {
                    "Account": ACCOUNT,
                    "Role Arn": _role("ci"),
                    "Role Name": "ci",
                    "Trusted Service": "codebuild.amazonaws.com",
                    "IsAdmin?": "No",
                    "CanPrivEscToAdmin?": "YES",
                }
            ],
        },
    )
    found = [f for f in parse_cloudfox(run).findings if f.check_id == PRIVESC_CHECK]
    # One per role, whatever trusts it; an admin role is already admin, not escalating.
    assert [f.resource_uid for f in found] == [_role("ci")]
    f = found[0]
    assert (f.severity, f.region, f.service, f.resource_type) == (
        "high",
        "global",
        "iam",
        "AwsIamRole",
    )
    assert f.categories == ("privilege-escalation",)


def test_only_another_accounts_root_without_external_id_is_a_trust_finding(
    tmp_path: Path,
) -> None:
    run = _run(
        tmp_path,
        {
            "role-trusts-principals": [
                _principal("vendor", f"arn:aws:iam::{OTHER}:root", admin=False, escalates=False),
                _principal("org", f"arn:aws:iam::{OTHER}:root", admin=True, escalates=False),
                _principal(
                    "safe", f"arn:aws:iam::{OTHER}:root", admin=True, escalates=False, ext="x"
                ),
                _principal("own", f"arn:aws:iam::{ACCOUNT}:root", admin=True, escalates=False),
                _principal(
                    "named", f"arn:aws:iam::{OTHER}:role/deployer", admin=False, escalates=False
                ),
            ]
        },
    )
    found = {
        f.resource_uid: f for f in parse_cloudfox(run).findings if f.check_id == ROOT_TRUST_CHECK
    }
    assert set(found) == {_role("vendor"), _role("org")}
    assert found[_role("vendor")].severity == "medium"
    assert found[_role("org")].severity == "high"  # an admin role raises it
    assert OTHER in found[_role("vendor")].title
    assert found[_role("vendor")].categories == ("trust-boundaries",)


def test_public_endpoints_carry_prowler_names(tmp_path: Path) -> None:
    def endpoint(service: str, name: str, public: str, port: str = "443") -> dict[str, str]:
        return {
            "Account": ACCOUNT,
            "Service": service,
            "Region": "us-east-1",
            "Name": name,
            "Endpoint": f"{name}.example",
            "Port": port,
            "Protocol": "https",
            "Public": public,
        }

    run = _run(
        tmp_path,
        {
            "endpoints": [
                endpoint("Lambda URL", "billing", "True"),
                endpoint("ELBv2", "web-lb", "True"),
                endpoint("ELBv2", "web-lb", "True", port="80"),
                endpoint("RDS", "db", "False", port="5432"),
                endpoint("Grafana", "dash", "True"),
            ]
        },
    )
    batch = parse_cloudfox(run)
    found = [f for f in batch.findings if f.check_id == PUBLIC_ENDPOINT_CHECK]
    assert len(found) == 4  # the private database is not one; each port is
    lam = next(f for f in found if "billing" in f.title)
    assert lam.resource_uid == f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:billing"
    assert (lam.service, lam.resource_type) == ("awslambda", "AwsLambdaFunction")
    lbs = [f for f in found if f.resource_uid == "ELBv2:web-lb"]
    assert {(f.service, f.resource_type) for f in lbs} == {("elbv2", "AwsElbv2LoadBalancer")}
    # The loader looks the load balancer up by name, like its edge.
    assert {batch.finding_targets[f.finding_uid][0] for f in lbs} == {"web-lb"}
    other = next(f for f in found if "dash" in f.title)
    assert (other.service, other.resource_type) == ("grafana", "Other")
    assert all(f.categories == ("internet-exposed",) for f in found)


def test_each_check_runs_only_when_its_file_exists(tmp_path: Path) -> None:
    run = _run(tmp_path, {"endpoints": []})
    executed = parse_cloudfox(run).executed
    assert executed == {(PUBLIC_ENDPOINT_CHECK, ANY_REGION)}


def test_every_check_runs_everywhere_on_a_full_run(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {"role-trusts-principals": [], "endpoints": [], "env-vars": []},
    )
    checks = {check for check, region in parse_cloudfox(run).executed}
    assert checks == {ENV_EXPOSURE_CHECK, PRIVESC_CHECK, ROOT_TRUST_CHECK, PUBLIC_ENDPOINT_CHECK}
    assert {region for _, region in parse_cloudfox(run).executed} == {ANY_REGION}


def test_finding_uids_are_stable_and_values_never_read(tmp_path: Path) -> None:
    rows = {
        "env-vars": [
            {
                "Account": ACCOUNT,
                "Service": "Lambda",
                "Region": "us-east-1",
                "Name": "billing",
                "Key": "DB_PASSWORD",
                "Value": "pw-must-not-appear",
            },
            {
                "Account": ACCOUNT,
                "Service": "Lambda",
                "Region": "us-east-1",
                "Name": "billing",
                "Key": "LOG_LEVEL",
                "Value": "debug",
            },
        ]
    }
    first = parse_cloudfox(_run(tmp_path / "a", rows)).findings
    again = parse_cloudfox(_run(tmp_path / "b", rows)).findings
    assert [f.finding_uid for f in first] == [f.finding_uid for f in again]
    assert len(first) == 1
    f = first[0]
    assert (f.service, f.resource_type, f.categories) == (
        "awslambda",
        "AwsLambdaFunction",
        ("secrets",),
    )
    assert "pw-must-not-appear" not in repr(first)


def test_network_ports_count_only_public_addresses(tmp_path: Path) -> None:
    """network-ports (argus_v12) merges public and private hosts and lists every load
    balancer's DNS name, internal ones too: only a public IP address becomes an edge, which the
    loader then joins to the inventory through the host index."""

    def row(service: str, host: str, ports: str, protocol: str = "tcp") -> dict[str, str]:
        return {
            "Account": ACCOUNT,
            "Service": service,
            "Region": "us-east-1",
            "Protocol": protocol,
            "Host": host,
            "Ports": ports,
        }

    run = _run(
        tmp_path,
        {
            "network-ports": [
                row("EC2", "3.80.0.7", "80"),
                row("EC2", "2001:db8::7", "80"),  # a documentation range: not a public address
                row("EC2", "2600:1f18::7", "80,443"),
                row("EC2", "10.0.1.7", "22"),
                row("ECS", "3.80.0.8", "8000-8100", "udp"),
                row("ELBv2", "internal-app-1.us-east-1.elb.amazonaws.com", "443"),
                row("RDS", "db.abc.us-east-1.rds.amazonaws.com", "5432"),
                row("EC2", "3.80.0.9", ""),
            ]
        },
    )
    edges = [e for e in parse_cloudfox(run).edges if e.attributes.get("module") == "network-ports"]
    assert [(e.target_host, e.attributes["protocol"], e.attributes["ports"]) for e in edges] == [
        ("3.80.0.7", "tcp", "80"),
        ("2600:1f18::7", "tcp", "80,443"),
        ("3.80.0.8", "udp", "8000-8100"),
    ]
    assert {(e.source_uid, e.type, e.target_uid) for e in edges} == {
        ("internet", "INTERNET_REACHABLE", None)
    }
    assert edges[0].attributes["service"] == "EC2"
