"""Synthetic CloudFox v2.0.5 output for the modules the adapter reads.

Formats follow CloudFox's legacy writer (internal/output.go), which AWS modules use. CloudFox
nests its files as cloudfox-output/aws/<profile>-<account>/{csv,json}/; the AWS source moves
them up after the run, so the archive holds <out>/{csv,json}/<file>.{csv,json}, and this source
writes that layout directly. A JSON file is an
indented array of objects mapping each header to a string value. Headers are copied from the
module sources (aws/role-trusts.go, permissions.go, endpoints.go, env-vars.go); flags are
"YES"/"No" and "True"/"False" as the modules print them. Three allowlisted loot files are
written too, so the Demo estate shows CloudFox's commands (ADR-0038): bucket-commands,
instances-ssmCommands and network-ports-public-ipv4, in CloudFox's block format. They carry no
secret values. Other table and loot files are not written: no adapter reads them.

env-vars rows carry secret values, as the real module's do.
"""

import csv
import io
import json
from pathlib import Path

from argus.collection.synthetic.estate import EstateDay

TOOL_VERSION = "2.0.5"

ROLE_TRUST_PRINCIPALS = (
    "Account",
    "Role Arn",
    "Role Name",
    "Trusted Principal",
    "ExternalID",
    "IsAdmin?",
    "CanPrivEscToAdmin?",
)
ROLE_TRUST_SERVICES = (
    "Account",
    "Role Arn",
    "Role Name",
    "Trusted Service",
    "IsAdmin?",
    "CanPrivEscToAdmin?",
)
PERMISSIONS = (
    "Account",
    "Type",
    "Name",
    "Arn",
    "Policy",
    "Policy Name",
    "Policy Arn",
    "Effect",
    "Action",
    "Resource",
    "Condition",
)
ENDPOINTS = ("Account", "Service", "Region", "Name", "Endpoint", "Port", "Protocol", "Public")
ENV_VARS = ("Account", "Service", "Region", "Name", "Key", "Value")

# Module files in the order all-checks produces them; throttling cuts the tail.
MODULES = ("role-trusts-principals", "role-trusts-services", "permissions", "endpoints", "env-vars")


def _yes(flag: bool) -> str:
    return "YES" if flag else "No"


def tables(estate: EstateDay) -> dict[str, tuple[tuple[str, ...], list[list[str]]]]:
    acct = estate.account_id
    roles = estate.resources.get("aws_iam_role", [])
    escalate = estate.roles_that_escalate
    principals, services, permissions = [], [], []
    for role in roles:
        trusted = role.attrs["trusted"]
        admin = role.attrs["admin"]
        if trusted.startswith("arn:"):
            principals.append(
                [acct, role.arn, role.name, trusted, "", _yes(admin), _yes(role.name in escalate)]
            )
        else:
            services.append(
                [acct, role.arn, role.name, trusted, _yes(admin), _yes(role.name in escalate)]
            )
        if admin:
            permissions.append(
                [
                    acct,
                    "Role",
                    role.name,
                    role.arn,
                    "Managed",
                    "AdministratorAccess",
                    "arn:aws:iam::aws:policy/AdministratorAccess",
                    "Allow",
                    "*",
                    "*",
                    "",
                ]
            )
            continue
        actions = ["s3:GetObject", "logs:PutLogEvents"]
        if role.name in escalate:
            actions += ["iam:PassRole", "ec2:RunInstances"]
        for action in actions:
            permissions.append(
                [
                    acct,
                    "Role",
                    role.name,
                    role.arn,
                    "Inline",
                    f"{role.name}-policy",
                    "",
                    "Allow",
                    action,
                    "*",
                    "",
                ]
            )

    endpoints = []
    for lb in estate.resources.get("aws_ec2_application_load_balancer", []) + estate.resources.get(
        "aws_ec2_network_load_balancer", []
    ):
        endpoints.append(
            [
                acct,
                "ELBv2",
                lb.region,
                lb.name,
                lb.attrs["dns_name"],
                "443",
                "https",
                str(lb.attrs["scheme"] == "internet-facing"),
            ]
        )
    for fn in estate.resources.get("aws_lambda_function", []):
        if fn.attrs["public_url"]:
            endpoints.append(
                [
                    acct,
                    "Lambda URL",
                    fn.region,
                    fn.name,
                    f"https://{fn.name}.lambda-url.{fn.region}.on.aws/",
                    "443",
                    "https",
                    "True",
                ]
            )
    for db in estate.resources.get("aws_rds_db_instance", []):
        endpoints.append(
            [
                acct,
                "RDS",
                db.region,
                db.name,
                f"{db.name}.{db.region}.rds.amazonaws.com",
                "5432",
                "tcp",
                str(bool(db.attrs["public"])),
            ]
        )

    env_vars = [
        [acct, "Lambda", fn.region, fn.name, key, value]
        for fn in estate.resources.get("aws_lambda_function", [])
        for key, value in fn.attrs["environment"].items()
    ]

    return {
        "role-trusts-principals": (ROLE_TRUST_PRINCIPALS, principals),
        "role-trusts-services": (ROLE_TRUST_SERVICES, services),
        "permissions": (PERMISSIONS, permissions),
        "endpoints": (ENDPOINTS, endpoints),
        "env-vars": (ENV_VARS, env_vars),
    }


def loot(estate: EstateDay) -> dict[str, str]:
    """The allowlisted loot files for the Demo estate (ADR-0038): CloudFox's own block format,
    command text templated from resource names, ids and public addresses only. No secret values.
    The adapter parses, labels and resolves these exactly as it does a real run's."""
    profile_banner = (
        "#############################################\n"
        "# Set the $profile environment variable to the profile you will use.\n"
        "#############################################\n\n"
    )
    files: dict[str, str] = {}

    # Every bucket, so any bucket in the Demo shows the block (the browser walk opens one).
    buckets = estate.resources.get("aws_s3_bucket", [])
    if buckets:
        blocks = [profile_banner]
        for b in buckets:
            blocks.append(f"# Bucket: {b.name}\n")
            blocks.append(f"aws --profile $profile s3 ls --recursive s3://{b.name}/\n")
            blocks.append("# Download the whole bucket (do this with caution)\n")
            blocks.append(
                f"aws --profile $profile s3 cp s3://{b.name}/ ./s3-buckets/{b.name} --recursive\n\n"
            )
        files["bucket-commands.txt"] = "".join(blocks)

    public = [r for r in estate.resources.get("aws_ec2_instance", []) if r.attrs.get("public_ip")][
        :4
    ]
    if public:
        blocks = []
        for inst in public:
            region = inst.region
            blocks.append("-" * 71 + "\n")
            blocks.append(f"############## Instance: {inst.native_id}  ##############\n")
            blocks.append("-" * 71 + "\n")
            blocks.append(f"### SSM start-session to {inst.native_id} ###\n")
            blocks.append(
                f"aws --profile $profile --region {region} ssm start-session "
                f"--target {inst.native_id}\n\n"
            )
        files["instances-ssmCommands.txt"] = "".join(blocks)

        ports_header = (
            "#############################################\n"
            "# The network services may have various ingress rules depending on your source IP.\n"
            "#############################################\n"
        )
        nmap = "".join(
            f"sudo nmap -Pn -sV -p 22,443 {inst.attrs['public_ip']}\n" for inst in public
        )
        files["network-ports-public-ipv4.txt"] = ports_header + nmap

    return files


def write(out_dir: Path, estate: EstateDay, *, keep_modules: int | None) -> int:
    (out_dir / "csv").mkdir(parents=True)
    (out_dir / "json").mkdir()
    rows_written = 0
    for i, (name, (header, body)) in enumerate(tables(estate).items()):
        if keep_modules is not None and i >= keep_modules:
            break
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(body)
        (out_dir / "csv" / f"{name}.csv").write_text(buffer.getvalue())
        records = [dict(zip(header, row, strict=True)) for row in body]
        (out_dir / "json" / f"{name}.json").write_text(json.dumps(records, indent=2))
        rows_written += len(body)
    # Loot files (ADR-0038), always written whole: they are a few lines and have no modules to cap.
    loot_files = loot(estate)
    if loot_files:
        (out_dir / "loot").mkdir(exist_ok=True)
        for name, body_text in loot_files.items():
            (out_dir / "loot" / name).write_text(body_text)
    return rows_written
