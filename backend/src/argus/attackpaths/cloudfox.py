"""The CloudFox adapter: role trusts, admin/escalation flags, public endpoints, the ports open on
public addresses (network-ports) and secret-like environment variables -> edges and
attacker-view findings. Pure.

Findings (2026-10-07) come from the same files as the edges, one check each: a role that can
escalate to administrator, a role that trusts another account's root without an ExternalId, a
public endpoint, and a secret-like environment variable. They carry Prowler's service, resource
type and category names, so the Findings filters match both tools.

env-vars rows carry secret VALUES. The parser reads the variable name and the resource only;
the value column is never copied into the batch, so it cannot reach Postgres by any path.
"""

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

from argus.core.rawstore import RawRun
from argus.core.redaction import is_secret_key, redact_text
from argus.core.resolver import resolve
from argus.findings import ANY_REGION, FindingResult

SUPPORTED_VERSIONS = frozenset({"2.0.5"})
INTERNET = "internet"
# The attacker-view checks.
ENV_EXPOSURE_CHECK = "cloudfox_env_var_secret"
PRIVESC_CHECK = "cloudfox_role_privesc_to_admin"
ROOT_TRUST_CHECK = "cloudfox_cross_account_root_trust_no_external_id"
PUBLIC_ENDPOINT_CHECK = "cloudfox_public_endpoint"
_TRUST_FILES = ("role-trusts-principals", "role-trusts-services")
_ROOT_RE = re.compile(r"^arn:aws[a-z-]*:iam::([0-9]{12}):root$")
# CloudFox's service names -> Prowler's service and resource type. Others: the CloudFox name
# in lower case, type "Other" (Prowler's own fallback).
_PROWLER_NAMES = {
    "Lambda": ("awslambda", "AwsLambdaFunction"),
    "Lambda URL": ("awslambda", "AwsLambdaFunction"),
    "ECS": ("ecs", "AwsEcsTaskDefinition"),
    "ELBv2": ("elbv2", "AwsElbv2LoadBalancer"),
    "ELB": ("elb", "AwsElbLoadBalancer"),
    "RDS": ("rds", "AwsRdsDbInstance"),
    "API Gateway": ("apigateway", "AwsApiGatewayRestApi"),
    "CloudFront": ("cloudfront", "AwsCloudFrontDistribution"),
    "EKS": ("eks", "AwsEksCluster"),
    "OpenSearch": ("opensearch", "AwsOpenSearchServiceDomain"),
    "Redshift": ("redshift", "AwsRedshiftCluster"),
}
_ROLE = ("iam", "AwsIamRole")
_ENDPOINT_KINDS = {"Lambda URL": "lambda_function", "RDS": "rds_db_instance"}
_ENDPOINT_TYPES = {"ELBv2": ("aws_ec2_application_load_balancer", "aws_ec2_network_load_balancer")}


class UnsupportedVersionError(ValueError):
    pass


def admin_node(account_id: str) -> str:
    """The pseudo-node that stands for "administrator of this account"."""
    return f"admin:{account_id}"


@dataclass(frozen=True)
class CloudFoxEdge:
    source_uid: str
    type: str
    attributes: dict[str, Any]
    target_uid: str | None = None
    # When the target is only known by name (a load balancer), the loader looks it up.
    target_name: str | None = None
    target_types: tuple[str, ...] = ()
    # When it is only known by a public address (network-ports), the loader asks the host
    # index which resource holds it.
    target_host: str | None = None


@dataclass
class CloudFoxBatch:
    edges: list[CloudFoxEdge]
    findings: list[FindingResult]
    executed: frozenset[tuple[str, str]]
    complete: bool
    unresolved: list[str]
    # Findings on a resource known only by name (a load balancer): finding_uid -> the name and
    # inventory types the loader looks it up by, as for edges.
    finding_targets: dict[str, tuple[str, tuple[str, ...]]] = field(default_factory=dict)
    # CloudFox's loot commands (ADR-0038), tied to a resource; the loader resolves and stores them.
    commands: list["LootCommand"] = field(default_factory=list)


def _rows(run: RawRun, name: str) -> list[dict[str, str]] | None:
    # json/<module>.json since 2026-10-06; older runs keep CloudFox's own nesting
    # (cloudfox-output/aws/<profile>-<account>/json/) and still replay.
    wanted = f"json/{name}.json"
    file = next(
        (f for f in run.manifest.files if f.path == wanted or f.path.endswith(f"/{wanted}")),
        None,
    )
    if file is None:
        return None
    rows: list[dict[str, str]] = json.loads(run.path(file.path).read_text())
    return rows


def _trust_edges(run: RawRun, account: str) -> list[CloudFoxEdge]:
    edges: list[CloudFoxEdge] = []
    admin = admin_node(account)
    for name in ("role-trusts-principals", "role-trusts-services"):
        for row in _rows(run, name) or []:
            role = row["Role Arn"]
            if name == "role-trusts-principals" and row.get("Trusted Principal"):
                edges.append(
                    CloudFoxEdge(
                        row["Trusted Principal"],
                        "CAN_ASSUME",
                        {"external_id": bool(row.get("ExternalID"))},
                        target_uid=role,
                    )
                )
            if row.get("IsAdmin?") == "YES":
                edges.append(CloudFoxEdge(role, "IS_ADMIN", {}, target_uid=admin))
            if row.get("CanPrivEscToAdmin?") == "YES":
                edges.append(CloudFoxEdge(role, "CAN_PRIVESC_TO", {}, target_uid=admin))
    return edges


def _endpoint_edges(run: RawRun, account: str) -> tuple[list[CloudFoxEdge], list[str]]:
    edges: list[CloudFoxEdge] = []
    unresolved: list[str] = []
    for row in _rows(run, "endpoints") or []:
        if row.get("Public") != "True":
            continue
        attrs = {
            "service": row["Service"],
            "port": row.get("Port"),
            "protocol": row.get("Protocol"),
        }
        service, region, name = row["Service"], row.get("Region"), row["Name"]
        if service in _ENDPOINT_TYPES:
            edges.append(
                CloudFoxEdge(
                    INTERNET,
                    "INTERNET_REACHABLE",
                    attrs,
                    target_name=name,
                    target_types=_ENDPOINT_TYPES[service],
                )
            )
            continue
        uid = resolve(name, account_id=account, region=region, kind=_ENDPOINT_KINDS.get(service))
        if uid is None:
            unresolved.append(f"{service}:{name}")
            continue
        edges.append(CloudFoxEdge(INTERNET, "INTERNET_REACHABLE", attrs, target_uid=uid))
    return edges, unresolved


def _public_address(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def _network_port_edges(run: RawRun) -> list[CloudFoxEdge]:
    """network-ports (aws/network-ports.go): the ports a resource's security groups and network
    ACL let in, per address (argus_v12). Its JSON merges public and private addresses and lists
    every load balancer's DNS name as public, internal ones too, so only a row whose host is a
    public IP address counts. It does not check a rule's source range or the route to an
    internet gateway: Argus's own rules judge that, and a door only CloudFox finds is shown as
    CloudFox's alone (ADR-0035, third amendment)."""
    edges: list[CloudFoxEdge] = []
    for row in _rows(run, "network-ports") or []:
        host = (row.get("Host") or "").strip()
        if not _public_address(host) or not row.get("Ports"):
            continue
        attrs = {
            "module": "network-ports",
            "service": row.get("Service"),
            "protocol": (row.get("Protocol") or "").lower(),
            "ports": row["Ports"],
        }
        edges.append(CloudFoxEdge(INTERNET, "INTERNET_REACHABLE", attrs, target_host=host))
    return edges


def _prowler_names(service: str) -> tuple[str, str]:
    return _PROWLER_NAMES.get(service, (service.lower().replace(" ", ""), "Other"))


def _finding(
    check: str,
    uid: str,
    discriminator: str,
    *,
    severity: str,
    region: str,
    title: str,
    names: tuple[str, str],
    category: str,
    remediation: tuple[str, str],
) -> FindingResult:
    """One attacker-view finding. Its uid hashes the tool, check, resource and what tells two
    findings on one resource apart, so it is stable across scans."""
    digest = hashlib.sha256(f"cloudfox|{check}|{uid}|{discriminator}".encode()).hexdigest()
    return FindingResult(
        finding_uid=f"cloudfox-{digest[:40]}",
        check_id=check,
        status="FAIL",
        muted=False,
        severity=severity,
        region=region,
        resource_uid=uid,
        title=title,
        remediation_text=remediation[0],
        remediation_url=remediation[1],
        compliance={},
        service=names[0],
        resource_type=names[1],
        categories=(category,),
    )


_ENV_REMEDIATION = (
    "Move the value to AWS Secrets Manager or SSM Parameter Store "
    "and read it at runtime; rotate the exposed secret.",
    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html",
)
_PRIVESC_REMEDIATION = (
    "Remove the permissions that let this role gain administrator rights (for example "
    "iam:PassRole with a compute service, iam:CreatePolicyVersion or iam:AttachRolePolicy), "
    "or limit them to specific resources; review who can assume the role.",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
)
_ROOT_TRUST_REMEDIATION = (
    "Add an sts:ExternalId condition to the role's trust policy, or trust a specific role in "
    "that account instead of its root, so only the intended principal can assume it.",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html",
)
_ENDPOINT_REMEDIATION = (
    "Confirm the endpoint must be public. If not, make it internal or restrict who can reach it "
    "(security groups, resource policies, authentication).",
    "https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/"
    "attack-surface-reduction.html",
)


def _env_findings(rows: list[dict[str, str]], account: str) -> list[FindingResult]:
    findings: list[FindingResult] = []
    for row in rows:
        key = row["Key"]  # the value column is never read
        if not is_secret_key(key):
            continue
        service, region, name = row["Service"], row.get("Region") or "global", row["Name"]
        uid = (
            resolve(name, account_id=account, region=region, kind="lambda_function")
            if service == "Lambda"
            else None
        ) or f"{service}:{name}"
        findings.append(
            _finding(
                ENV_EXPOSURE_CHECK,
                uid,
                key,
                severity="high",
                region=region,
                title=f"Secret-like environment variable {key} in {service} {name}",
                names=_prowler_names(service),
                category="secrets",
                remediation=_ENV_REMEDIATION,
            )
        )
    return findings


def _trust_findings(run: RawRun, account: str) -> list[FindingResult]:
    findings: dict[str, FindingResult] = {}
    for name in _TRUST_FILES:
        for row in _rows(run, name) or []:
            role, role_name = row["Role Arn"], row.get("Role Name") or row["Role Arn"]
            admin = row.get("IsAdmin?") == "YES"
            escalates = row.get("CanPrivEscToAdmin?") == "YES"
            if escalates and not admin:
                f = _finding(
                    PRIVESC_CHECK,
                    role,
                    "",
                    severity="high",
                    region="global",
                    title=f"Role {role_name} can escalate to administrator",
                    names=_ROLE,
                    category="privilege-escalation",
                    remediation=_PRIVESC_REMEDIATION,
                )
                findings[f.finding_uid] = f
            trusted = _ROOT_RE.match(row.get("Trusted Principal") or "")
            if trusted and trusted.group(1) != account and not row.get("ExternalID"):
                f = _finding(
                    ROOT_TRUST_CHECK,
                    role,
                    row["Trusted Principal"],
                    severity="high" if admin or escalates else "medium",
                    region="global",
                    title=(
                        f"Role {role_name} trusts account {trusted.group(1)} without an ExternalId"
                    ),
                    names=_ROLE,
                    category="trust-boundaries",
                    remediation=_ROOT_TRUST_REMEDIATION,
                )
                findings[f.finding_uid] = f
    return list(findings.values())


def _endpoint_findings(
    rows: list[dict[str, str]], account: str
) -> tuple[list[FindingResult], dict[str, tuple[str, tuple[str, ...]]]]:
    findings: dict[str, FindingResult] = {}
    targets: dict[str, tuple[str, tuple[str, ...]]] = {}
    for row in rows:
        if row.get("Public") != "True":
            continue
        service, region, name = row["Service"], row.get("Region") or "global", row["Name"]
        port = row.get("Port") or ""
        uid = (
            resolve(name, account_id=account, region=region, kind=_ENDPOINT_KINDS[service])
            if service in _ENDPOINT_KINDS
            else None
        ) or f"{service}:{name}"
        f = _finding(
            PUBLIC_ENDPOINT_CHECK,
            uid,
            port,
            severity="medium",
            region=region,
            title=f"{service} {name} is reachable from the internet"
            + (f" on port {port}" if port else ""),
            names=_prowler_names(service),
            category="internet-exposed",
            remediation=_ENDPOINT_REMEDIATION,
        )
        findings[f.finding_uid] = f
        if service in _ENDPOINT_TYPES:
            targets[f.finding_uid] = (name, _ENDPOINT_TYPES[service])
    return list(findings.values()), targets


# ── CloudFox loot commands (ADR-0038) ──────────────────────────────────────────
# Argus shows the commands from CloudFox's loot files, labelled and never run. Only the files
# below are read; any other loot file (secret-bearing user data, env-vars, lists, policy JSON,
# PMapper) is never opened. A command's resource is named in a header line or in the command
# itself; it resolves like an edge target (a built uid, a name + inventory types, or a public
# host). Every command and note passes redact_text() before it is stored, so no secret value
# reaches Postgres. The label comes from a fixed table of AWS CLI operations and tools and fails
# closed to "acts_on_target".

CHECK = "check"
READS_DATA = "reads_data"
ACTS_ON_TARGET = "acts_on_target"

# (service, operation) -> label. Anything not here is acts_on_target.
_AWS_LABELS = {
    ("s3", "ls"): CHECK,
    ("lambda", "get-function"): CHECK,
    ("eks", "update-kubeconfig"): CHECK,
    ("s3", "cp"): READS_DATA,
    ("secretsmanager", "get-secret-value"): READS_DATA,
    ("ssm", "get-parameter"): READS_DATA,
    ("ssm", "get-parameters"): READS_DATA,
    ("sqs", "receive-message"): READS_DATA,
}
# Leading non-aws tools. docker and curl/wget are judged by their own arguments below.
_TOOL_LABELS = {"nmap": CHECK, "mkdir": CHECK, "mount": READS_DATA}
_RANK = {CHECK: 0, READS_DATA: 1, ACTS_ON_TARGET: 2}

_REGION_RE = re.compile(r"--region\s+(\S+)")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]+\b")
_APIGW_RE = re.compile(r"https://([a-z0-9]+)\.execute-api\.")
# Shell control operators: a line chaining several commands is labelled by its worst part.
_SEGMENT_RE = re.compile(r"\|\||&&|[;|&]")
# A request body or upload makes curl/wget send data, whatever the method flag says.
_SENDS_FLAGS = ("-d", "-F", "-T")
_SENDS_PREFIXES = ("--data", "--form", "--json", "--upload-file", "--post-")


@dataclass(frozen=True)
class LootCommand:
    """One command from a loot file. The resource is resolved like an edge target: a built uid,
    a name the loader looks up by inventory type, or a public host the loader maps to its owner.
    Exactly one of uid / name / host is set."""

    label: str
    command: str
    note: str | None
    source: str
    ordinal: int
    resource_uid: str | None = None
    resource_name: str | None = None
    resource_types: tuple[str, ...] = ()
    resource_host: str | None = None


def _classify(command: str) -> str:
    """The command's label, from the fixed table; acts_on_target when unknown (fail closed). A
    line that chains commands takes its worst part's label; a command substitution acts."""
    if "$(" in command or "`" in command:
        return ACTS_ON_TARGET
    labels = [_classify_one(part) for part in _SEGMENT_RE.split(command)]
    return max(labels, key=_RANK.__getitem__)


def _http_method(tokens: list[str]) -> str:
    for i, token in enumerate(tokens):
        if token in ("-X", "--request", "--method"):
            return tokens[i + 1].upper() if i + 1 < len(tokens) else ""
        for flag in ("-X", "--request=", "--method="):
            if token.startswith(flag) and len(token) > len(flag):
                return token[len(flag) :].upper()
    return "GET"


def _classify_one(command: str) -> str:
    tokens = command.split()
    while tokens and (tokens[0] == "sudo" or "=" in tokens[0]):
        tokens = tokens[1:]  # sudo, and VAR=value prefixes
    if not tokens:
        return ACTS_ON_TARGET
    lead = tokens[0]
    if lead == "aws":
        i = 1
        while i < len(tokens) and tokens[i].startswith("--"):
            i += 2  # a global flag and its value (--profile X, --region Y, --output Z)
        if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
            return _AWS_LABELS.get((tokens[i], tokens[i + 1]), ACTS_ON_TARGET)
        return ACTS_ON_TARGET
    if lead in ("curl", "wget"):
        sends = any(t.startswith(_SENDS_FLAGS) or t.startswith(_SENDS_PREFIXES) for t in tokens)
        if sends or _http_method(tokens) not in ("GET", "HEAD"):
            return ACTS_ON_TARGET
        downloads = lead == "wget" or any(
            t in ("-o", "-O", "--output", "--remote-name") or t.startswith("--output=")
            for t in tokens
        )
        return READS_DATA if downloads else CHECK
    if lead == "docker":
        return READS_DATA if tokens[1:2] == ["pull"] else ACTS_ON_TARGET
    return _TOOL_LABELS.get(lead, ACTS_ON_TARGET)


def _region(command: str, default: str) -> str:
    match = _REGION_RE.search(command)
    return match.group(1) if match else default


def _ref(kind: str, name: str, account: str, region: str) -> dict[str, Any]:
    """The resource a command names, as uid / name+types / host (mirrors CloudFoxEdge)."""
    if kind == "host":
        return {"resource_host": name}
    uid = {
        "s3_bucket": f"arn:aws:s3:::{name}",
        "lambda_function": f"arn:aws:lambda:{region}:{account}:function:{name}",
        "sqs": f"arn:aws:sqs:{region}:{account}:{name}",
        "sns": f"arn:aws:sns:{region}:{account}:{name}",
        "eks": f"arn:aws:eks:{region}:{account}:cluster/{name}",
    }.get(kind)
    if kind == "ec2_instance":
        uid = resolve(name, account_id=account, region=region, kind=None)
    if uid is not None:
        return {"resource_uid": uid}
    # Known only by name: the loader looks it up in the inventory (secrets, API Gateway, ECR, EFS).
    types = {
        "secret": ("aws_secretsmanager_secret",),
        "apigw": ("aws_api_gatewayv2_api", "aws_api_gateway_rest_api"),
        "ecr": ("aws_ecr_repository",),
        "efs": ("aws_efs_file_system", "aws_fsx_file_system"),
    }.get(kind, ())
    return {"resource_name": name, "resource_types": types}


# Files whose blocks name the resource in a header line: a regex and the resource kind.
_HEADER_FILES = {
    "bucket-commands.txt": (re.compile(r"^#\s*Bucket:\s*(.+?)\s*$"), "s3_bucket"),
    "sqs-commands.txt": (re.compile(r"^#\s*Queue:\s*(.+?)\s*$"), "sqs"),
    "sns-commands.txt": (re.compile(r"^#\s*Topic:\s*(.+?)\s*$"), "sns"),
    "lambda-get-function-commands.txt": (
        re.compile(r"^#\s*Lambda Name:\s*(.+?)\s*$"),
        "lambda_function",
    ),
    "instances-ssmCommands.txt": (re.compile(r"^#+\s*Instance:\s*(\S+)"), "ec2_instance"),
    "instances-ec2InstanceConnectCommands.txt": (
        re.compile(r"^#+\s*Instance:\s*(\S+)"),
        "ec2_instance",
    ),
    # Formats below are from CloudFox's source; the emulator did not exercise them, so they are
    # re-checked against a real fixture (docs/spikes/cloudfox-loot.md, Next).
    "ecr-pull-commands.txt": (re.compile(r"^#\s*(?:Repository|Repo):\s*(.+?)\s*$"), "ecr"),
    "filesystems-mount-commands.txt": (
        re.compile(r"^#\s*(?:File ?[Ss]ystem|Filesystem):\s*(\S+)"),
        "efs",
    ),
}
# Allowlisted files whose resource is named in each command, not a header.
_COMMAND_FILES = (
    "network-ports-public-ipv4.txt",
    "network-ports-private-ipv4.txt",
    "network-ports-public-ipv6.txt",
    "api-gw.txt",
    "eks-kubeconfig-commands.txt",
    "pull-secrets-commands.txt",
)
LOOT_FILES = frozenset(_HEADER_FILES) | frozenset(_COMMAND_FILES)

_SEPARATOR_RE = re.compile(r"^\s*[-=]{3,}\s*$")


def _refs_from_command(
    source: str, command: str, account: str, region: str
) -> list[dict[str, Any]]:
    """The resource(s) a header-less file's command names."""
    if source.startswith("network-ports"):
        ips = _IPV6_RE.findall(command) if "ipv6" in source else _IPV4_RE.findall(command)
        return [{"resource_host": ip} for ip in ips]
    if source == "api-gw.txt":
        match = _APIGW_RE.search(command)
        return [_ref("apigw", match.group(1), account, region)] if match else []
    if source == "eks-kubeconfig-commands.txt":
        match = re.search(r"--name\s+(\S+)", command)
        return [_ref("eks", match.group(1), account, region)] if match else []
    if source == "pull-secrets-commands.txt":
        match = re.search(r"--secret-id\s+(\S+)", command)
        return [_ref("secret", match.group(1), account, region)] if match else []
    return []


def _loot_text(run: RawRun, name: str) -> str | None:
    wanted = f"loot/{name}"
    file = next(
        (f for f in run.manifest.files if f.path == wanted or f.path.endswith(f"/{wanted}")),
        None,
    )
    return run.path(file.path).read_text() if file is not None else None


def _loot_commands(run: RawRun, account: str, default_region: str) -> list[LootCommand]:
    """Every command from the allowlisted loot files, cleaned, labelled and tied to a resource."""
    commands: list[LootCommand] = []
    ordinal = 0
    for source in sorted(LOOT_FILES):
        text = _loot_text(run, source)
        if text is None:
            continue
        header = _HEADER_FILES.get(source)
        current: dict[str, Any] | None = None
        pending: list[str] = []
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line.strip() or _SEPARATOR_RE.match(line):
                pending.clear()
                continue
            header_match = header[0].match(line) if header is not None else None
            if header_match is not None:
                # The resource's uid is built per command, with the command's region (sqs/sns).
                current = {"_kind": header[1], "_name": header_match.group(1)}  # type: ignore[index]
                pending.clear()
                continue
            if line.lstrip().startswith("#"):
                pending.append(line.lstrip().lstrip("#").strip())
                continue
            # A command line.
            command = redact_text(line).strip()
            if not command:
                pending.clear()
                continue
            note = "\n".join(p for p in pending if p) or None
            if note is not None:
                note = redact_text(note)
            label = _classify(line)
            if header is not None:
                if current is None:
                    pending.clear()
                    continue
                ref = _ref(
                    current["_kind"], current["_name"], account, _region(line, default_region)
                )
                refs = [ref]
            else:
                refs = _refs_from_command(source, line, account, _region(line, default_region))
            for ref in refs:
                commands.append(
                    LootCommand(
                        label=label,
                        command=command,
                        note=note,
                        source=source,
                        ordinal=ordinal,
                        **ref,
                    )
                )
                ordinal += 1
            pending.clear()
    return commands


def parse_cloudfox(run: RawRun) -> CloudFoxBatch:
    manifest = run.manifest
    if manifest.tool != "cloudfox":
        raise ValueError(f"not a cloudfox run: {manifest.tool}")
    if manifest.tool_version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersionError(f"cloudfox {manifest.tool_version} not supported")
    account = manifest.account_id
    endpoint_edges, unresolved = _endpoint_edges(run, account)
    env_rows = _rows(run, "env-vars")
    endpoint_rows = _rows(run, "endpoints")
    principal_rows = _rows(run, "role-trusts-principals")
    trusts_ran = principal_rows is not None or _rows(run, "role-trusts-services") is not None
    # A check ran if the module behind it wrote its file: in every region of the run's scope (a
    # real CloudFox run scans every enabled region and records no scope: every region), or, for
    # the role checks, everywhere, because IAM is global.
    regions = manifest.region_scope or [ANY_REGION]
    ran = {
        ENV_EXPOSURE_CHECK: (env_rows is not None, regions),
        PUBLIC_ENDPOINT_CHECK: (endpoint_rows is not None, regions),
        PRIVESC_CHECK: (trusts_ran, [ANY_REGION]),
        ROOT_TRUST_CHECK: (principal_rows is not None, [ANY_REGION]),
    }
    executed = frozenset((check, r) for check, (did, scope) in ran.items() if did for r in scope)
    endpoint_findings, finding_targets = _endpoint_findings(endpoint_rows or [], account)
    return CloudFoxBatch(
        edges=_trust_edges(run, account) + endpoint_edges + _network_port_edges(run),
        findings=(
            _env_findings(env_rows or [], account)
            + _trust_findings(run, account)
            + endpoint_findings
        ),
        executed=executed,
        complete=manifest.status == "complete",
        unresolved=unresolved,
        finding_targets=finding_targets,
        commands=_loot_commands(run, account, regions[0]),
    )
