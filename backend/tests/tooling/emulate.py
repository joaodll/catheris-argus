"""Run the pinned CloudFox and Steampipe export against a fake AWS (moto), to learn their output
and to check that every table the inventory collects exports the way production runs it.

Dev only (argus_v11 round 4, ADR-0037; argus_v12). Two jobs:
- CloudFox: which loot and JSON files 2.0.5 writes and how their lines read.
- Steampipe: every table in steampipe_tables_aws.txt, exported with production's own options
  (collection/tables.py) and judged by production's own test (collection/aws/tools.py), as a
  user holding the scanner role's policies (deploy/aws/scanner-role.yaml) with moto enforcing
  them. A column the role cannot read fails its table here as it does on AWS (argus_v12: one
  denied EC2 column dropped every instance of a real account). report.json lists each table.
- `--scenario exposure` (2026-10-21): the exposure scenario estate (exposure_estate.py) alone,
  exported with moto's IAM checks off (the fixture is about data shapes, and moto fails its
  signature check on JSON-protocol services such as Lambda), written as a fixture with every
  secret value redacted (fixture/steampipe/), and, with `--prowler`, Prowler's own exposure
  checks against the same estate (scenario.json compares nothing: the test does).
It is a bridge until a scrubbed real fixture arrives (scrub_fixtures.py on the machine that
scans a real account); it never replaces one, because an emulator's values are not AWS's, moto
does not implement every API, and its copies of the AWS-managed policies may be older.

    docker compose --profile emulate run --rm emulate

Runs inside the `emulate` service: the worker image (the same pinned binaries) with the working
tree's backend source, on an internal network whose only other member is moto. There is no route
out and no real credential: every key is a moto placeholder or one moto issued. Output goes to
<repo>/emulated/ (git-ignored): it holds the estate's fake secret values on purpose, so the
env-vars loot can be inspected.

CloudFox fetches two public files on every run (docs/spikes/cloudfox-loot.md): AWS's region table,
which gates most modules, and fwdcloudsec's known-accounts list (role-trusts). There is no route
out, so the harness answers for both host names itself (argus_v13): small stand-ins over HTTPS,
from a CA made for the run and trusted by CloudFox alone (SSL_CERT_FILE). compose.yaml points the
two names at the container. CloudFox runs with moto's IAM checks off (they fail moto's JSON-protocol
services, as Lambda and ECS): it is here for its output formats; Steampipe runs with them on.
"""

from __future__ import annotations

import argparse
import datetime
import http.server
import io
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import boto3
import exposure_estate
import scrub_fixtures
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from argus.collection.aws.tools import denied_actions, table_failed, table_outcome
from argus.collection.tables import steampipe_tables, table_options
from argus.core import redaction
from argus.findings import PROWLER_EXPOSURE_CHECKS

REGION = "us-east-1"
PROFILE = "emulate"
FAKE_KEY = "testing"  # moto accepts any key while auth is off; its documented placeholders
CLOUDFOX = "/usr/local/bin/cloudfox"
STEAMPIPE = "/usr/local/bin/steampipe_export_aws"
PROWLER = "/opt/prowler/bin/prowler"
SCANNER_ROLE = Path("/policy/scanner-role.yaml")
TOOL_TIMEOUT = 900  # seconds
TABLE_TIMEOUT = 300  # seconds, per table
PARALLEL_TABLES = 8
# A failure moto causes, not our export: an API it does not implement or answers in a shape the
# SDK cannot decode. Such a table needs the real run to judge. moto enforces IAM reliably only
# for query-protocol services (EC2, IAM, ELB, RDS, ...), which hold the network data the
# internet rules read.
EMULATOR_GAP = re.compile(
    r"not yet implemented|NotImplemented|deserialization failed|StatusCode: (404|500|501)|"
    r"UnknownOperation|InvalidAction|failed to decode|"
    # moto's own signature check fails on some REST services (CloudFront, Backup, ...).
    r"SignatureDoesNotMatch|UnknownError|"
    # S3 addresses buckets by host name (<bucket>.moto), which the internal network cannot resolve.
    r"lookup [^ ]+[.]moto on",
    re.IGNORECASE,
)
REGION_TABLE_HOST = "api.regional-table.region-services.aws.a2z.com"
KNOWN_ACCOUNTS_HOST = "raw.githubusercontent.com"
KNOWN_ACCOUNTS_PATH = "/fwdcloudsec/known_aws_accounts/main/accounts.yaml"
# Every service CloudFox 2.0.5 asks the region table about (IsServiceInRegion and
# GetRegionsForService in its source). awsservicemap matches the slug of each entry's service URL.
CLOUDFOX_SERVICES = (
    "amazon-mq", "amazonlightsail.com", "api-gateway", "athena", "cloud9", "cloudformation",
    "cloudtrail", "codeartifact", "codebuild", "codecommit", "codedeploy", "datapipeline",
    "directoryservice", "dynamodb", "ec2", "ecr", "ecs", "efs", "eks", "elasticache",
    "elasticbeanstalk", "elasticloadbalancing", "glue", "grafana", "kms", "lambda",
    "opensearch-service", "ram", "rds", "redshift", "sagemaker-ai", "secrets-manager", "sns",
    "sqs", "step-functions", "streams", "systems-manager",
)  # fmt: skip
PARTNER_ACCOUNT = "210987654321"  # emu-partner's trusted account: a "known vendor" here


def region_table() -> bytes:
    """AWS's region table, cut to the services CloudFox asks about, in REGION only."""
    prices = [
        {
            "id": f"{slug}:{REGION}",
            "attributes": {
                "aws:region": REGION,
                "aws:serviceName": slug,
                "aws:serviceUrl": f"https://aws.amazon.com/{slug}/",
            },
        }
        for slug in CLOUDFOX_SERVICES
    ]
    return json.dumps({"prices": prices}).encode()


def known_accounts() -> bytes:
    """fwdcloudsec's list (name, source, accounts per vendor), with one emulated vendor."""
    return (
        f"- name: 'Emulated vendor'\n  source: ['https://example.com']\n"
        f"  accounts: ['{PARTNER_ACCOUNT}']\n"
    ).encode()


def _certificates(home: Path) -> tuple[Path, Path, Path]:
    """A CA for this run and a certificate for both host names. Only the run's tools trust it."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "argus emulator CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, REGION_TABLE_HOST)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(REGION_TABLE_HOST),
                    x509.DNSName(KNOWN_ACCOUNTS_HOST),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = home / "ca.pem", home / "server.pem", home / "server.key"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def serve_outside_files(home: Path, served: list[str]) -> Path:
    """Answer CloudFox's two outside requests on 127.0.0.1:443 (compose.yaml maps both names
    there). Returns the CA file for SSL_CERT_FILE; `served` collects what was asked for."""
    ca_path, cert_path, key_path = _certificates(home)
    files = {
        (REGION_TABLE_HOST, "/index.json"): (region_table(), "application/json"),
        (KNOWN_ACCOUNTS_HOST, KNOWN_ACCOUNTS_PATH): (known_accounts(), "text/plain"),
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            host = (self.headers.get("Host") or "").split(":")[0]
            served.append(f"{host}{self.path}")
            body, kind = files.get((host, self.path), (b"", ""))
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", kind or "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return ca_path


def wait_for(endpoint: str, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            with urllib.request.urlopen(f"{endpoint}/moto-api/", timeout=2):  # noqa: S310 - fixed
                return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def reset(endpoint: str) -> None:
    """moto keeps its estate while it runs: start every run from an empty account."""
    request = urllib.request.Request(f"{endpoint}/moto-api/reset", method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=10):  # noqa: S310 - fixed internal endpoint
        pass


def enforce_auth(endpoint: str, on: bool) -> None:
    """moto checks every request against IAM after this many more requests: never (seeding),
    or from now on (the tools)."""
    request = urllib.request.Request(  # noqa: S310 - fixed internal endpoint
        f"{endpoint}/moto-api/reset-auth",
        data=b"0" if on else b"inf",
        method="POST",
        headers={"Content-Type": "text/plain"},  # moto reads the raw body, not a form
    )
    with urllib.request.urlopen(request, timeout=10):  # noqa: S310
        pass


ACTION_LINE = r"- [a-z0-9-]+:[A-Za-z0-9*]+"


def scanner_statements(template: str) -> list[dict[str, Any]]:
    """The Allow and Deny statements of the scanner role's own policies (every `- Sid:` with an
    Action list in scanner-role.yaml). The worker image has no YAML parser, and the template's
    statements all share one plain shape; the counts are printed so a drift shows."""
    statements: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_actions = False
    for line in template.splitlines():
        text = line.strip()
        if text.startswith("- Sid:"):
            current = {"Effect": None, "Action": [], "Resource": "*"}
            statements.append(current)
            in_actions = False
        elif current is not None and text.startswith("Effect:"):
            current["Effect"] = text.split(":", 1)[1].strip()
        elif current is not None and text == "Action:":
            in_actions = True
        elif in_actions and current is not None and re.fullmatch(ACTION_LINE, text):
            current["Action"].append(text[2:])
        elif text and not text.startswith("#"):
            in_actions = False
    return [s for s in statements if s["Effect"] in ("Allow", "Deny") and s["Action"]]


def scanner_user(endpoint: str) -> tuple[str, str, dict[str, int]]:
    """A user with the scanner role's permissions: the two AWS-managed policies and the role's
    own statements. sts:GetCallerIdentity needs no permission on AWS; moto asks for one."""
    iam = client("iam", endpoint)
    iam.create_user(UserName="argus-scanner")
    for arn in (
        "arn:aws:iam::aws:policy/SecurityAudit",
        "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
    ):
        # moto's authorizer ignores AWS-managed policies attached to a user: the same document,
        # as a policy of the account's own.
        version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        document = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]
        copy = iam.create_policy(
            PolicyName="copy-" + arn.rsplit("/", 1)[1],
            PolicyDocument=json.dumps(document["Document"]),
        )["Policy"]["Arn"]
        iam.attach_user_policy(UserName="argus-scanner", PolicyArn=copy)
    statements = scanner_statements(SCANNER_ROLE.read_text())
    statements.append({"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"})
    for n, chunk in enumerate(range(0, len(statements), 4)):
        iam.put_user_policy(
            UserName="argus-scanner",
            PolicyName=f"scanner-{n}",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statements[chunk : chunk + 4]}
            ),
        )
    key = iam.create_access_key(UserName="argus-scanner")["AccessKey"]
    counts = {
        "allow_actions": sum(len(s["Action"]) for s in statements if s["Effect"] == "Allow"),
        "deny_actions": sum(len(s["Action"]) for s in statements if s["Effect"] == "Deny"),
    }
    return key["AccessKeyId"], key["SecretAccessKey"], counts


def client(service: str, endpoint: str) -> Any:
    return boto3.client(
        service,
        endpoint_url=endpoint,
        region_name=REGION,
        aws_access_key_id=FAKE_KEY,
        aws_secret_access_key=FAKE_KEY,
    )


def _trust(principal: dict[str, Any]) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
        }
    )


def _policy(actions: list[str]) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
        }
    )


def _seed_web(ec2: Any, vpc: str, subnet: str) -> tuple[dict[str, Any], str, dict[str, Any], str]:
    # argus_v12: a web server open on port 80 (IPv4 and IPv6), and a second instance whose
    # public address is an Elastic IP on its second network interface.
    web_sg = ec2.create_security_group(GroupName="emu-http", Description="http", VpcId=vpc)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(
        GroupId=web_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )
    web = ec2.run_instances(
        ImageId="ami-12c6146b",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        NetworkInterfaces=[
            {
                "DeviceIndex": 0,
                "SubnetId": subnet,
                "Groups": [web_sg],
                "AssociatePublicIpAddress": True,
            }
        ],
    )["Instances"][0]
    web_ip = ec2.describe_instances(InstanceIds=[web["InstanceId"]])["Reservations"][0][
        "Instances"
    ][0].get("PublicIpAddress", "")
    eni = ec2.create_network_interface(SubnetId=subnet, Groups=[web_sg])["NetworkInterface"][
        "NetworkInterfaceId"
    ]
    side = ec2.run_instances(
        ImageId="ami-12c6146b", MinCount=1, MaxCount=1, InstanceType="t3.micro", SubnetId=subnet
    )["Instances"][0]["InstanceId"]
    ec2.attach_network_interface(NetworkInterfaceId=eni, InstanceId=side, DeviceIndex=1)
    eip = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=eip["AllocationId"], NetworkInterfaceId=eni)
    acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
    ec2.create_network_acl_entry(
        NetworkAclId=acl,
        RuleNumber=100,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        CidrBlock="0.0.0.0/0",
        PortRange={"From": 80, "To": 443},
    )

    return web, web_ip, eip, web_sg


def _seed_names_and_clusters(
    endpoint: str,
    iam: Any,
    lb_dns: str,
    web_ip: str,
    subnets: tuple[str, str],
    groups: tuple[str, str],
) -> str:
    """Route 53 names in front of the estate, and an EKS and an ECS cluster."""
    subnet, subnet_b = subnets
    sg, web_sg = groups
    # A public zone: alias to the ALB, a CNAME to that record (a chain), an A record to the web
    # instance's IP, and a CNAME to an S3 website (a target that is not a front door).
    s3 = client("s3", endpoint)
    s3.create_bucket(Bucket="emu-site")
    s3.put_bucket_website(
        Bucket="emu-site", WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}}
    )
    r53 = client("route53", endpoint)
    zone = r53.create_hosted_zone(Name="emu.example.com", CallerReference="emu")["HostedZone"]["Id"]

    def record(name: str, type_: str, value: str) -> dict[str, Any]:
        return {
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": name,
                "Type": type_,
                "TTL": 60,
                "ResourceRecords": [{"Value": value}],
            },
        }

    r53.change_resource_record_sets(
        HostedZoneId=zone,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": "app.emu.example.com",
                        "Type": "A",
                        "AliasTarget": {
                            "HostedZoneId": "Z35SXDOTRQ7X7K",
                            "DNSName": lb_dns,
                            "EvaluateTargetHealth": False,
                        },
                    },
                },
                record("www.emu.example.com", "CNAME", "app.emu.example.com"),
                record("web.emu.example.com", "A", web_ip or "192.0.2.10"),
                record(
                    "static.emu.example.com", "CNAME", "emu-site.s3-website-us-east-1.amazonaws.com"
                ),
            ]
        },
    )
    eks_role = iam.create_role(
        RoleName="emu-eks", AssumeRolePolicyDocument=_trust({"Service": "eks.amazonaws.com"})
    )["Role"]["Arn"]
    client("eks", endpoint).create_cluster(
        name="emu-eks",
        roleArn=eks_role,
        resourcesVpcConfig={
            "subnetIds": [subnet, subnet_b],
            "securityGroupIds": [sg],
            "endpointPublicAccess": True,
        },
    )
    ecs = client("ecs", endpoint)
    ecs.create_cluster(clusterName="emu-ecs")
    ecs.register_task_definition(
        family="emu-task",
        networkMode="awsvpc",
        containerDefinitions=[{"name": "web", "image": "nginx", "memory": 128}],
    )
    ecs.create_service(
        cluster="emu-ecs",
        serviceName="emu-svc",
        taskDefinition="emu-task",
        desiredCount=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet],
                "securityGroups": [web_sg],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    rds = client("rds", endpoint)
    rds.create_db_subnet_group(
        DBSubnetGroupName="emu-db", DBSubnetGroupDescription="db", SubnetIds=[subnet, subnet_b]
    )
    rds.create_db_instance(
        DBInstanceIdentifier="emu-db",
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="emu",
        MasterUserPassword="fake-password-for-the-emulator",
        AllocatedStorage=20,
        DBSubnetGroupName="emu-db",
        VpcSecurityGroupIds=[sg],
        PubliclyAccessible=True,
    )
    return zone


def _seed_messaging_and_apis(endpoint: str, lambda_role: str) -> None:
    """argus_v13: what CloudFox's sqs, sns, ecr, api-gateway and step-functions modules list."""
    sqs = client("sqs", endpoint)
    queue = sqs.create_queue(QueueName="emu-orders")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=queue,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                        }
                    ],
                }
            )
        },
    )
    sns = client("sns", endpoint)
    topic = sns.create_topic(Name="emu-alerts")["TopicArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)
    client("ecr", endpoint).create_repository(repositoryName="emu/web")
    api = client("apigateway", endpoint)
    rest = api.create_rest_api(name="emu-partner-rest")["id"]
    root = api.get_resources(restApiId=rest)["items"][0]["id"]
    orders = api.create_resource(restApiId=rest, parentId=root, pathPart="orders")["id"]
    api.put_method(restApiId=rest, resourceId=orders, httpMethod="GET", authorizationType="NONE")
    api.put_integration(
        restApiId=rest,
        resourceId=orders,
        httpMethod="GET",
        type="MOCK",
        integrationHttpMethod="GET",
    )
    api.create_deployment(restApiId=rest, stageName="prod")
    client("stepfunctions", endpoint).create_state_machine(
        name="emu-fulfil",
        definition=json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}}),
        roleArn=lambda_role,
    )


def seed(endpoint: str) -> dict[str, str]:
    """A small estate with something for every CloudFox module that writes loot: roles that
    are admin or can escalate, a cross-account trust without an external id, a public instance
    with an instance profile and user data, a function with an environment and a public URL, a
    bucket, a secret, an internet-facing load balancer, a public database, a queue open to anyone,
    a topic, an image repository, a REST API and a state machine."""
    iam, ec2 = client("iam", endpoint), client("ec2", endpoint)
    iam.create_role(
        RoleName="emu-admin", AssumeRolePolicyDocument=_trust({"Service": "ec2.amazonaws.com"})
    )
    iam.put_role_policy(RoleName="emu-admin", PolicyName="all", PolicyDocument=_policy(["*"]))
    iam.create_role(
        RoleName="emu-app", AssumeRolePolicyDocument=_trust({"Service": "ec2.amazonaws.com"})
    )
    iam.put_role_policy(
        RoleName="emu-app",
        PolicyName="escalate",
        PolicyDocument=_policy(["iam:PassRole", "ec2:RunInstances", "s3:GetObject"]),
    )
    iam.create_role(
        RoleName="emu-partner",
        AssumeRolePolicyDocument=_trust({"AWS": "arn:aws:iam::210987654321:root"}),
    )
    lambda_role = iam.create_role(
        RoleName="emu-lambda",
        AssumeRolePolicyDocument=_trust({"Service": "lambda.amazonaws.com"}),
    )["Role"]["Arn"]
    iam.create_instance_profile(InstanceProfileName="emu-app")
    iam.add_role_to_instance_profile(InstanceProfileName="emu-app", RoleName="emu-app")
    iam.create_user(UserName="emu-deployer")
    iam.create_access_key(UserName="emu-deployer")

    vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24", AvailabilityZone="us-east-1a")[
        "Subnet"
    ]["SubnetId"]
    subnet_b = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.20.2.0/24", AvailabilityZone="us-east-1b"
    )["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rtb = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)
    sg = ec2.create_security_group(GroupName="emu-web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ],
    )
    instance = ec2.run_instances(
        ImageId="ami-12c6146b",  # moto's default AMI
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        NetworkInterfaces=[
            {"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg], "AssociatePublicIpAddress": True}
        ],
        IamInstanceProfile={"Name": "emu-app"},
        UserData="#!/bin/bash\nexport EMU_TOKEN=fake-token-for-the-emulator\n",
    )["Instances"][0]["InstanceId"]
    web, web_ip, eip, web_sg = _seed_web(ec2, vpc, subnet)

    code = io.BytesIO()
    with zipfile.ZipFile(code, "w") as z:
        z.writestr("app.py", "def handler(event, context):\n    return 'ok'\n")
    lam = client("lambda", endpoint)
    lam.create_function(
        FunctionName="emu-api",
        Runtime="python3.12",
        Role=lambda_role,
        Handler="app.handler",
        Code={"ZipFile": code.getvalue()},
        Environment={"Variables": {"DB_PASSWORD": "fake-password-for-the-emulator"}},
    )
    lam.create_function_url_config(FunctionName="emu-api", AuthType="NONE")

    client("s3", endpoint).create_bucket(Bucket="emu-assets")
    client("secretsmanager", endpoint).create_secret(Name="emu/db", SecretString="fake-secret")
    elb = client("elbv2", endpoint)
    lb = elb.create_load_balancer(
        Name="emu-edge", Subnets=[subnet, subnet_b], SecurityGroups=[sg], Scheme="internet-facing"
    )["LoadBalancers"][0]["LoadBalancerArn"]
    tg = elb.create_target_group(Name="emu-tg", Protocol="HTTP", Port=80, VpcId=vpc)[
        "TargetGroups"
    ][0]["TargetGroupArn"]
    elb.create_listener(
        LoadBalancerArn=lb,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}],
    )
    elb.register_targets(TargetGroupArn=tg, Targets=[{"Id": instance, "Port": 80}])
    lb_dns = elb.describe_load_balancers(LoadBalancerArns=[lb])["LoadBalancers"][0]["DNSName"]
    zone = _seed_names_and_clusters(endpoint, iam, lb_dns, web_ip, (subnet, subnet_b), (sg, web_sg))
    _seed_messaging_and_apis(endpoint, lambda_role)
    return {
        "vpc": vpc,
        "subnet": subnet,
        "instance_profile": "emu-app",
        "lb": lb,
        "web_instance": web["InstanceId"],
        "web_ip": web_ip,
        "eip": eip["PublicIp"],
        "zone": zone,
    }


def tool_env(home: Path, endpoint: str, key: tuple[str, str], ca: Path) -> dict[str, str]:
    """As the worker's tool_profile(): one private profile, an environment built from nothing,
    plus the emulator's endpoint for every service and the run's CA (for the outside files). The
    key is the one moto issued to the scanner user."""
    (home / "credentials").write_text(
        f"[{PROFILE}]\naws_access_key_id = {key[0]}\naws_secret_access_key = {key[1]}\n"
    )
    (home / "config").write_text(f"[profile {PROFILE}]\nregion = {REGION}\n")
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "AWS_PROFILE": PROFILE,
        "AWS_SHARED_CREDENTIALS_FILE": str(home / "credentials"),
        "AWS_CONFIG_FILE": str(home / "config"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ENDPOINT_URL": endpoint,
        "STEAMPIPE_INSTALL_DIR": str(home / "steampipe"),
        "SSL_CERT_FILE": str(ca),
    }


def run(cmd: list[str], env: dict[str, str], log: Path) -> int:
    with log.open("ab") as out:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, env=env, cwd=env["HOME"], stdout=out, stderr=out, timeout=TOOL_TIMEOUT, check=False
        ).returncode


def run_cloudfox(out: Path, env: dict[str, str]) -> int:
    target = out / "cloudfox"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    rc = run(
        [
            CLOUDFOX,
            "aws",
            "all-checks",
            "--profile",
            PROFILE,
            "--outdir",
            str(target),
            "--verbosity",
            "1",
            "--yes",
        ],
        env,
        out / "cloudfox.log",
    )
    # CloudFox writes module errors here whatever $TMPDIR says (collection/aws/tools.py).
    errors = Path("/tmp/.cloudfox/cloudfox-error.log")  # noqa: S108 - CloudFox's own path
    if errors.exists():
        shutil.copy(errors, out / "cloudfox-error.log")
    return rc


def run_steampipe(
    out: Path,
    env: dict[str, str],
    endpoint: str,
    tables: tuple[str, ...],
    options: Callable[[str], tuple[str, ...]] = table_options,
) -> dict[str, dict[str, Any]]:
    """Every table of the inventory, with production's options and production's failure test.
    One line per table: ok, empty, partial (a denied call, rows kept), failed (denied: the
    scanner role's policies; emulator: moto lacks the API; error: anything else)."""
    target = out / "steampipe"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    config = Path(env["HOME"]) / "steampipe-config"
    config.mkdir()
    (config / "aws.spc").write_text(
        f'connection "aws" {{\n  plugin = "aws"\n  profile = "{PROFILE}"\n'
        f'  regions = ["{REGION}"]\n  endpoint_url = "{endpoint}"\n'
        # moto serves buckets by path only: <bucket>.moto does not resolve on this network.
        "  s3_force_path_style = true\n"
        # One attempt: moto's errors are not transient, and nine retries per call made the
        # run take hours.
        "  max_error_retry_attempts = 1\n}\n"
    )

    def export(table: str) -> tuple[str, dict[str, Any]]:
        rows_path, err_path = target / f"{table}.jsonl", target / f"{table}.err"
        with rows_path.open("wb") as rows, err_path.open("wb") as err:
            try:
                rc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    [
                        STEAMPIPE,
                        table,
                        "--connection",
                        "aws",
                        "--config-dir",
                        str(config),
                        "--output",
                        "jsonl",
                        *options(table),
                    ],
                    env=env,
                    cwd=env["HOME"],
                    stdout=rows,
                    stderr=err,
                    timeout=TABLE_TIMEOUT,
                    check=False,
                ).returncode
            except subprocess.TimeoutExpired:
                rc = -9
        errors = err_path.read_text(errors="replace")
        rows_n = sum(1 for line in rows_path.read_text().splitlines() if line.startswith("{"))
        denied = sorted(denied_actions(errors))
        if table_failed(rc, errors, rows_path):
            first = next(
                (line for line in errors.splitlines() if "[ERROR]" in line or "error" in line),
                errors.strip().splitlines()[-1] if errors.strip() else f"exit {rc}",
            )
            # A response the SDK cannot read is moto's (with auth on, its signature check fails
            # every JSON-protocol service: Lambda, DynamoDB, EKS, API Gateway, ...); a denial
            # AWS-style is a readable AccessDenied or UnauthorizedOperation.
            # Not applicable or refused (ADR-0012, second amendment) as production classes it:
            # Organizations not in use is one moto answers like AWS.
            outcome = None if denied else table_outcome(errors)
            why = (
                "emulator"
                if EMULATOR_GAP.search(errors)
                else "denied"
                if denied
                else outcome or "error"
            )
            result = {"status": "failed", "why": why, "error": first[-300:], "denied": denied}
        elif denied:
            result = {"status": "partial", "rows": rows_n, "denied": denied}
        else:
            result = {"status": "ok" if rows_n else "empty", "rows": rows_n}
        if not errors.strip():
            err_path.unlink()
        return table, result

    with ThreadPoolExecutor(max_workers=PARALLEL_TABLES) as pool:
        return dict(pool.map(export, tables))


def loot_report(out: Path) -> dict[str, Any]:
    """Every loot file CloudFox wrote: its path under the output, line count and first lines."""
    files = sorted(p for p in (out / "cloudfox").rglob("*") if p.is_file() and "loot" in p.parts)
    return {
        str(p.relative_to(out / "cloudfox")): {
            "lines": sum(1 for _ in p.open(errors="replace")),
            "head": p.read_text(errors="replace").splitlines()[:8],
        }
        for p in files
    }


def scenario_options(table: str) -> tuple[str, ...]:
    """Production's options, but instance profiles without their tags: moto answers
    ListInstanceProfileTags with XML the SDK cannot decode (2026-10-21), and no rule reads them."""
    if table == "aws_iam_instance_profile":
        return (
            "--select",
            "arn,instance_profile_id,instance_profile_name,create_date,path,roles,title,akas,"
            "partition,region,account_id",
        )
    return table_options(table)


def run_prowler_checks(out: Path, env: dict[str, str]) -> tuple[int, dict[str, dict[str, Any]]]:
    """Prowler's own verdict on each instance (the spike): {instance id: {check: [status,
    severity]}}. Its log stays beside the output when it fails."""
    target = out / "prowler"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    rc = run(
        [
            PROWLER,
            "aws",
            "--profile",
            PROFILE,
            "--region",
            REGION,
            "--checks",
            *PROWLER_EXPOSURE_CHECKS,
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            str(target),
            "--no-banner",
            "--log-level",
            "ERROR",
            "--ignore-exit-code-3",
        ],
        env,
        out / "prowler.log",
    )
    verdicts: dict[str, dict[str, Any]] = {}
    for path in target.glob("*.ocsf.json"):
        for finding in json.loads(path.read_text() or "[]"):
            check = finding["metadata"]["event_code"]
            for resource in finding.get("resources", []):
                instance = str(resource.get("uid", "")).rsplit("/", 1)[-1]
                verdicts.setdefault(instance, {})[check] = [
                    finding["status_code"],
                    finding["severity"],
                ]
    return rc, verdicts


def _fixture_row(
    value: Any, keys: scrub_fixtures.Mapping, keep: frozenset[str] = frozenset()
) -> Any:
    """A raw row with every secret value destroyed and nothing else changed: the scrubber's
    secret pass (scrub_fixtures.Scrubber.scrub_json) without its pseudonyms, which an estate
    that is fake by construction does not need and the test's case names would not survive.
    Access key ids get the scrubber's numbered stand-ins (`keys`), one per key."""
    if isinstance(value, dict):
        return {
            k: redaction.redact_value(v)
            if redaction.is_secret_key(k) and k not in keep
            else _fixture_row(v, keys)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_fixture_row(v, keys) for v in value]
    if isinstance(value, str):
        text = redaction.mask_url_credentials(value)
        text = scrub_fixtures.KEY_ID_RE.sub(lambda m: keys.key_id(m.group(0)), text)
        for pattern in scrub_fixtures.SECRET_PATTERNS:
            text = pattern.sub(redaction.REDACTED, text)
        return text
    return value


def write_fixture(
    source: Path, dest: Path, tables: dict[str, dict[str, Any]], keys: scrub_fixtures.Mapping
) -> list[str]:
    """Each exported table with rows, redacted, as dest/<table>.jsonl. The scrubber's own leak
    check runs on every file; any hit deletes the fixture and is returned."""
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    problems: list[str] = []
    for table, result in sorted(tables.items()):
        if result["status"] not in ("ok", "partial"):
            continue
        keep = redaction.NOT_SECRET_COLUMNS.get(table, frozenset())
        rows = [
            json.dumps(_fixture_row(json.loads(line), keys, keep), sort_keys=True)
            for line in (source / f"{table}.jsonl").read_text().splitlines()
            if line.startswith("{")
        ]
        path = dest / f"{table}.jsonl"
        text = "\n".join(rows) + "\n"
        problems += scrub_fixtures.leaks(path, text, keys)
        path.write_text(text)
    if problems:
        shutil.rmtree(dest)
    return problems


def write_prowler_fixture(source: Path, dest: Path, keys: scrub_fixtures.Mapping) -> list[str]:
    """Prowler's failing findings only (its passes are 90% of the file and no adapter test
    needs them), redacted and checked like the Steampipe fixture."""
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    problems: list[str] = []
    for path in sorted(source.glob("*.ocsf.json")):
        findings = [f for f in json.loads(path.read_text() or "[]") if f["status_code"] == "FAIL"]
        text = json.dumps(_fixture_row(findings, keys), indent=1, sort_keys=True) + "\n"
        target = dest / path.name
        problems += scrub_fixtures.leaks(target, text, keys)
        target.write_text(text)
    if problems:
        shutil.rmtree(dest)
    return problems


def scenario(args: argparse.Namespace) -> int:
    """The exposure scenario estate alone: seed, CloudFox (its facts for the attack-path waves),
    Steampipe on the fixture tables, Prowler when asked, then the fixture."""
    enforce_auth(args.endpoint, on=False)
    ids = exposure_estate.seed(lambda service: client(service, args.endpoint))
    key_id, secret, _ = scanner_user(args.endpoint)
    out = args.out / "scenario"
    out.mkdir(exist_ok=True)
    served: list[str] = []
    with tempfile.TemporaryDirectory(prefix="argus-emulate-") as home:
        ca = serve_outside_files(Path(home), served)
        env = tool_env(Path(home), args.endpoint, (key_id, secret), ca)
        cloudfox_rc = None if args.skip_cloudfox else run_cloudfox(out, env)
        tables = run_steampipe(
            out, env, args.endpoint, exposure_estate.FIXTURE_TABLES, options=scenario_options
        )
        prowler_rc, prowler = run_prowler_checks(out, env) if args.prowler else (None, {})
    keys = scrub_fixtures.Mapping()  # the access key ids replaced, checked as originals
    problems = write_fixture(out / "steampipe", out / "fixture" / "steampipe", tables, keys)
    if args.prowler:
        problems += write_prowler_fixture(out / "prowler", out / "fixture" / "prowler", keys)
    report = {
        "instances": ids,
        "cloudfox_exit": cloudfox_rc,
        "steampipe_tables": tables,
        "prowler_exit": prowler_rc,
        # Prowler's verdicts by case name, for comparison with Argus's door per case.
        "prowler": {name: prowler.get(instance, {}) for name, instance in sorted(ids.items())},
        "fixture_problems": problems,
    }
    (out / "scenario.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "steampipe_tables"}, indent=2))
    print(
        "tables: "
        + ", ".join(f"{t}={r['status']}:{r.get('rows', r.get('why'))}" for t, r in tables.items())
    )
    share(args.out)
    return 1 if problems else 0


def share(out: Path) -> None:
    """The service runs as the image's user, not the host's: leave the output readable and
    removable from the host. Fake data only (see the module docstring)."""
    for path in out.rglob("*"):  # what this run wrote; `out` itself is the host's
        if not path.is_symlink():
            path.chmod(0o777 if path.is_dir() else 0o666)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--endpoint", default="http://moto:5000")
    parser.add_argument("--out", type=Path, default=Path("/out"))
    parser.add_argument("--table", action="append", default=[], help="only this table (repeatable)")
    parser.add_argument("--skip-steampipe", action="store_true", help="CloudFox only (its loot)")
    parser.add_argument(
        "--no-options",
        action="store_true",
        help="export without production's options: every column (shows what they prevent)",
    )
    parser.add_argument(
        "--scenario",
        choices=["exposure"],
        help="seed only this scenario estate and write its fixture (exposure_estate.py)",
    )
    parser.add_argument("--skip-cloudfox", action="store_true", help="with --scenario")
    parser.add_argument(
        "--prowler", action="store_true", help="with --scenario: Prowler's exposure checks too"
    )
    args = parser.parse_args(argv)
    if not os.access(args.out, os.W_OK):
        print(f"{args.out} is not writable: run `mkdir -p -m 0777 emulated` in the repository")
        return 2
    wait_for(args.endpoint)
    reset(args.endpoint)
    if args.scenario:
        return scenario(args)
    enforce_auth(args.endpoint, on=False)
    seeded = seed(args.endpoint)
    key_id, secret, policy_counts = scanner_user(args.endpoint)
    served: list[str] = []
    tables: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="argus-emulate-") as home:
        ca = serve_outside_files(Path(home), served)
        env = tool_env(Path(home), args.endpoint, (key_id, secret), ca)
        cloudfox_rc = run_cloudfox(args.out, env)
        if not args.skip_steampipe:
            enforce_auth(args.endpoint, on=True)
            try:
                tables = run_steampipe(
                    args.out,
                    env,
                    args.endpoint,
                    tuple(args.table) or steampipe_tables(),
                    options=(lambda _: ()) if args.no_options else table_options,
                )
            finally:
                enforce_auth(args.endpoint, on=False)
    by_status: dict[str, list[str]] = {}
    for table, result in tables.items():
        key = result["status"] + (f":{result['why']}" if "why" in result else "")
        by_status.setdefault(key, []).append(table)
    report = {
        "seeded": seeded,
        "scanner_policy": policy_counts,
        "cloudfox_exit": cloudfox_rc,
        "outside_files_served": sorted(set(served)),
        "steampipe_summary": {k: len(v) for k, v in sorted(by_status.items())},
        "steampipe_failed": {
            t: r for t, r in sorted(tables.items()) if r["status"] in ("failed", "partial")
        },
        "steampipe_tables": tables,
        "loot": loot_report(args.out),
    }
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "seeded",
                    "scanner_policy",
                    "cloudfox_exit",
                    "outside_files_served",
                    "steampipe_summary",
                    "steampipe_failed",
                )
            },
            indent=2,
        )
    )
    print(f"loot files: {len(report['loot'])}; details in {args.out / 'report.json'}")
    share(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
