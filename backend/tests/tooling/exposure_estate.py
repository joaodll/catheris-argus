"""The exposure scenario estate (2026-10-21): one case per way Prowler's exposure checks and
Argus's internet rules can disagree, and per entry or move an attack path should take.

Seeded into moto by `emulate.py --scenario exposure`; its Steampipe export, with every secret
value redacted, is the fixture behind tests/ingest/test_exposure_scenarios.py. Each instance is
tagged Name=exp-<case>, so the fixture reads by case and the test asserts by name.

Network (us-east-1a unless noted):
    exp-vpc 10.30.0.0/16, internet gateway; its main route table routes to it too, as a
        default VPC's does (Prowler 5.44.0 reads any VPC's main table: the exp-vpc-b case)
      exp-public    10.30.1.0/24  default route -> internet gateway
      exp-acl       10.30.2.0/24  same route; a network ACL denying tcp/22 first
      exp-private   10.30.3.0/24  no default route
      exp-inspected 10.30.4.0/24  default route -> a Gateway Load Balancer endpoint (vpce-)
    exp-vpc-b 10.40.0.0/16, no internet gateway; exp-b-subnet has no route table of its own

Cases (instances unless named otherwise):
    exp-open            public IP, tcp/22 open, routed, default ACL: reachable
    exp-no-public-ip    tcp/22 open, no public address
    exp-stopped         tcp/22 open, an Elastic IP, stopped (moto drops the address on a stop,
                        which AWS keeps: the verdict is not_running either way)
    exp-terminated      tcp/22 open, terminated: no door
    exp-ipv6-rule       tcp/22 open to ::/0 only, IPv4-only instance
    exp-vpc-b           tcp/22 open, public IP, subnet with no route table of its own
    exp-acl-deny        tcp/22 open, the subnet's ACL denies it
    exp-icmp-only       only ICMP open to the internet
    exp-two-enis        open group on a private interface, closed group on a public one
    exp-inspected       tcp/22 open, default route to a vpce-
    exp-s3-reader       exposed, its role holds AmazonS3ReadOnlyAccess (AWS-managed)
    exp-rdp-target      private, tcp/3389 from the VPC: a lateral neighbour of the doors
    exp-ssm-target      private: exp-open's role can ssm:SendCommand on it
    exp-public-bucket   bucket public by its own policy
    exp-public-queue    queue public by its own policy -> exp-consumer (Lambda) whose role
                        reads the secret exp/api-key
    exp-outsider        role trusting another account's root, no external id
    exp-github          role trusting GitHub's OIDC provider with no `sub` condition
    exp-old-key         user with an active access key, in exp-admins (AdministratorAccess)
    exp-console         user with a console password and no MFA, s3:* on *
    exp-escalator       user allowed iam:CreatePolicyVersion on *

Values are fake by construction (moto ids, account 123456789012); the fake secrets are there so
the fixture proves redaction, and the emulator redacts them before writing the fixture.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Callable
from typing import Any

Client = Callable[[str], Any]
AMI = "ami-12c6146b"  # moto's default AMI
AZ = "us-east-1a"
OUTSIDE_ACCOUNT = "999988887777"
GITHUB_OIDC = "token.actions.githubusercontent.com"

# The tables the relationship rules, the internet rules and the attack-path rules read, plus the
# IAM and endpoint tables the later attack-path waves need. Only these go into the fixture.
FIXTURE_TABLES = (
    "aws_ec2_instance",
    "aws_ec2_network_interface",
    "aws_iam_access_key",
    "aws_iam_group",
    "aws_iam_instance_profile",
    "aws_iam_open_id_connect_provider",
    "aws_iam_policy",
    "aws_iam_role",
    "aws_iam_user",
    "aws_lambda_event_source_mapping",
    "aws_lambda_function",
    # Not aws_s3_account_settings: moto does not serve the account's Block Public Access
    # (s3control, 2026-10-22), so the public bucket's verdict is Unknown here.
    "aws_s3_bucket",
    "aws_secretsmanager_secret",
    "aws_sqs_queue",
    "aws_ssm_managed_instance",
    "aws_vpc",
    "aws_vpc_eip",
    "aws_vpc_endpoint",
    "aws_vpc_network_acl",
    "aws_vpc_route_table",
    "aws_vpc_security_group",
    "aws_vpc_security_group_rule",
    "aws_vpc_subnet",
)


def _tags(kind: str, name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}]}]


def _trust(principal: dict[str, Any], action: str = "sts:AssumeRole", **extra: Any) -> str:
    statement = {"Effect": "Allow", "Principal": principal, "Action": action, **extra}
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


def _allow(actions: list[str], resource: str = "*") -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
        }
    )


def _public(action: str, resource: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": action, "Resource": resource}
            ],
        }
    )


class _Network:
    """The two VPCs, their subnets and the groups the cases share."""

    def __init__(self, ec2: Any) -> None:
        self.ec2 = ec2
        self.vpc = ec2.create_vpc(
            CidrBlock="10.30.0.0/16", TagSpecifications=_tags("vpc", "exp-vpc")
        )["Vpc"]["VpcId"]
        igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=self.vpc)
        main = ec2.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [self.vpc]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"][0]["RouteTableId"]
        ec2.create_route(RouteTableId=main, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
        public_rt = self._route_table("exp-public-rt")
        ec2.create_route(RouteTableId=public_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
        self.public = self._subnet("10.30.1.0/24", "exp-public", public_rt)
        self.acl_subnet = self._subnet("10.30.2.0/24", "exp-acl", public_rt)
        self.private = self._subnet("10.30.3.0/24", "exp-private", self._route_table("exp-priv-rt"))
        self.inspected = self._subnet("10.30.4.0/24", "exp-inspected", self._inspection_route())
        self._deny_ssh_acl()
        self.vpc_b = ec2.create_vpc(
            CidrBlock="10.40.0.0/16", TagSpecifications=_tags("vpc", "exp-vpc-b")
        )["Vpc"]["VpcId"]
        self.b_subnet = self._subnet("10.40.1.0/24", "exp-b-subnet", None, self.vpc_b)
        self.ssh = self.group("exp-ssh", [self.rule("tcp", 22)])
        self.closed = self.group("exp-closed", [])

    def _route_table(self, name: str, vpc: str | None = None) -> str:
        return str(
            self.ec2.create_route_table(
                VpcId=vpc or self.vpc, TagSpecifications=_tags("route-table", name)
            )["RouteTable"]["RouteTableId"]
        )

    def _subnet(self, cidr: str, name: str, route_table: str | None, vpc: str | None = None) -> str:
        subnet = self.ec2.create_subnet(
            VpcId=vpc or self.vpc,
            CidrBlock=cidr,
            AvailabilityZone=AZ,
            TagSpecifications=_tags("subnet", name),
        )["Subnet"]["SubnetId"]
        if route_table:
            self.ec2.associate_route_table(RouteTableId=route_table, SubnetId=subnet)
        return str(subnet)

    def _inspection_route(self) -> str:
        """A default route to a Gateway Load Balancer endpoint (a firewall's), which AWS
        reports as GatewayId vpce-…; Argus cannot tell what the firewall lets through."""
        endpoint = self.ec2.create_vpc_endpoint(
            VpcEndpointType="GatewayLoadBalancer",
            VpcId=self.vpc,
            ServiceName="com.amazonaws.vpce.us-east-1.vpce-svc-0a1b2c3d4e5f60718",
        )["VpcEndpoint"]["VpcEndpointId"]
        table = self._route_table("exp-inspected-rt")
        self.ec2.create_route(
            RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", VpcEndpointId=endpoint
        )
        return table

    def _deny_ssh_acl(self) -> None:
        acl = self.ec2.create_network_acl(
            VpcId=self.vpc, TagSpecifications=_tags("network-acl", "exp-deny-ssh")
        )["NetworkAcl"]["NetworkAclId"]
        for number, egress, action, ports in (
            (90, False, "deny", {"From": 22, "To": 22}),
            (100, False, "allow", None),
            (100, True, "allow", None),
        ):
            self.ec2.create_network_acl_entry(
                NetworkAclId=acl,
                RuleNumber=number,
                Protocol="6" if ports else "-1",
                RuleAction=action,
                Egress=egress,
                CidrBlock="0.0.0.0/0",
                **({"PortRange": ports} if ports else {}),
            )
        current = self.ec2.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": [self.acl_subnet]}]
        )["NetworkAcls"][0]
        association = next(
            a["NetworkAclAssociationId"]
            for a in current["Associations"]
            if a["SubnetId"] == self.acl_subnet
        )
        self.ec2.replace_network_acl_association(AssociationId=association, NetworkAclId=acl)

    @staticmethod
    def rule(
        protocol: str, port: int, *, v4: str | None = "0.0.0.0/0", v6: str | None = None
    ) -> dict[str, Any]:
        rule: dict[str, Any] = {"IpProtocol": protocol, "FromPort": port, "ToPort": port}
        if v4:
            rule["IpRanges"] = [{"CidrIp": v4}]
        if v6:
            rule["Ipv6Ranges"] = [{"CidrIpv6": v6}]
        return rule

    def group(self, name: str, rules: list[dict[str, Any]], vpc: str | None = None) -> str:
        group = self.ec2.create_security_group(
            GroupName=name, Description=name, VpcId=vpc or self.vpc
        )["GroupId"]
        if rules:
            self.ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=rules)
        return str(group)

    def instance(
        self,
        name: str,
        subnet: str,
        groups: list[str],
        *,
        public: bool = True,
        profile: str | None = None,
    ) -> str:
        extra: dict[str, Any] = {"IamInstanceProfile": {"Name": profile}} if profile else {}
        return str(
            self.ec2.run_instances(
                ImageId=AMI,
                MinCount=1,
                MaxCount=1,
                InstanceType="t3.micro",
                NetworkInterfaces=[
                    {
                        "DeviceIndex": 0,
                        "SubnetId": subnet,
                        "Groups": groups,
                        "AssociatePublicIpAddress": public,
                    }
                ],
                MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"},
                TagSpecifications=_tags("instance", name),
                **extra,
            )["Instances"][0]["InstanceId"]
        )

    def elastic_ip(self, *, instance: str | None = None, interface: str | None = None) -> None:
        allocation = self.ec2.allocate_address(Domain="vpc")["AllocationId"]
        target = {"InstanceId": instance} if instance else {"NetworkInterfaceId": interface}
        self.ec2.associate_address(AllocationId=allocation, **target)


def _profile(iam: Any, name: str, *, inline: str | None = None, managed: str | None = None) -> str:
    """A role an EC2 instance runs as, with an instance profile of the same name."""
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_trust({"Service": "ec2.amazonaws.com"})
    )
    if inline:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-inline", PolicyDocument=inline)
    if managed:
        iam.attach_role_policy(RoleName=name, PolicyArn=managed)
    iam.create_instance_profile(InstanceProfileName=name)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _seed_instances(ec2: Any, iam: Any) -> dict[str, str]:
    net = _Network(ec2)
    operator = _profile(iam, "exp-operator", inline=_allow(["ssm:SendCommand", "ssm:StartSession"]))
    reader = _profile(
        iam, "exp-s3-reader", managed="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    )
    ids = {
        "exp-open": net.instance("exp-open", net.public, [net.ssh], profile=operator),
        "exp-no-public-ip": net.instance("exp-no-public-ip", net.public, [net.ssh], public=False),
        "exp-stopped": net.instance("exp-stopped", net.public, [net.ssh], public=False),
        "exp-terminated": net.instance("exp-terminated", net.public, [net.ssh]),
        "exp-ipv6-rule": net.instance(
            "exp-ipv6-rule",
            net.public,
            [net.group("exp-ssh-v6", [net.rule("tcp", 22, v4=None, v6="::/0")])],
        ),
        "exp-vpc-b": net.instance(
            "exp-vpc-b",
            net.b_subnet,
            [net.group("exp-b-ssh", [net.rule("tcp", 22)], vpc=net.vpc_b)],
        ),
        "exp-acl-deny": net.instance("exp-acl-deny", net.acl_subnet, [net.ssh]),
        "exp-icmp-only": net.instance(
            "exp-icmp-only",
            net.public,
            [net.group("exp-icmp", [net.rule("icmp", -1)])],
        ),
        "exp-two-enis": net.instance("exp-two-enis", net.private, [net.ssh], public=False),
        "exp-inspected": net.instance("exp-inspected", net.inspected, [net.ssh]),
        "exp-s3-reader": net.instance("exp-s3-reader", net.public, [net.ssh], profile=reader),
        "exp-rdp-target": net.instance(
            "exp-rdp-target",
            net.private,
            [net.group("exp-rdp-internal", [net.rule("tcp", 3389, v4="10.30.0.0/16")])],
            public=False,
        ),
        "exp-ssm-target": net.instance("exp-ssm-target", net.private, [net.closed], public=False),
    }
    # The stopped instance has an Elastic IP, which a stop keeps (it drops only an address
    # assigned at launch).
    net.elastic_ip(instance=ids["exp-stopped"])
    ec2.stop_instances(InstanceIds=[ids["exp-stopped"]])
    ec2.terminate_instances(InstanceIds=[ids["exp-terminated"]])
    # A public interface whose group opens nothing, beside the private one whose group opens
    # tcp/22: merged, they would look reachable (B3).
    eni = ec2.create_network_interface(
        SubnetId=net.public,
        Groups=[net.closed],
        TagSpecifications=_tags("network-interface", "exp-two-enis-public"),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ec2.attach_network_interface(
        NetworkInterfaceId=eni, InstanceId=ids["exp-two-enis"], DeviceIndex=1
    )
    net.elastic_ip(interface=eni)
    return ids


def _seed_public_by_policy(client: Client, iam: Any) -> None:
    s3 = client("s3")
    s3.create_bucket(Bucket="exp-public-bucket")
    s3.put_bucket_policy(
        Bucket="exp-public-bucket",
        Policy=_public("s3:GetObject", "arn:aws:s3:::exp-public-bucket/*"),
    )
    secret = client("secretsmanager").create_secret(
        Name="exp/api-key", SecretString="fake-api-key-for-the-emulator"
    )["ARN"]
    sqs = client("sqs")
    queue = sqs.create_queue(QueueName="exp-public-queue")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=queue, Attributes={"Policy": _public("sqs:SendMessage", queue_arn)}
    )
    role = iam.create_role(
        RoleName="exp-consumer",
        AssumeRolePolicyDocument=_trust({"Service": "lambda.amazonaws.com"}),
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName="exp-consumer",
        PolicyName="exp-consumer-inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": secret,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
                        "Resource": queue_arn,
                    },
                ],
            }
        ),
    )
    code = io.BytesIO()
    with zipfile.ZipFile(code, "w") as z:
        z.writestr("app.py", "def handler(event, context):\n    return 'ok'\n")
    lam = client("lambda")
    lam.create_function(
        FunctionName="exp-consumer",
        Runtime="python3.12",
        Role=role,
        Handler="app.handler",
        Code={"ZipFile": code.getvalue()},
        Environment={"Variables": {"API_KEY_SECRET": "exp/api-key"}},
    )
    lam.create_event_source_mapping(EventSourceArn=queue_arn, FunctionName="exp-consumer")


def _seed_identities(iam: Any) -> None:
    iam.create_role(
        RoleName="exp-outsider",
        AssumeRolePolicyDocument=_trust({"AWS": f"arn:aws:iam::{OUTSIDE_ACCOUNT}:root"}),
    )
    iam.attach_role_policy(
        RoleName="exp-outsider", PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    )
    provider = iam.create_open_id_connect_provider(
        Url=f"https://{GITHUB_OIDC}",
        ClientIDList=["sts.amazonaws.com"],
        ThumbprintList=["6938fd4d98bab03faadb97b34396831e3780aea1"],
    )["OpenIDConnectProviderArn"]
    iam.create_role(
        RoleName="exp-github",
        AssumeRolePolicyDocument=_trust(
            {"Federated": provider},
            "sts:AssumeRoleWithWebIdentity",
            Condition={"StringEquals": {f"{GITHUB_OIDC}:aud": "sts.amazonaws.com"}},
        ),
    )
    iam.put_role_policy(
        RoleName="exp-github", PolicyName="exp-github-inline", PolicyDocument=_allow(["s3:*"])
    )
    iam.create_group(GroupName="exp-admins")
    iam.attach_group_policy(
        GroupName="exp-admins", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    iam.create_user(UserName="exp-old-key")
    iam.add_user_to_group(GroupName="exp-admins", UserName="exp-old-key")
    iam.create_access_key(UserName="exp-old-key")
    iam.create_user(UserName="exp-console")
    iam.create_login_profile(UserName="exp-console", Password="Fake-password-for-the-emulator-1")
    iam.put_user_policy(
        UserName="exp-console", PolicyName="exp-console-inline", PolicyDocument=_allow(["s3:*"])
    )
    iam.create_user(UserName="exp-escalator")
    iam.put_user_policy(
        UserName="exp-escalator",
        PolicyName="exp-escalator-inline",
        PolicyDocument=_allow(["iam:CreatePolicyVersion"]),
    )


def seed(client: Client) -> dict[str, str]:
    """Seed every case; returns the instance id per case name (the other cases are named)."""
    iam = client("iam")
    ids = _seed_instances(client("ec2"), iam)
    _seed_public_by_policy(client, iam)
    _seed_identities(iam)
    return ids
