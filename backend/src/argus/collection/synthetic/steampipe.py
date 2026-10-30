"""Synthetic `steampipe_export_aws` output: one JSONL file per table, one object per row.

Column names and shapes follow steampipe-plugin-aws v1.34.0 (aws/table_<name>.go and
common_columns.go): every row carries partition, region and account_id; JSON columns are
nested objects; timestamps are RFC 3339 strings. Only a realistic subset of each table's
columns is emitted. Secret-bearing columns the real plugin returns (Lambda
environment_variables, EC2 user_data) are present on purpose, so redaction downstream is
exercised by the same shapes it will meet.
"""

import base64
import json
from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from argus.collection.synthetic.estate import EstateDay
from argus.collection.synthetic.frontdoor import ROW_TABLES
from argus.collection.synthetic.model import Resource, h, hexid

TOOL_VERSION = "1.34.0"


def _common(r: Resource, account_id: str) -> dict[str, Any]:
    return {"partition": "aws", "region": r.region, "account_id": account_id}


def _tags(r: Resource, estate: EstateDay) -> dict[str, str]:
    return {
        "Name": r.name,
        "Environment": estate.profile.label,
        "Owner": f"team-{hexid(4, r.uid, 'owner')}",
    }


def _tags_src(tags: dict[str, str]) -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def _created(r: Resource) -> str:
    return f"{r.attrs['created']}T00:00:00Z"


def _vpc(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    return {
        "vpc_id": r.native_id,
        "arn": r.arn,
        "cidr_block": r.attrs["cidr_block"],
        "state": "available",
        "is_default": r.attrs["is_default"],
        "instance_tenancy": "default",
        "owner_id": e.account_id,
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
    }


def _subnet(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    return {
        "subnet_id": r.native_id,
        "subnet_arn": r.arn,
        "vpc_id": r.attrs["vpc_id"],
        "cidr_block": r.attrs["cidr_block"],
        "state": "available",
        "owner_id": e.account_id,
        "availability_zone": r.attrs["availability_zone"],
        "map_public_ip_on_launch": r.attrs["public"],
        "default_for_az": False,
        "available_ip_address_count": 240,
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
    }


def _security_group(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    permissions = [
        {
            "IpProtocol": rule["protocol"],
            "FromPort": rule["from_port"],
            "ToPort": rule["to_port"],
            "IpRanges": [{"CidrIp": rule["cidr"]}] if rule.get("cidr") else [],
            "Ipv6Ranges": [{"CidrIpv6": rule["cidr_ipv6"]}] if rule.get("cidr_ipv6") else [],
            "UserIdGroupPairs": [],
            "PrefixListIds": [],
        }
        for rule in r.attrs["ingress"]
    ]
    return {
        "group_name": r.name,
        "group_id": r.native_id,
        "arn": r.arn,
        "description": f"{r.name} managed by terraform",
        "vpc_id": r.attrs["vpc_id"],
        "owner_id": e.account_id,
        "ip_permissions": permissions,
        "ip_permissions_egress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
    }


def _security_group_rules(e: EstateDay) -> list[dict[str, Any]]:
    rows = []
    for sg in e.resources.get("aws_vpc_security_group", []):
        for i, rule in enumerate(sg.attrs["ingress"]):
            rule_id = f"sgr-{hexid(17, sg.native_id, i)}"
            rows.append(
                {
                    **_common(sg, e.account_id),
                    "security_group_rule_id": rule_id,
                    "group_id": sg.native_id,
                    "is_egress": False,
                    "type": "ingress",
                    "group_owner_id": e.account_id,
                    "ip_protocol": rule["protocol"],
                    "from_port": rule["from_port"],
                    "to_port": rule["to_port"],
                    "cidr_ipv4": rule.get("cidr"),
                    "cidr_ipv6": rule.get("cidr_ipv6"),
                    "referenced_group_id": None,
                    "akas": [
                        f"arn:aws:ec2:{sg.region}:{e.account_id}:security-group-rule/{rule_id}"
                    ],
                    "title": rule_id,
                }
            )
    return rows


# Network ACL entries: everything in and out, for IPv4 and IPv6, then the default deny.
_ALLOW_ALL = [
    {"RuleNumber": n, "Egress": egress, "RuleAction": action, "Protocol": "-1", **cidr}
    for egress in (False, True)
    for n, action, cidr in (
        (100, "allow", {"CidrBlock": "0.0.0.0/0"}),
        (101, "allow", {"Ipv6CidrBlock": "::/0"}),
        (32767, "deny", {"CidrBlock": "0.0.0.0/0"}),
        (32768, "deny", {"Ipv6CidrBlock": "::/0"}),
    )
]
# A subnet's own ACL (attrs["acl"]): "deny-http" denies port 80 from anywhere before allowing
# the rest, so a web server open on 80 in its security group is still closed (ADR-0035).
_ACLS = {
    "deny-http": [
        {
            "RuleNumber": 90,
            "Egress": False,
            "RuleAction": "deny",
            "Protocol": "6",
            "PortRange": {"From": 80, "To": 80},
            "CidrBlock": "0.0.0.0/0",
        },
        *_ALLOW_ALL,
    ],
}


def _network_row(vpc: Resource, e: EstateDay, kind: str, rid: str) -> dict[str, Any]:
    return {
        **_common(vpc, e.account_id),
        "owner_id": e.account_id,
        "akas": [f"arn:aws:ec2:{vpc.region}:{e.account_id}:{kind}/{rid}"],
        "title": rid,
    }


def _vpc_network(e: EstateDay) -> dict[str, list[dict[str, Any]]]:
    """Each VPC's internet gateway, route tables and network ACLs: a main table with local
    routes only, a public table sending 0.0.0.0/0 and ::/0 to the gateway for the public subnets,
    and a default ACL that allows everything (a subnet with attrs["acl"] gets its own). A VPC
    with attrs["no_routes"] has no route table rows, as if the table were denied."""
    out: dict[str, list[dict[str, Any]]] = {
        "aws_vpc_internet_gateway": [],
        "aws_vpc_route_table": [],
        "aws_vpc_network_acl": [],
    }
    subnets = e.resources.get("aws_vpc_subnet", [])
    for vpc in e.resources.get("aws_vpc", []):
        mine = [s for s in subnets if s.attrs["vpc_id"] == vpc.native_id]
        igw = f"igw-{hexid(17, vpc.native_id, 'igw')}"
        out["aws_vpc_internet_gateway"].append(
            {
                **_network_row(vpc, e, "internet-gateway", igw),
                "internet_gateway_id": igw,
                "attachments": [{"State": "available", "VpcId": vpc.native_id}],
            }
        )
        if not vpc.attrs.get("no_routes"):
            local = {
                "DestinationCidrBlock": vpc.attrs["cidr_block"],
                "GatewayId": "local",
                "Origin": "CreateRouteTable",
                "State": "active",
            }
            main = f"rtb-{hexid(17, vpc.native_id, 'main')}"
            public = f"rtb-{hexid(17, vpc.native_id, 'public')}"
            to_igw = [
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": igw, "State": "active"},
                {"DestinationIpv6CidrBlock": "::/0", "GatewayId": igw, "State": "active"},
            ]
            for rid, routes, assoc in (
                (main, [local], [{"Main": True, "RouteTableId": main}]),
                (
                    public,
                    [local, *to_igw],
                    [
                        {"Main": False, "RouteTableId": public, "SubnetId": s.native_id}
                        for s in mine
                        if s.attrs["public"]
                    ],
                ),
            ):
                out["aws_vpc_route_table"].append(
                    {
                        **_network_row(vpc, e, "route-table", rid),
                        "vpc_id": vpc.native_id,
                        "route_table_id": rid,
                        "routes": routes,
                        "associations": [
                            {**a, "RouteTableAssociationId": f"rtbassoc-{hexid(17, rid, i)}"}
                            for i, a in enumerate(assoc)
                        ],
                    }
                )
        groups: dict[str, list[Resource]] = {}
        for s in mine:
            groups.setdefault(s.attrs.get("acl", "default"), []).append(s)
        for name, members in sorted(groups.items()):
            aid = f"acl-{hexid(17, vpc.native_id, name)}"
            out["aws_vpc_network_acl"].append(
                {
                    **_network_row(vpc, e, "network-acl", aid),
                    "arn": f"arn:aws:ec2:{vpc.region}:{e.account_id}:network-acl/{aid}",
                    "vpc_id": vpc.native_id,
                    "network_acl_id": aid,
                    "is_default": name == "default",
                    "entries": _ALLOW_ALL if name == "default" else _ACLS[name],
                    "associations": [
                        {
                            "NetworkAclAssociationId": f"aclassoc-{hexid(17, aid, s.native_id)}",
                            "NetworkAclId": aid,
                            "SubnetId": s.native_id,
                        }
                        for s in members
                    ],
                }
            )
    return out


def _instance(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    user_data = base64.b64encode(
        f"#!/bin/bash\nexport APP_TOKEN=tok-{hexid(16, r.uid, 'ud')}\n".encode()
    ).decode()
    return {
        "instance_id": r.native_id,
        "arn": r.arn,
        "instance_type": r.attrs["instance_type"],
        "instance_state": "running",
        "subnet_id": r.attrs["subnet_id"],
        "vpc_id": r.attrs["vpc_id"],
        "private_ip_address": r.attrs["private_ip"],
        "public_ip_address": r.attrs["public_ip"],
        "iam_instance_profile_arn": r.attrs["instance_profile_arn"],
        "security_groups": [{"GroupId": g, "GroupName": g} for g in r.attrs["security_groups"]],
        "metadata_options": {
            "HttpTokens": "required" if r.attrs["imdsv2"] else "optional",
            "HttpEndpoint": "enabled",
        },
        "monitoring_state": "disabled",
        "launch_time": _created(r),
        "image_id": f"ami-{hexid(17, r.region, 'ami')}",
        "architecture": "x86_64",
        "user_data": user_data,
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
    }


def _lambda(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    return {
        "name": r.name,
        "arn": r.arn,
        "runtime": r.attrs["runtime"],
        "handler": "app.handler",
        "role": r.attrs["role_arn"],
        "timeout": 30,
        "memory_size": 256,
        "package_type": "Zip",
        "version": "$LATEST",
        "environment_variables": r.attrs["environment"],
        "url_config": (
            {
                "AuthType": "NONE",
                "FunctionUrl": f"https://{hexid(26, r.uid)}.lambda-url.{r.region}.on.aws/",
            }
            if r.attrs["public_url"]
            else None
        ),
        "vpc_subnet_ids": r.attrs.get("vpc_subnet_ids"),
        "vpc_security_group_ids": r.attrs.get("vpc_security_group_ids"),
        "last_modified": _created(r),
        "tags": tags,
        "title": r.name,
    }


def _role(r: Resource, e: EstateDay) -> dict[str, Any]:
    trusted = r.attrs["trusted"]
    principal = {"AWS": trusted} if trusted.startswith("arn:") else {"Service": trusted}
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
    }
    attached = (
        ["arn:aws:iam::aws:policy/AdministratorAccess"]
        if r.attrs["admin"]
        else [f"arn:aws:iam::{e.account_id}:policy/{r.name}-policy"]
    )
    tags = _tags(r, e)
    return {
        "name": r.name,
        "arn": r.arn,
        "role_id": r.native_id,
        "path": "/",
        "assume_role_policy_document": json.dumps(document),
        "assume_role_policy_std": document,
        "attached_policy_arns": attached,
        "inline_policies_std": r.attrs.get("inline", []),
        "max_session_duration": 3600,
        "create_date": _created(r),
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
    }


# IAM groups every synthetic account has: admins (AWS-managed AdministratorAccess) and two
# teams with a customer-managed policy each. A user is in one group, by a fixed hash.
GROUPS = ("admins", "developers", "operators")
GROUPS_CREATED = "2025-01-15T00:00:00Z"


def _group_arn(account_id: str, group: str) -> str:
    return f"arn:aws:iam::{account_id}:group/{group}"


def _user_groups(r: Resource) -> list[str]:
    return ["admins"] if r.attrs["admin"] else [GROUPS[1 + h(r.uid, "group") % 2]]


def _group_policy(account_id: str, group: str) -> str:
    if group == "admins":
        return "arn:aws:iam::aws:policy/AdministratorAccess"
    return f"arn:aws:iam::{account_id}:policy/{group}-policy"


def _groups(e: EstateDay) -> list[dict[str, Any]]:
    users = e.resources.get("aws_iam_user", [])
    rows = []
    for group in GROUPS:
        arn = _group_arn(e.account_id, group)
        rows.append(
            {
                "partition": "aws",
                "region": "global",
                "account_id": e.account_id,
                "name": group,
                "group_id": f"AGPA{hexid(17, e.account_id, group).upper()}",
                "arn": arn,
                "path": "/",
                "create_date": GROUPS_CREATED,
                "attached_policy_arns": [_group_policy(e.account_id, group)],
                "inline_policies": [],
                "inline_policies_std": [],
                "users": [
                    {"Arn": u.arn, "UserName": u.name, "UserId": u.native_id}
                    for u in users
                    if group in _user_groups(u)
                ],
                "title": group,
                "akas": [arn],
            }
        )
    return rows


def _policies(e: EstateDay) -> list[dict[str, Any]]:
    """The customer-managed policies the users, roles and groups attach (the export runs with
    is_aws_managed = false, so AWS-managed ones are not rows)."""
    attached: dict[str, int] = {}
    principals = [
        *(_user(u, e) for u in e.resources.get("aws_iam_user", [])),
        *(_role(r, e) for r in e.resources.get("aws_iam_role", [])),
        *_groups(e),
    ]
    for principal in principals:
        for arn in principal["attached_policy_arns"]:
            if ":iam::aws:policy/" not in arn:
                attached[arn] = attached.get(arn, 0) + 1
    rows = []
    for arn in sorted(attached):
        name = arn.rsplit("/", 1)[1]
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket", "logs:PutLogEvents"],
                    "Resource": "*",
                }
            ],
        }
        rows.append(
            {
                "partition": "aws",
                "region": "global",
                "account_id": e.account_id,
                "name": name,
                "policy_id": f"ANPA{hexid(17, arn).upper()}",
                "arn": arn,
                "path": "/",
                "default_version_id": "v1",
                "is_aws_managed": False,
                "is_attachable": True,
                "is_attached": True,
                "attachment_count": attached[arn],
                "permissions_boundary_usage_count": 0,
                "create_date": GROUPS_CREATED,
                "update_date": GROUPS_CREATED,
                "policy": json.dumps(document),
                "policy_std": document,
                "title": name,
                "akas": [arn],
            }
        )
    return rows


def _born(r: Resource) -> date:
    return date.fromisoformat(r.attrs["created"])


def _user(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    created = _created(r)
    attached = (
        ["arn:aws:iam::aws:policy/AdministratorAccess"]
        if r.attrs["admin"]
        else [f"arn:aws:iam::{e.account_id}:policy/{r.name}-policy"]
    )
    console = r.attrs["console"]
    return {
        "name": r.name,
        "user_id": r.native_id,
        "path": "/",
        "arn": r.arn,
        "create_date": created,
        # A fixed day per user (never after the estate's day), so the configuration does not
        # change every day.
        "password_last_used": (
            f"{login}T09:00:00Z"
            if console and (login := _born(r) + timedelta(days=h(r.uid, "login") % 300)) <= e.day
            else None
        ),
        "permissions_boundary_arn": None,
        "permissions_boundary_type": None,
        "mfa_enabled": r.attrs["mfa"],
        "login_profile": (
            {"CreateDate": created, "PasswordResetRequired": False, "UserName": r.name}
            if console
            else None
        ),
        "mfa_devices": (
            [
                {
                    "EnableDate": created,
                    "SerialNumber": f"arn:aws:iam::{e.account_id}:mfa/{r.name}",
                    "UserName": r.name,
                }
            ]
            if r.attrs["mfa"]
            else []
        ),
        "groups": [
            {
                "Arn": _group_arn(e.account_id, group),
                "GroupName": group,
                "GroupId": f"AGPA{hexid(17, e.account_id, group).upper()}",
                "Path": "/",
                "CreateDate": GROUPS_CREATED,
            }
            for group in _user_groups(r)
        ],
        "inline_policies": [],
        "inline_policies_std": [],
        "attached_policy_arns": attached,
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
        "akas": [r.arn],
    }


def _access_keys(e: EstateDay) -> list[dict[str, Any]]:
    """Each user's access keys. The key id has the shape of a real one (AKIA + 16) and is
    generated, never committed. Last use is fixed per key, not per day."""
    rows = []
    for user in e.resources.get("aws_iam_user", []):
        born = _born(user)
        for key in user.attrs["keys"]:
            key_id = f"AKIA{hexid(16, user.uid, key['index']).upper()}"
            created = born + timedelta(days=key["index"] * 30)
            idle = key["idle_days"]
            last_used = (
                created + timedelta(days=key["age_days"] - idle) if idle is not None else None
            )
            used = last_used is not None and last_used <= e.day
            rows.append(
                {
                    **_common(user, e.account_id),
                    "access_key_id": key_id,
                    "user_name": user.name,
                    "status": "Active" if key["active"] else "Inactive",
                    "create_date": f"{created}T00:00:00Z",
                    "access_key_last_used_date": f"{last_used}T12:00:00Z" if used else None,
                    "access_key_last_used_service": "s3" if used else None,
                    "access_key_last_used_region": "us-east-1" if used else None,
                    "title": key_id,
                    "akas": [f"arn:aws:iam::{e.account_id}:user/{user.name}/accesskey/{key_id}"],
                }
            )
    return rows


def _instance_profile(r: Resource, e: EstateDay) -> dict[str, Any]:
    roles = (
        [{"Arn": r.attrs["role_arn"], "RoleName": r.attrs["role_arn"].rsplit("/", 1)[-1]}]
        if r.attrs["role_arn"]
        else []
    )
    return {
        "instance_profile_name": r.name,
        "arn": r.arn,
        "instance_profile_id": r.native_id,
        "path": "/",
        "roles": roles,
        "create_date": _created(r),
        "title": r.name,
    }


def _load_balancer(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    return {
        "name": r.name,
        "arn": r.arn,
        "scheme": r.attrs["scheme"],
        "type": "application" if "/app/" in r.arn else "network",
        "vpc_id": r.attrs["vpc_id"],
        "dns_name": r.attrs["dns_name"],
        "security_groups": r.attrs.get("security_groups", []),
        "availability_zones": [
            {"ZoneName": f"{r.region}{'abc'[i % 3]}", "SubnetId": subnet}
            for i, subnet in enumerate(r.attrs.get("subnet_ids", []))
        ],
        "state_code": "active",
        "ip_address_type": r.attrs.get("ip_address_type", "ipv4"),
        "created_time": _created(r),
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
    }


def _target_group(r: Resource, e: EstateDay) -> dict[str, Any]:
    return {
        "target_group_name": r.name,
        "target_group_arn": r.arn,
        "target_type": r.attrs.get("target_type", "instance"),
        "load_balancer_arns": [r.attrs["load_balancer_arn"]]
        if r.attrs["load_balancer_arn"]
        else [],
        "port": r.attrs["port"],
        "protocol": "HTTPS",
        "target_health_descriptions": [
            {"Target": {"Id": t, "Port": r.attrs["port"]}, "TargetHealth": {"State": "healthy"}}
            for t in r.attrs["targets"]
        ],
        "title": r.name,
    }


def _rds(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    return {
        "db_instance_identifier": r.name,
        "arn": r.arn,
        "engine": r.attrs["engine"],
        "engine_version": "16.4",
        "class": "db.t4g.medium",
        "status": "available",
        "publicly_accessible": r.attrs["public"],
        "storage_encrypted": r.attrs["encrypted"],
        "vpc_id": r.attrs["vpc_id"],
        "db_subnet_group_name": f"{r.name}-subnets",
        "subnets": [{"SubnetIdentifier": r.attrs["subnet_id"]}] if r.attrs["subnet_id"] else [],
        "vpc_security_groups": [
            {"VpcSecurityGroupId": g, "Status": "active"}
            for g in r.attrs.get("security_groups", [])
        ],
        "endpoint_address": f"{r.name}.{hexid(12, r.uid)}.{r.region}.rds.amazonaws.com",
        "endpoint_port": 5432,
        "backup_retention_period": 7,
        "create_time": _created(r),
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
    }


def _bucket(r: Resource, e: EstateDay) -> dict[str, Any]:
    tags = _tags(r, e)
    return {
        "name": r.name,
        "arn": r.arn,
        "creation_date": _created(r),
        "versioning_enabled": r.attrs["versioning"],
        "block_public_acls": True,
        "block_public_policy": True,
        "ignore_public_acls": True,
        "restrict_public_buckets": True,
        "bucket_policy_is_public": False,
        "event_notification_configuration": r.attrs.get("notifications"),
        "tags": tags,
        "tags_src": _tags_src(tags),
        "title": r.name,
        "region_override": r.attrs["bucket_region"],
    }


def _ssm_instance(r: Resource, e: EstateDay) -> dict[str, Any]:
    """An instance Systems Manager manages and reaches (ssm-command)."""
    return {
        "instance_id": r.native_id,
        "arn": r.arn,
        "ping_status": "Online",
        "resource_type": "EC2Instance",
        "platform_type": "Linux",
        "title": r.native_id,
    }


def _row(r: Resource, e: EstateDay) -> dict[str, Any]:
    """Front-door tables (frontdoor.py): the row is written where the resource is made."""
    return {**r.attrs["row"], "title": r.name}


BUILDERS: dict[str, Callable[[Resource, EstateDay], dict[str, Any]]] = {
    "aws_vpc": _vpc,
    "aws_vpc_subnet": _subnet,
    "aws_vpc_security_group": _security_group,
    "aws_ec2_instance": _instance,
    "aws_lambda_function": _lambda,
    "aws_iam_role": _role,
    "aws_iam_instance_profile": _instance_profile,
    "aws_iam_user": _user,
    "aws_ec2_application_load_balancer": _load_balancer,
    "aws_ec2_network_load_balancer": _load_balancer,
    "aws_ec2_target_group": _target_group,
    "aws_rds_db_instance": _rds,
    "aws_s3_bucket": _bucket,
    "aws_ssm_managed_instance": _ssm_instance,
    **dict.fromkeys(ROW_TABLES, _row),
}


# The tables this source writes; the rest of the list has no synthetic counterpart.
TABLES = frozenset(
    {
        *BUILDERS,
        "aws_vpc_security_group_rule",
        "aws_iam_access_key",
        "aws_iam_group",
        "aws_iam_policy",
        "aws_vpc_internet_gateway",
        "aws_vpc_route_table",
        "aws_vpc_network_acl",
    }
)
_NETWORK_TABLES = ("aws_vpc_internet_gateway", "aws_vpc_route_table", "aws_vpc_network_acl")


def rows_by_table(estate: EstateDay, tables: list[str]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    network = _vpc_network(estate) if set(_NETWORK_TABLES) & set(tables) else {}
    for table in tables:
        if table in network:
            out[table] = network[table]
            continue
        if table == "aws_vpc_security_group_rule":
            out[table] = _security_group_rules(estate)
            continue
        if table == "aws_iam_access_key":
            out[table] = _access_keys(estate)
            continue
        if table == "aws_iam_group":
            out[table] = _groups(estate)
            continue
        if table == "aws_iam_policy":
            out[table] = _policies(estate)
            continue
        builder = BUILDERS[table]
        rows = []
        for r in estate.resources.get(table, []):
            row = {**_common(r, estate.account_id), **builder(r, estate)}
            # S3 buckets are global in Steampipe but report the bucket's own region.
            if table == "aws_s3_bucket":
                row["region"] = row.pop("region_override")
            rows.append(row)
        out[table] = rows
    return out


def write(out_dir: Path, estate: EstateDay, tables: list[str], keep_tables: int | None) -> int:
    """Writes <table>.jsonl for each table, the first keep_tables only when a run is cut
    short. Returns the number of rows written."""
    written = 0
    for i, (table, rows) in enumerate(rows_by_table(estate, tables).items()):
        if keep_tables is not None and i >= keep_tables:
            break
        lines = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        (out_dir / f"{table}.jsonl").write_text(lines)
        written += len(rows)
    return written
