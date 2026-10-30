"""A deterministic synthetic AWS estate, defined for every date.

The estate is a pure function of (account id, seed, date): no state is stored, so a 180-day
backfill and a live daily run produce the same resources for the same day. Each resource type
has a number of *slots*; a slot hosts successive *generations* of a resource, each with a
lifetime and a gap before its replacement, all derived from a hash. Network and identity
slots are long-lived, compute churns.

Three profiles (prod, staging, shared) are chosen from the seed. The prod profile carries the
fixed scenarios the MVP gate checks: an internet-exposed instance whose role can escalate to
admin, and a bucket whose public-access finding is fixed and reopened on a 90-day cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from functools import cached_property
from typing import Any

from argus.collection.synthetic.frontdoor import ORDERS_API_ROLE, add_front_door
from argus.collection.synthetic.model import Resource, h, hexid, u

EPOCH = date(2020, 1, 1)
PERMANENT = 10**7  # days


@dataclass(frozen=True)
class Profile:
    label: str
    regions: tuple[str, ...]
    # Steampipe table -> slots per region (global tables: total slots).
    slots: dict[str, int]


PROFILES = (
    Profile(
        "prod",
        ("us-east-1", "eu-west-1"),
        {
            "aws_vpc": 2,
            "aws_vpc_subnet": 6,
            "aws_vpc_security_group": 8,
            "aws_ec2_instance": 24,
            "aws_lambda_function": 12,
            "aws_ec2_application_load_balancer": 2,
            "aws_ec2_network_load_balancer": 1,
            "aws_ec2_target_group": 3,
            "aws_rds_db_instance": 3,
            "aws_iam_role": 28,
            "aws_iam_instance_profile": 6,
            "aws_iam_user": 8,
            "aws_s3_bucket": 16,
        },
    ),
    Profile(
        "staging",
        ("us-east-1",),
        {
            "aws_vpc": 1,
            "aws_vpc_subnet": 4,
            "aws_vpc_security_group": 6,
            "aws_ec2_instance": 14,
            "aws_lambda_function": 8,
            "aws_ec2_application_load_balancer": 1,
            "aws_ec2_network_load_balancer": 0,
            "aws_ec2_target_group": 2,
            "aws_rds_db_instance": 2,
            "aws_iam_role": 18,
            "aws_iam_instance_profile": 4,
            "aws_iam_user": 5,
            "aws_s3_bucket": 10,
        },
    ),
    Profile(
        "shared",
        ("us-east-1",),
        {
            "aws_vpc": 1,
            "aws_vpc_subnet": 2,
            "aws_vpc_security_group": 4,
            "aws_ec2_instance": 6,
            "aws_lambda_function": 10,
            "aws_ec2_application_load_balancer": 0,
            "aws_ec2_network_load_balancer": 1,
            "aws_ec2_target_group": 1,
            "aws_rds_db_instance": 1,
            "aws_iam_role": 22,
            "aws_iam_instance_profile": 3,
            "aws_iam_user": 6,
            "aws_s3_bucket": 14,
        },
    ),
)

GLOBAL_TABLES = frozenset(
    {"aws_iam_role", "aws_iam_instance_profile", "aws_iam_user", "aws_s3_bucket"}
)
# Long-lived types: the estate's structure. Everything else churns.
STABLE_TABLES = frozenset(
    {"aws_vpc", "aws_vpc_subnet", "aws_vpc_security_group", "aws_iam_instance_profile"}
)

# The fixed attack-path scenario (prod only).
SCENARIO_INSTANCE = "web-public-01"
SCENARIO_SG = "web-public-sg"
SCENARIO_ROLE = "web-app-role"
SCENARIO_PROFILE = "web-app-profile"
SCENARIO_PEER = "app-internal-01"
SCENARIO_PEER_SG = "internal-ssh-sg"
# Exposure accuracy (ADR-0035, second amendment): public by their settings, but routing, a
# network ACL or missing data decide.
EXPOSURE_SG = "web-http-sg"
NO_ROUTE_INSTANCE = "legacy-public-ip"
ACL_INSTANCE = "dmz-web-01"
UNKNOWN_INSTANCE = "legacy-vpc-app"
# The fixed regression scenario (prod only): fixed at day 30 of a 90-day cycle, reopened at 70.
REGRESSION_BUCKET = "customer-exports"
REGRESSION_CHECK = "s3_bucket_level_public_access_block"
ADMIN_ROLES = ("OrganizationAccountAccessRole", "break-glass-admin")

# The organization's management account (fake, outside the demo range). As in a real
# organization, OrganizationAccountAccessRole trusts its root, with no ExternalId.
MANAGEMENT_ACCOUNT = "100000000001"


def regression_bucket(account_id: str) -> str:
    """The regression bucket's name in one account. S3 names are global and a bucket ARN
    carries no account, so every prod-profile estate needs its own name."""
    return f"{REGRESSION_BUCKET}-{hexid(6, account_id, 'regression')}"


def profile_for(seed: int) -> Profile:
    return PROFILES[seed % len(PROFILES)]


def day_number(day: date) -> int:
    return (day - EPOCH).days


@dataclass
class EstateDay:
    """Every resource that exists in one account on one day, with how they connect."""

    account_id: str
    seed: int
    day: date
    profile: Profile
    resources: dict[str, list[Resource]]

    def all(self) -> list[Resource]:
        return [r for rows in self.resources.values() for r in rows]

    def by_name(self, table: str, name: str) -> Resource | None:
        return next((r for r in self.resources.get(table, []) if r.name == name), None)

    @cached_property
    def roles_that_escalate(self) -> frozenset[str]:
        """Role names CloudFox would mark CanPrivEscToAdmin: the scenario role plus a few."""
        names = {r.name for r in self.resources.get("aws_iam_role", [])}
        chosen = {n for n in names if u(self.account_id, "privesc", n) < 0.08}
        if self.profile.label == "prod":
            chosen.add(SCENARIO_ROLE)
            # The front-door chain ends in an attack path (frontdoor.py).
            chosen.add(f"{self.profile.label}-{ORDERS_API_ROLE}")
        return frozenset(chosen & names)


@dataclass(frozen=True)
class _Slot:
    """Everything a builder needs about the slot it fills."""

    table: str
    region: str
    slot: int
    gen: int
    built: dict[str, list[Resource]]
    estate: Estate

    @property
    def key(self) -> tuple[object, ...]:
        return (self.estate.account_id, self.table, self.region, self.slot, self.gen)

    @property
    def label(self) -> str:
        return self.estate.profile.label

    def same_region(self, table: str) -> list[Resource]:
        return [r for r in self.built.get(table, []) if r.region == self.region]

    def roles_trusting(self, service: str) -> list[Resource]:
        return [r for r in self.built.get("aws_iam_role", []) if r.attrs["trusted"] == service]

    def pick(self, rows: list[Resource], *key: object) -> Resource | None:
        return rows[h(self.estate.account_id, *key) % len(rows)] if rows else None

    def make(
        self, native_id: str, name: str, arn: str, attrs: dict[str, Any], region: str | None = None
    ) -> Resource:
        return Resource(self.table, region or self.region, native_id, name, arn, attrs)


class Estate:
    def __init__(self, account_id: str, seed: int) -> None:
        self.account_id = account_id
        self.seed = seed
        self.profile = profile_for(seed)

    # ------------------------------------------------------------------ slots
    def _slot_alive(self, table: str, region: str, slot: int, dayno: int) -> tuple[int, int] | None:
        """(generation, day number it was created) alive in this slot on this day, or None
        during the gap between a deletion and its replacement."""
        fixed_start = h(self.account_id, table, region, slot, "born") % 500
        if table in STABLE_TABLES or slot == 0:
            return 0, fixed_start
        life = 25 + h(self.account_id, table, region, slot, "life") % 300
        if h(self.account_id, table, region, slot, "permanent") % 4 == 0:
            return 0, fixed_start
        phase = h(self.account_id, table, region, slot, "phase") % life
        position = dayno + phase
        gap = max(1, life // 12)
        if position % life < gap:
            return None  # deleted, replacement not created yet
        generation = position // life
        return generation, generation * life - phase + gap

    def at(self, day: date) -> EstateDay:
        dayno = day_number(day)
        resources: dict[str, list[Resource]] = {}
        regions = {
            t: (("global",) if t in GLOBAL_TABLES else self.profile.regions)
            for t in self.profile.slots
        }
        # Build in dependency order so later types can reference earlier ones.
        order = (
            "aws_vpc",
            "aws_vpc_subnet",
            "aws_vpc_security_group",
            "aws_iam_role",
            "aws_iam_instance_profile",
            "aws_iam_user",
            "aws_ec2_instance",
            "aws_lambda_function",
            "aws_ec2_application_load_balancer",
            "aws_ec2_network_load_balancer",
            "aws_ec2_target_group",
            "aws_rds_db_instance",
            "aws_s3_bucket",
        )
        for table in order:
            count = self.profile.slots.get(table, 0)
            rows: list[Resource] = []
            for region in regions.get(table, ()):
                for slot in range(count):
                    alive = self._slot_alive(table, region, slot, dayno)
                    if alive is None:
                        continue
                    generation, born = alive
                    resource = self._build(table, region, slot, generation, resources)
                    # Creation dates are fixed per generation, so an unchanged resource keeps
                    # an unchanged configuration from day to day.
                    resource.attrs["created"] = (EPOCH + timedelta(days=born)).isoformat()
                    rows.append(resource)
            resources[table] = rows
        estate = EstateDay(self.account_id, self.seed, day, self.profile, resources)
        if self.profile.label == "prod":
            self._add_scenario(estate)
        add_front_door(estate, created=(EPOCH + timedelta(days=100)).isoformat())
        return estate

    # ------------------------------------------------------------------ builders
    def _arn(self, service: str, region: str, resource: str) -> str:
        region_part = "" if region == "global" else region
        account = "" if service == "s3" else self.account_id
        return f"arn:aws:{service}:{region_part}:{account}:{resource}"

    def _build(
        self, table: str, region: str, slot: int, gen: int, built: dict[str, list[Resource]]
    ) -> Resource:
        builder = getattr(self, f"_build_{table.removeprefix('aws_')}", None)
        if builder is None:
            raise ValueError(f"no builder for {table}")
        resource: Resource = builder(_Slot(table, region, slot, gen, built, self))
        return resource

    def _build_vpc(self, s: _Slot) -> Resource:
        vid = f"vpc-{hexid(17, *s.key)}"
        return s.make(
            vid,
            f"{s.label}-vpc-{s.slot}",
            self._arn("ec2", s.region, f"vpc/{vid}"),
            {"cidr_block": f"10.{s.slot + 10}.0.0/16", "is_default": False},
        )

    def _build_vpc_subnet(self, s: _Slot) -> Resource:
        vpc = s.pick(s.same_region("aws_vpc"), "subnet-vpc", s.slot)
        sid = f"subnet-{hexid(17, *s.key)}"
        public = s.slot % 2 == 0
        return s.make(
            sid,
            f"{s.label}-{'public' if public else 'private'}-{s.slot}",
            self._arn("ec2", s.region, f"subnet/{sid}"),
            {
                "vpc_id": vpc.native_id if vpc else None,
                "public": public,
                "cidr_block": f"10.{s.slot + 10}.{s.slot}.0/24",
                "availability_zone": f"{s.region}{'abc'[s.slot % 3]}",
            },
        )

    def _build_vpc_security_group(self, s: _Slot) -> Resource:
        vpc = s.pick(s.same_region("aws_vpc"), "sg-vpc", s.slot)
        gid = f"sg-{hexid(17, *s.key)}"
        open_world = u(*s.key, "open") < 0.25
        port = (22, 3389, 443, 5432, 8080)[h(*s.key, "port") % 5]
        rule = {
            "cidr": "0.0.0.0/0" if open_world else "10.0.0.0/8",
            "from_port": port,
            "to_port": port,
            "protocol": "tcp",
        }
        return s.make(
            gid,
            f"{s.label}-sg-{s.slot}",
            self._arn("ec2", s.region, f"security-group/{gid}"),
            {"vpc_id": vpc.native_id if vpc else None, "ingress": [rule]},
        )

    def _build_iam_role(self, s: _Slot) -> Resource:
        name = (
            ADMIN_ROLES[s.slot]
            if s.slot < len(ADMIN_ROLES)
            else f"{('app', 'etl', 'ci', 'svc', 'ops')[s.slot % 5]}-role-{s.slot}-g{s.gen}"
        )
        service = ("ec2.amazonaws.com", "lambda.amazonaws.com")[s.slot % 2]
        trusted = (
            f"arn:aws:iam::{MANAGEMENT_ACCOUNT}:root"
            if name == ADMIN_ROLES[0]
            else f"arn:aws:iam::{self.account_id}:root"
            if name in ADMIN_ROLES
            else service
        )
        return s.make(
            f"AROA{hexid(17, *s.key).upper()}",
            name,
            self._arn("iam", "global", f"role/{name}"),
            {"trusted": trusted, "admin": name in ADMIN_ROLES},
            region="global",
        )

    def _build_iam_instance_profile(self, s: _Slot) -> Resource:
        role = s.pick(s.roles_trusting("ec2.amazonaws.com"), "ip-role", s.slot)
        name = f"{s.label}-profile-{s.slot}"
        return s.make(
            f"AIPA{hexid(17, *s.key).upper()}",
            name,
            self._arn("iam", "global", f"instance-profile/{name}"),
            {"role_arn": role.arn if role else None},
            region="global",
        )

    def _build_iam_user(self, s: _Slot) -> Resource:
        """People and the odd service user. Slot 0 is a long-standing administrator; a user
        has up to two access keys (Steampipe's aws_iam_access_key rows are built from them)."""
        name = (
            "legacy-admin"
            if s.slot == 0
            else f"{('dev', 'ci', 'ops', 'svc')[s.slot % 4]}-user-{s.slot}-g{s.gen}"
        )
        console = s.slot == 0 or u(*s.key, "console") < 0.5
        keys = [
            {
                "index": i,
                "active": u(*s.key, "key-active", i) < 0.8,
                "age_days": 30 + h(*s.key, "key-age", i) % 400,
                # Days since the key was last used; None: never used.
                "idle_days": None
                if u(*s.key, "key-used", i) < 0.25
                else h(*s.key, "key-idle", i) % 200,
            }
            for i in range(h(*s.key, "keys") % 3)
        ]
        return s.make(
            f"AIDA{hexid(17, *s.key).upper()}",
            name,
            self._arn("iam", "global", f"user/{name}"),
            {
                "admin": s.slot == 0,
                "console": console,
                "mfa": console and u(*s.key, "mfa") < 0.7,
                "keys": keys,
            },
            region="global",
        )

    def _build_ec2_instance(self, s: _Slot) -> Resource:
        key = s.key
        subnet = s.pick(s.same_region("aws_vpc_subnet"), "inst-subnet", s.slot, s.gen)
        groups = s.same_region("aws_vpc_security_group")
        in_vpc = [g for g in groups if subnet and g.attrs["vpc_id"] == subnet.attrs["vpc_id"]]
        sg = s.pick(in_vpc or groups, "inst-sg", s.slot, s.gen)
        profile = s.pick(s.built.get("aws_iam_instance_profile", []), "inst-ip", s.slot)
        iid = f"i-{hexid(17, *key)}"
        public = bool(subnet and subnet.attrs["public"]) and u(*key, "pub") < 0.5
        public_ip = (
            (f"54.{h(*key, 'a') % 200 + 20}.{h(*key, 'b') % 250}.{h(*key, 'c') % 250 + 1}")
            if public
            else None
        )
        return s.make(
            iid,
            f"{s.label}-{('web', 'api', 'worker', 'batch')[s.slot % 4]}-{s.slot}",
            self._arn("ec2", s.region, f"instance/{iid}"),
            {
                "subnet_id": subnet.native_id if subnet else None,
                "vpc_id": subnet.attrs["vpc_id"] if subnet else None,
                "security_groups": [sg.native_id] if sg else [],
                "instance_profile_arn": profile.arn if profile else None,
                "public_ip": public_ip,
                "private_ip": f"10.{s.slot + 10}.{h(*key, 'd') % 250}.{h(*key, 'e') % 250 + 2}",
                "instance_type": ("t3.medium", "m6i.large", "c6i.xlarge")[s.slot % 3],
                "imdsv2": u(*key, "imds") < 0.7,
            },
        )

    def _build_lambda_function(self, s: _Slot) -> Resource:
        role = s.pick(s.roles_trusting("lambda.amazonaws.com"), "fn-role", s.slot)
        name = f"{s.label}-{('ingest', 'notify', 'resize', 'sync')[s.slot % 4]}-{s.slot}-g{s.gen}"
        env = {"LOG_LEVEL": "info", "STAGE": s.label}
        if u(*s.key, "secret") < 0.3:
            env["DB_PASSWORD"] = f"pw-{hexid(12, *s.key, 'pw')}"
        return s.make(
            name,
            name,
            self._arn("lambda", s.region, f"function:{name}"),
            {
                "role_arn": role.arn if role else None,
                "environment": env,
                "runtime": ("python3.12", "nodejs20.x")[s.slot % 2],
                "public_url": u(*s.key, "url") < 0.15,
            },
        )

    def _load_balancer(self, s: _Slot, kind: str) -> Resource:
        name = f"{s.label}-{kind}-lb-{s.slot}"
        subnet = s.pick(s.same_region("aws_vpc_subnet"), "lb-subnet", s.slot)
        vpc_id = subnet.attrs["vpc_id"] if subnet else None
        subnets = [
            x.native_id for x in s.same_region("aws_vpc_subnet") if x.attrs["vpc_id"] == vpc_id
        ]
        sg = s.pick(
            [g for g in s.same_region("aws_vpc_security_group") if g.attrs["vpc_id"] == vpc_id],
            "lb-sg",
            s.slot,
        )
        return s.make(
            name,
            name,
            self._arn(
                "elasticloadbalancing", s.region, f"loadbalancer/{kind}/{name}/{hexid(16, *s.key)}"
            ),
            {
                "scheme": "internet-facing" if s.slot == 0 else "internal",
                "vpc_id": vpc_id,
                "subnet_ids": subnets[:2],
                "security_groups": [sg.native_id] if sg else [],
                "dns_name": f"{name}-{h(*s.key) % 10**9}.{s.region}.elb.amazonaws.com",
            },
        )

    def _build_ec2_application_load_balancer(self, s: _Slot) -> Resource:
        return self._load_balancer(s, "app")

    def _build_ec2_network_load_balancer(self, s: _Slot) -> Resource:
        return self._load_balancer(s, "net")

    def _build_ec2_target_group(self, s: _Slot) -> Resource:
        lbs = s.same_region("aws_ec2_application_load_balancer") + s.same_region(
            "aws_ec2_network_load_balancer"
        )
        lb = s.pick(lbs, "tg-lb", s.slot)
        targets = [
            i.native_id
            for i in s.same_region("aws_ec2_instance")
            if u(self.account_id, "tg", s.slot, i.native_id) < 0.2
        ][:4]
        name = f"{s.label}-tg-{s.slot}"
        return s.make(
            name,
            name,
            self._arn("elasticloadbalancing", s.region, f"targetgroup/{name}/{hexid(16, *s.key)}"),
            {"load_balancer_arn": lb.arn if lb else None, "targets": targets, "port": 443},
        )

    def _build_rds_db_instance(self, s: _Slot) -> Resource:
        subnet = s.pick(s.same_region("aws_vpc_subnet"), "db-subnet", s.slot)
        groups = [
            g
            for g in s.same_region("aws_vpc_security_group")
            if subnet and g.attrs["vpc_id"] == subnet.attrs["vpc_id"]
        ]
        sg = s.pick(groups, "db-sg", s.slot)
        name = f"{s.label}-db-{s.slot}"
        return s.make(
            name,
            name,
            self._arn("rds", s.region, f"db:{name}"),
            {
                "engine": "postgres",
                "public": u(*s.key, "dbpub") < 0.15,
                "encrypted": u(*s.key, "enc") < 0.8,
                "subnet_id": subnet.native_id if subnet else None,
                "vpc_id": subnet.attrs["vpc_id"] if subnet else None,
                "security_groups": [sg.native_id] if sg else [],
            },
        )

    def _build_s3_bucket(self, s: _Slot) -> Resource:
        name = (
            f"{s.label}-{('logs', 'assets', 'backups', 'data', 'exports')[s.slot % 5]}"
            f"-{hexid(6, *s.key)}"
        )
        return s.make(
            name,
            name,
            self._arn("s3", "global", name),
            {"bucket_region": self.profile.regions[0], "versioning": u(*s.key, "ver") < 0.6},
            region="global",
        )

    def _add_scenario(self, estate: EstateDay) -> None:
        """Fixed resources for the attack paths and the regression (prod profile)."""
        region = self.profile.regions[0]
        res = estate.resources
        public_subnet = next(
            s for s in res["aws_vpc_subnet"] if s.region == region and s.attrs["public"]
        )
        vpc_id = public_subnet.attrs["vpc_id"]
        sg = Resource(
            "aws_vpc_security_group",
            region,
            f"sg-{hexid(17, 'scenario-sg')}",
            SCENARIO_SG,
            self._arn("ec2", region, f"security-group/sg-{hexid(17, 'scenario-sg')}"),
            {
                "vpc_id": vpc_id,
                "ingress": [
                    {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"}
                ],
            },
        )
        role = Resource(
            "aws_iam_role",
            "global",
            f"AROA{hexid(17, 'scenario-role').upper()}",
            SCENARIO_ROLE,
            self._arn("iam", "global", f"role/{SCENARIO_ROLE}"),
            {
                "trusted": "ec2.amazonaws.com",
                "admin": False,
                # What CloudFox's escalation flag rests on, by permission name (privilege-
                # escalation), and Systems Manager commands to the private peer (ssm-command;
                # ADR-0037 second amendment, wave 3).
                "inline": [
                    {
                        "PolicyName": "deploy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["iam:passrole", "ec2:runinstances"],
                                    "Resource": ["*"],
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["ssm:sendcommand"],
                                    "Resource": ["*"],
                                },
                            ],
                        },
                    }
                ],
            },
        )
        profile = Resource(
            "aws_iam_instance_profile",
            "global",
            f"AIPA{hexid(17, 'scenario-profile').upper()}",
            SCENARIO_PROFILE,
            self._arn("iam", "global", f"instance-profile/{SCENARIO_PROFILE}"),
            {"role_arn": role.arn},
        )
        iid = f"i-{hexid(17, 'scenario-instance')}"
        instance = Resource(
            "aws_ec2_instance",
            region,
            iid,
            SCENARIO_INSTANCE,
            self._arn("ec2", region, f"instance/{iid}"),
            {
                "subnet_id": public_subnet.native_id,
                "vpc_id": vpc_id,
                "security_groups": [sg.native_id],
                "instance_profile_arn": profile.arn,
                "public_ip": "54.210.17.44",
                "private_ip": "10.10.0.17",
                "instance_type": "t3.large",
                "imdsv2": False,
            },
        )
        bucket = Resource(
            "aws_s3_bucket",
            "global",
            regression_bucket(self.account_id),
            regression_bucket(self.account_id),
            self._arn("s3", "global", regression_bucket(self.account_id)),
            {"bucket_region": region, "versioning": False},
        )
        # Lateral movement: a private peer in the same VPC accepts SSH from private addresses,
        # so a key taken from the exposed instance opens it too.
        private_subnet = next(
            (
                s
                for s in res["aws_vpc_subnet"]
                if s.region == region and not s.attrs["public"] and s.attrs["vpc_id"] == vpc_id
            ),
            public_subnet,
        )
        peer_sg_id = f"sg-{hexid(17, 'scenario-peer-sg')}"
        peer_sg = Resource(
            "aws_vpc_security_group",
            region,
            peer_sg_id,
            SCENARIO_PEER_SG,
            self._arn("ec2", region, f"security-group/{peer_sg_id}"),
            {
                "vpc_id": vpc_id,
                "ingress": [
                    {"cidr": "10.0.0.0/8", "from_port": 22, "to_port": 22, "protocol": "tcp"}
                ],
            },
        )
        peer_id = f"i-{hexid(17, 'scenario-peer')}"
        peer = Resource(
            "aws_ec2_instance",
            region,
            peer_id,
            SCENARIO_PEER,
            self._arn("ec2", region, f"instance/{peer_id}"),
            {
                "subnet_id": private_subnet.native_id,
                "vpc_id": vpc_id,
                "security_groups": [peer_sg.native_id],
                "instance_profile_arn": None,
                "public_ip": None,
                "private_ip": "10.10.1.21",
                "instance_type": "m6i.large",
                "imdsv2": True,
            },
        )
        # Systems Manager manages the peer and reaches it (aws_ssm_managed_instance).
        managed = Resource(
            "aws_ssm_managed_instance",
            region,
            peer_id,
            SCENARIO_PEER,
            self._arn("ssm", region, f"managed-instance/{peer_id}"),
            {},
        )
        exposure = self._exposure_cases(region, vpc_id, private_subnet, profile.arn)
        for fixed in (sg, role, profile, instance, bucket, peer_sg, peer, managed, *exposure):
            fixed.attrs["created"] = (EPOCH + timedelta(days=100)).isoformat()
        for fixed in exposure:
            res.setdefault(fixed.table, []).append(fixed)
        res["aws_vpc_security_group"].append(peer_sg)
        res["aws_ec2_instance"].append(peer)
        res.setdefault("aws_ssm_managed_instance", []).append(managed)
        res["aws_vpc_security_group"].append(sg)
        res["aws_iam_role"].append(role)
        res["aws_iam_instance_profile"].append(profile)
        res["aws_ec2_instance"].append(instance)
        res["aws_s3_bucket"].append(bucket)

    def _exposure_cases(
        self, region: str, vpc_id: str, private_subnet: Resource, admin_profile: str
    ) -> list[Resource]:
        """Three instances open to anywhere on port 80 or 443 that the internet still does not
        reach for sure: one with a public address in a private subnet (no route to an internet
        gateway), one in a DMZ subnet whose network ACL denies port 80, one in a VPC whose route
        tables were never collected (unknown). The unknown one runs as the escalating scenario
        role, so its attack path to administrator is Unknown (ADR-0037)."""

        def ec2(table: str, key: str, kind: str, name: str, attrs: dict[str, Any]) -> Resource:
            prefix = {"aws_vpc": "vpc", "aws_vpc_subnet": "subnet", "aws_vpc_security_group": "sg"}
            rid = f"{prefix.get(table, 'i')}-{hexid(17, 'exposure', key)}"
            arn = self._arn("ec2", region, f"{kind}/{rid}")
            return Resource(table, region, rid, name, arn, attrs)

        def group(key: str, name: str, vpc: str, port: int) -> Resource:
            rule = {"cidr": "0.0.0.0/0", "from_port": port, "to_port": port, "protocol": "tcp"}
            attrs = {"vpc_id": vpc, "ingress": [rule]}
            return ec2("aws_vpc_security_group", key, "security-group", name, attrs)

        def server(
            key: str, name: str, subnet: Resource, sg: Resource, ip: str, profile: str | None = None
        ) -> Resource:
            return ec2(
                "aws_ec2_instance",
                key,
                "instance",
                name,
                {
                    "subnet_id": subnet.native_id,
                    "vpc_id": subnet.attrs["vpc_id"],
                    "security_groups": [sg.native_id],
                    "instance_profile_arn": profile,
                    "public_ip": ip,
                    "private_ip": "10.10.9.10",
                    "instance_type": "t3.small",
                    "imdsv2": True,
                },
            )

        web_sg = group("web-sg", EXPOSURE_SG, vpc_id, 80)
        dmz = ec2(
            "aws_vpc_subnet",
            "dmz",
            "subnet",
            f"{self.profile.label}-dmz",
            {
                "vpc_id": vpc_id,
                "public": True,
                "cidr_block": "10.10.200.0/24",
                "availability_zone": f"{region}a",
                "acl": "deny-http",
            },
        )
        legacy_vpc = ec2(
            "aws_vpc",
            "legacy-vpc",
            "vpc",
            f"{self.profile.label}-legacy-vpc",
            {"cidr_block": "10.99.0.0/16", "is_default": False, "no_routes": True},
        )
        legacy_subnet = ec2(
            "aws_vpc_subnet",
            "legacy-subnet",
            "subnet",
            f"{self.profile.label}-legacy-public",
            {
                "vpc_id": legacy_vpc.native_id,
                "public": True,
                "cidr_block": "10.99.0.0/24",
                "availability_zone": f"{region}b",
            },
        )
        legacy_sg = group(
            "legacy-sg", f"{self.profile.label}-legacy-https-sg", legacy_vpc.native_id, 443
        )
        return [
            web_sg,
            dmz,
            legacy_vpc,
            legacy_subnet,
            legacy_sg,
            server("no-route", NO_ROUTE_INSTANCE, private_subnet, web_sg, "54.210.17.60"),
            server("acl", ACL_INSTANCE, dmz, web_sg, "54.210.17.61"),
            server(
                "unknown", UNKNOWN_INSTANCE, legacy_subnet, legacy_sg, "54.210.17.62", admin_profile
            ),
        ]

    # ------------------------------------------------------------------ posture
    @staticmethod
    def posture(day: date) -> float:
        """Share of the base failure rate still failing: improves over each year, then resets
        (a remediation programme that keeps finding new work)."""
        return 1.0 - 0.45 * ((day_number(day) % 365) / 365)

    def regression_failing(self, day: date) -> bool:
        phase = day_number(day) % 90
        return not 30 <= phase < 70
