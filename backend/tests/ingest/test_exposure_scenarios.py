"""The exposure scenario estate through the real ingest (plan 2026-10-21, round 0).

tests/tooling/exposure_estate.py seeds one instance per case into moto; `emulate.py --scenario
exposure --prowler` exported it with the pinned Steampipe and ran Prowler 5.44.0's own exposure
checks on it, both written with every secret value redacted to tests/fixtures/emulated/exposure.
Each case's door (the internet rules' edge and its reason) is asserted, with the evidence the
front doors list explains it from, and Prowler's verdict beside it: where they disagree, the
table below is the reason why, case by case. exp-stopped, exp-icmp-only and exp-two-enis were
Argus's own defects before ADR-0035's fifth amendment (no door, Reachable, Reachable).
"""

import json
import re
import shutil
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR

from argus.attackpaths import evaluate_paths
from argus.core.manifest import Manifest, Tool
from argus.core.rawstore import FilesystemRawStore, describe_files
from argus.findings import PROWLER_EXPOSURE_CHECKS
from argus.ingest import ingest_run, register_run

pytestmark = pytest.mark.db
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "emulated" / "exposure"
ACCOUNT = "123456789012"  # moto's
DAY = date(2026, 10, 21)
VERSIONS: dict[Tool, str] = {"steampipe": "1.34.0", "prowler": "5.45.0"}

# Each case's door: (edge from the internet, reason). None: no door.
DOORS: dict[str, tuple[str, str | None] | None] = {
    "exp-open": ("ROUTES_TO", None),
    "exp-s3-reader": ("ROUTES_TO", None),
    "exp-no-public-ip": ("PUBLIC_RESTRICTED", "no_public_address"),
    "exp-ipv6-rule": ("PUBLIC_RESTRICTED", "sg_no_public_source"),
    "exp-vpc-b": ("PUBLIC_RESTRICTED", "no_internet_route"),
    "exp-acl-deny": ("PUBLIC_RESTRICTED", "nacl_blocks"),
    "exp-inspected": ("PUBLIC_UNVERIFIED", None),
    "exp-terminated": None,
    "exp-rdp-target": None,
    "exp-ssm-target": None,
    "exp-stopped": ("PUBLIC_RESTRICTED", "not_running"),
    "exp-icmp-only": ("PUBLIC_RESTRICTED", "sg_no_public_source"),
    # The open group is on the private interface; the public one opens nothing.
    "exp-two-enis": ("PUBLIC_RESTRICTED", "no_public_address"),
}

# Prowler 5.44.0 on the same estate: its failing exposure checks and their severity. Where it
# disagrees with DOORS, the review's finding A says why: it never reads network ACLs
# (exp-acl-deny), counts ::/0 on an IPv4-only instance (exp-ipv6-rule), judges a subnet without
# its own route table by any VPC's main table (exp-vpc-b), ignores the instance's state
# (exp-stopped, exp-terminated) and its interfaces (exp-two-enis), and treats a default route
# to a firewall endpoint as a private subnet (exp-inspected).
PROWLER: dict[str, dict[str, str]] = {
    "exp-open": {
        "internet_facing_with_instance_profile": "high",
        "port_ssh": "critical",
        "public_ip": "medium",
    },
    "exp-s3-reader": {
        "internet_facing_with_instance_profile": "high",
        "port_ssh": "critical",
        "public_ip": "medium",
    },
    "exp-no-public-ip": {"port_ssh": "medium"},
    "exp-ipv6-rule": {"port_ssh": "critical", "public_ip": "medium"},
    "exp-vpc-b": {"port_ssh": "critical", "public_ip": "medium"},
    "exp-acl-deny": {"port_ssh": "critical", "public_ip": "medium"},
    "exp-inspected": {"port_ssh": "high", "public_ip": "medium"},
    "exp-terminated": {"port_ssh": "medium"},
    "exp-rdp-target": {},
    "exp-ssm-target": {},
    "exp-stopped": {"port_ssh": "medium"},
    "exp-icmp-only": {"public_ip": "medium"},
    "exp-two-enis": {"port_ssh": "medium"},
}

# What every Prowler exposure finding of a case carries (ADR-0035, sixth amendment): Argus's
# reach and why. Restricted is each disagreement; exp-terminated has no door at all (no_door).
REACH: dict[str, tuple[str, str | None]] = {
    "exp-open": ("confirmed", None),
    "exp-s3-reader": ("confirmed", None),
    "exp-no-public-ip": ("restricted", "no_public_address"),
    "exp-ipv6-rule": ("restricted", "sg_no_public_source"),
    "exp-vpc-b": ("restricted", "no_internet_route"),
    "exp-acl-deny": ("restricted", "nacl_blocks"),
    "exp-inspected": ("unknown", "inspection_route"),
    "exp-terminated": ("restricted", "no_door"),
    "exp-stopped": ("restricted", "not_running"),
    "exp-icmp-only": ("restricted", "sg_no_public_source"),
    "exp-two-enis": ("restricted", "no_public_address"),
}


def _names() -> dict[str, str]:
    """Instance ARN -> its case name (the Name tag), from the fixture itself."""
    names = {}
    for line in (FIXTURE / "steampipe" / "aws_ec2_instance.jsonl").read_text().splitlines():
        row = json.loads(line)
        tags = row["tags"] if isinstance(row["tags"], dict) else json.loads(row["tags"])
        names[row["arn"]] = tags["Name"]
    return names


def _ingest(owner: Engine, worker: Engine, store: FilesystemRawStore, tool: Tool, cid: int) -> None:
    run_uid = uuid4()
    path = store.path_for(tool, ACCOUNT, DAY, run_uid)
    staging = store.staging_dir(path)
    for file in (FIXTURE / tool).iterdir():
        shutil.copy(file, staging / file.name)
    now = datetime.now(UTC)
    manifest = store.commit(
        path,
        Manifest(
            run_uid=run_uid,
            tool=tool,
            tool_version=VERSIONS[tool],
            account_id=ACCOUNT,
            source="aws",
            snapshot_date=DAY,
            region_scope=["us-east-1"],
            started_at=now,
            finished_at=now,
            status="complete",
            exit_code=0,
            throttle_events=0,
            files=describe_files(staging),
        ),
    )
    with worker.begin() as conn:
        scan_run_id = register_run(conn, connection_id=cid, raw_path=path, manifest=manifest)
    outcome = ingest_run(worker, store=store, scan_run_id=scan_run_id, rules_dir=RULES_DIR)
    assert outcome.status == "complete", outcome.error


def _connection(owner: Engine) -> int:
    with owner.begin() as conn:
        cid: int = conn.execute(
            text(
                "INSERT INTO connection (name, kind, account_id, auth_method, created_by, "
                "updated_by) VALUES ('exposure', 'demo', :a, 'none', 't', 't') RETURNING id"
            ),
            {"a": ACCOUNT},
        ).scalar_one()
    return cid


@pytest.fixture
def estate(owner: Engine, worker: Engine, store: FilesystemRawStore) -> int:
    cid = _connection(owner)
    for tool in ("steampipe", "prowler"):
        _ingest(owner, worker, store, tool, cid)
    return cid


def _edges(owner: Engine, cid: int) -> dict[str, tuple[str, dict[str, Any]]]:
    """Each case's edge from the internet: its type and attributes."""
    names = _names()
    with owner.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT e.target_uid, e.type, e.attributes
                FROM edge e JOIN edge_snapshot s ON s.edge_id = e.id AND s.snapshot_date = :d
                WHERE e.connection_id = :c AND e.source_uid = 'internet'
                  AND e.type IN ('ROUTES_TO', 'PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED')
                  AND starts_with(e.origin, 'rule:')
            """),
            {"d": DAY, "c": cid},
        ).all()
    return {names[r.target_uid]: (r.type, r.attributes) for r in rows if r.target_uid in names}


def test_each_case_has_its_door(owner: Engine, estate: int) -> None:
    doors = {name: (kind, a.get("reason")) for name, (kind, a) in _edges(owner, estate).items()}
    assert {case: doors.get(case) for case in DOORS} == DOORS


def _facts(attributes: dict[str, Any]) -> list[tuple[Any, ...]]:
    """A door's evidence, per interface: (public families, open per family, and per subnet
    its family, route and ACL), interface and subnet ids left out (moto makes them up)."""
    route = re.compile(r"^(vpce|nat|tgw)-.*")
    return [
        (
            tuple(n["public"]),
            tuple(n["open"]["ipv4"]),
            tuple(n["open"]["ipv6"]),
            tuple((s["family"], route.sub(r"\1-", s["route"]), s["acl"]) for s in n["subnets"]),
        )
        for n in attributes["network"]
    ]


def test_each_door_carries_the_evidence_it_is_explained_from(owner: Engine, estate: int) -> None:
    """What the front doors list writes out (ADR-0035, fifth amendment): the state, what each
    interface's groups open in each family, and each subnet's route and ACL."""
    edges = _edges(owner, estate)
    facts = {case: _facts(attributes) for case, (_, attributes) in edges.items()}
    assert facts["exp-open"] == [(("ipv4",), ("tcp/22",), (), (("ipv4", "igw", "allows"),))]
    # Open to ::/0 only, on an instance with no IPv6 address: Prowler calls it critical.
    assert facts["exp-ipv6-rule"] == [(("ipv4",), (), ("tcp/22",), (("ipv4", "igw", None),))]
    assert facts["exp-acl-deny"] == [(("ipv4",), ("tcp/22",), (), (("ipv4", "igw", "blocks"),))]
    assert facts["exp-vpc-b"] == [(("ipv4",), ("tcp/22",), (), (("ipv4", "none", "allows"),))]
    assert facts["exp-inspected"] == [(("ipv4",), ("tcp/22",), (), (("ipv4", "vpce-", "allows"),))]
    assert facts["exp-icmp-only"] == [(("ipv4",), ("icmp",), (), (("ipv4", "igw", None),))]
    assert facts["exp-two-enis"] == [
        ((), ("tcp/22",), (), (("ipv4", "none", "allows"),)),
        (("ipv4",), (), (), (("ipv4", "igw", None),)),
    ]
    assert edges["exp-stopped"][1]["state"] == "stopped"
    assert edges["exp-stopped"][1]["open_ports"] == ["tcp/22"]
    assert {a["state"] for case, (_, a) in edges.items() if case != "exp-stopped"} == {"running"}


def test_prowler_judges_the_same_estate_as_the_review_found(owner: Engine, estate: int) -> None:
    """Prowler's own verdicts on the estate, as ingested: the other half of every
    disagreement the Findings page will explain (round 2)."""
    names = _names()
    with owner.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT resource_uid, check_id, severity FROM finding
                WHERE connection_id = :c AND state IN ('open', 'reopened')
                  AND check_id LIKE 'ec2_instance_%'
            """),
            {"c": estate},
        ).all()
    found: dict[str, dict[str, str]] = {name: {} for name in names.values()}
    for r in rows:
        check = r.check_id.removeprefix("ec2_instance_").removesuffix("_exposed_to_internet")
        found[names[r.resource_uid]][check] = r.severity
    assert found == PROWLER


def _reach(owner: Engine, cid: int) -> dict[str, set[tuple[str | None, str | None]]]:
    """Each case's Prowler exposure findings: the (reach, reason) pairs they carry."""
    names = _names()
    with owner.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT resource_uid, reach, reach_reason FROM finding
                WHERE connection_id = :c AND tool = 'prowler'
                  AND check_id = ANY(CAST(:chk AS text[]))
            """),
            {"c": cid, "chk": list(PROWLER_EXPOSURE_CHECKS)},
        ).all()
    found: dict[str, set[tuple[str | None, str | None]]] = {}
    for r in rows:
        found.setdefault(names[r.resource_uid], set()).add((r.reach, r.reach_reason))
    return found


def test_each_prowler_exposure_finding_carries_argus_verdict(owner: Engine, estate: int) -> None:
    """Every disagreement, with its reason, on the finding itself: the Findings page's Reach
    filter at Restricted lists them (ADR-0035, sixth amendment)."""
    assert _reach(owner, estate) == {case: {verdict} for case, verdict in REACH.items()}


def test_prowler_before_steampipe_waits_for_the_inventory(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Prowler ingested first: Argus has nothing to judge, so not_covered (not_in_inventory),
    never a guess; the Steampipe ingest that follows sets the verdict."""
    cid = _connection(owner)
    _ingest(owner, worker, store, "prowler", cid)
    assert _reach(owner, cid) == {case: {("not_covered", "not_in_inventory")} for case in REACH}
    _ingest(owner, worker, store, "steampipe", cid)
    assert _reach(owner, cid) == {case: {verdict} for case, verdict in REACH.items()}


# Each case's exposure path (ADR-0037, second amendment): every door is one, its kind from the
# ports it is open on (Prowler 5.44.0's port lists), its confidence from the door's verdict.
EXPOSED: dict[str, tuple[str, str] | None] = {
    "exp-open": ("internet-exposed-admin-port", "confirmed"),
    "exp-s3-reader": ("internet-exposed-admin-port", "confirmed"),
    "exp-no-public-ip": ("internet-exposed-admin-port", "blocked"),
    "exp-ipv6-rule": ("internet-exposed-admin-port", "blocked"),
    "exp-vpc-b": ("internet-exposed-admin-port", "blocked"),
    "exp-acl-deny": ("internet-exposed-admin-port", "blocked"),
    "exp-inspected": ("internet-exposed-admin-port", "unknown"),
    "exp-terminated": None,
    "exp-rdp-target": None,
    "exp-ssm-target": None,
    "exp-stopped": ("internet-exposed-admin-port", "blocked"),
    "exp-icmp-only": ("internet-exposed", "blocked"),
    "exp-two-enis": ("internet-exposed-admin-port", "blocked"),
}


def _paths(owner: Engine, cid: int) -> list[Any]:
    with owner.connect() as conn:
        return list(
            conn.execute(
                text("""
                    SELECT rule_id, entry_uid, target_uid, confidence, severity, has_failing
                    FROM attack_path WHERE connection_id = :c AND state = 'open'
                """),
                {"c": cid},
            )
        )


def test_every_door_is_an_attack_path_after_steampipe_alone(owner: Engine, estate: int) -> None:
    """No CloudFox run: Steampipe's ingest computes the paths, Prowler's sets their severity."""
    names = _names()
    exposed = {
        names[p.entry_uid]: (p.rule_id, p.confidence)
        for p in _paths(owner, estate)
        if p.rule_id.startswith("internet-exposed") and p.entry_uid in names
    }
    assert {case: exposed.get(case) for case in EXPOSED} == EXPOSED
    severity = {
        names[p.entry_uid]: (p.severity, p.has_failing)
        for p in _paths(owner, estate)
        if p.rule_id.startswith("internet-exposed") and p.entry_uid in names
    }
    # High, up one for a confirmed entry; Prowler's failing port check is on the way.
    assert severity["exp-open"] == ("critical", True)
    # Latent: down one; Prowler flags it, so not down for "no failing finding".
    assert severity["exp-stopped"] == ("medium", True)


def test_a_managed_policy_gives_a_data_path(owner: Engine, estate: int) -> None:
    """exp-s3-reader's role has AmazonS3ReadOnlyAccess (role-accesses v2): the internet reaches
    every bucket through it, any:s3."""
    names = _names()
    data = [
        p
        for p in _paths(owner, estate)
        if p.rule_id == "internet-to-data" and names.get(p.entry_uid) == "exp-s3-reader"
    ]
    assert [(p.target_uid, p.confidence) for p in data] == [("any:s3", "supported")]


def test_a_failing_check_on_the_doors_security_group_is_the_doors(
    owner: Engine, worker: Engine, estate: int
) -> None:
    """Prowler's security-group checks sit on the group, not on the path's nodes: a failing one
    on a group attached to the door keeps the path from going down for "no failing finding"."""
    names = {v: k for k, v in _names().items()}
    door = names["exp-icmp-only"]

    def failing() -> bool:
        evaluate_paths(worker, rules_dir=RULES_DIR, connection_id=estate, day=DAY, resolve=False)
        [path] = [
            p
            for p in _paths(owner, estate)
            if p.entry_uid == door and p.rule_id == "internet-exposed"
        ]
        return bool(path.has_failing)

    assert failing()  # Prowler's ec2_instance_public_ip on the instance itself
    with owner.begin() as conn:
        conn.execute(text("UPDATE finding SET muted = true WHERE resource_uid = :u"), {"u": door})
    assert not failing()
    with owner.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO finding (finding_uid, tool, check_id, connection_id, region,
                                     resource_uid, severity, status, muted, title, service,
                                     resource_type, categories, state, first_seen, last_seen)
                SELECT 'sg-check-' || e.target_uid, 'prowler',
                       'ec2_securitygroup_allow_ingress_from_internet_to_any_port', :c,
                       'us-east-1', e.target_uid, 'high', 'FAIL', false, 'Open to the internet',
                       'ec2', 'AwsEc2SecurityGroup', ARRAY['internet-exposed'], 'open', :d, :d
                FROM edge e JOIN edge_snapshot s ON s.edge_id = e.id AND s.snapshot_date = :d
                WHERE e.connection_id = :c AND e.type = 'MEMBER_OF' AND e.source_uid = :u
            """),
            {"c": estate, "d": DAY, "u": door},
        )
    assert failing()


def _entries(owner: Engine, cid: int) -> dict[str, tuple[str, dict[str, Any]]]:
    """Every rule edge from the internet, by its target's last ARN part: type, attributes."""
    with owner.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT e.target_uid, e.type, e.attributes
                FROM edge e JOIN edge_snapshot s ON s.edge_id = e.id AND s.snapshot_date = :d
                WHERE e.connection_id = :c AND e.source_uid = 'internet'
                  AND starts_with(e.origin, 'rule:')
            """),
            {"d": DAY, "c": cid},
        ).all()
    return {_last(r.target_uid): (r.type, r.attributes) for r in rows}


def _last(uid: str) -> str:
    """An ARN's last part: "exp-public-queue", "root", "s3" (any:s3)."""
    return uid.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def test_more_ways_in_than_the_network(owner: Engine, estate: int) -> None:
    """Wave 2 (ADR-0037, second amendment): a resource public by its own policy is a door, an
    outsider's principal and a user's credential are entries."""
    entries = _entries(owner, estate)
    assert entries["exp-public-queue"] == (
        "ROUTES_TO",
        {"via": "resource_policy", "actions": ["sqs:sendmessage"], "checked": ["resource_policy"]},
    )
    # Moto does not serve the account's S3 Block Public Access: Argus cannot tell.
    kind, bucket = entries["exp-public-bucket"]
    assert (kind, bucket["missing"]) == ("PUBLIC_UNVERIFIED", ["s3_account_settings:" + ACCOUNT])
    assert entries["root"] == ("OUTSIDER", {"kind": "other_account", "account": "999988887777"})
    github = entries["token.actions.githubusercontent.com"]
    assert github == ("OUTSIDER", {"kind": "oidc_no_subject"})
    assert entries["exp-old-key"][0] == entries["exp-console"][0] == "HAS_CREDENTIAL"
    assert entries["exp-console"][1] == {"credentials": ["console_password_no_mfa"]}
    assert "exp-escalator" not in entries  # no key, no password


def test_each_new_entry_reaches_what_it_can(owner: Engine, estate: int) -> None:
    short = _last
    found = {
        (p.rule_id, short(p.entry_uid), short(p.target_uid)): p.confidence
        for p in _paths(owner, estate)
    }
    assert found[("internet-public-policy", "exp-public-queue", "exp-public-queue")] == "confirmed"
    assert found[("internet-public-policy", "exp-public-bucket", "exp-public-bucket")] == "unknown"
    # The public queue triggers a function whose role reads the secret.
    secret = [
        p.confidence
        for p in _paths(owner, estate)
        if p.rule_id == "internet-to-data"
        and short(p.entry_uid) == "exp-public-queue"
        and ":secret:exp/api-key-" in p.target_uid
    ]
    assert secret == ["supported"]
    # Another account's root may assume exp-outsider, which reads every bucket.
    assert found[("internet-to-data", "root", "s3")] == "candidate"
    # A leaked key of a user in an administrators' group; a console password reaching S3.
    assert found[("internet-to-admin", "exp-old-key", ACCOUNT)] == "candidate"
    assert found[("internet-to-data", "exp-console", "s3")] == "candidate"


def test_moves_beyond_the_role(owner: Engine, estate: int) -> None:
    """Wave 3 (ADR-0037, second amendment): the RDP neighbour from every door in its VPC,
    Candidate, Blocked behind a Restricted door; an escalation by permission name."""
    names = _names()
    lateral = {
        names[p.entry_uid]: p.confidence
        for p in _paths(owner, estate)
        if p.rule_id == "internet-lateral-ssh" and names.get(p.target_uid) == "exp-rdp-target"
    }
    assert lateral["exp-open"] == "candidate"
    assert lateral["exp-stopped"] == "blocked"
    with owner.connect() as conn:
        escalation = conn.execute(
            text("""
                SELECT e.target_uid, e.attributes -> 'methods' AS methods
                FROM edge e JOIN edge_snapshot s ON s.edge_id = e.id AND s.snapshot_date = :d
                WHERE e.connection_id = :c AND e.type = 'CAN_ESCALATE_TO'
                  AND e.source_uid = :u
            """),
            {"d": DAY, "c": estate, "u": f"arn:aws:iam::{ACCOUNT}:user/exp-escalator"},
        ).one()
    assert (escalation.target_uid, escalation.methods) == (
        "admin:" + ACCOUNT,
        ["iam:createpolicyversion"],
    )
