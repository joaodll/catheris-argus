"""The walk's rules, kind by kind, on hand-built edges (ADR-0052; P1 R0 §6): no database.

Each test builds the standing edges as the walk reads them, names each kind's targets, and
checks the routes: their class, their steps, and what they leave out.
"""

from datetime import date
from itertools import pairwise
from typing import Any

from tests.conftest import RULES_DIR

from argus.attackpaths.kinds import load_kinds
from argus.attackpaths.routes import LIST_N, Evidence, FoundRoute, collect, targets_for
from argus.attackpaths.walk import MAX_DEPTH, build, chains, graph

A, B, C = "111111111111", "222222222222", "333333333333"
DAY = date(2026, 11, 15)
KINDS = load_kinds(RULES_DIR)
BY_ID = {k.id: k for k in KINDS}
_ids = iter(range(1, 10_000))


def edge(
    source: str,
    target: str,
    type_: str,
    *,
    origin: str = "rule:test@1",
    conn: int = 1,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": next(_ids),
        "source_uid": source,
        "target_uid": target,
        "source_resource_id": None,
        "target_resource_id": None,
        "type": type_,
        "origin": origin,
        "connection_id": conn,
        "day": DAY,
        "attributes": attributes,
    }


def door(uid: str, *, conn: int = 1, type_: str = "ROUTES_TO", **kw: Any) -> dict[str, Any]:
    return edge("internet", uid, type_, origin=kw.pop("origin", "rule:internet-entry@9"),
                conn=conn, **kw)  # fmt: skip


def routes(
    rows: list[dict[str, Any]],
    found: dict[str, set[str]],
    *,
    scanned: dict[str, int] | None = None,
    public_write: set[str] | None = None,
    exploitable: dict[str, str] | None = None,
    imds_v1: set[str] | None = None,
    exposed: set[str] | None = None,
    types: dict[str, str] | None = None,
) -> dict[tuple[str, str], FoundRoute]:
    scanned = scanned if scanned is not None else {A: 1}
    steps, cross = build(
        rows, scanned=scanned, public_write=public_write or set(), exposed=exposed or set()
    )
    ev = Evidence(exploitable or {}, imds_v1 or set(), exposed or set(), types or {})
    g = graph(steps, cross, ev.types)
    found_routes = collect(BY_ID, chains(g, targets_for(KINDS, found, ev)), ev)
    return {(r.kind.id, r.entry_uid): r for r in found_routes}


def reasons(route: FoundRoute, seq: int = 0) -> list[tuple[str, str]]:
    return [(s.type, s.reason) for s in route.listed()[seq].steps]


FN = f"arn:aws:lambda:eu-west-1:{A}:function:api"
ROLE = f"arn:aws:iam::{A}:role/api"
ADMIN = f"admin:{A}"
VM = f"arn:aws:ec2:eu-west-1:{A}:instance/i-1"
DB = f"arn:aws:rds:eu-west-1:{A}:db:orders"


# ---- the exposure kinds (entry only)


def test_an_open_admin_port_is_a_confirmed_one_step_route() -> None:
    found = routes([door(VM)], {"internet-exposed-admin-port": {VM}})
    route = found[("internet-exposed-admin-port", VM)]
    assert route.worst_class == "confirmed" and reasons(route) == [("ROUTES_TO", "internet_rule")]


def test_a_closed_door_is_latent_and_an_undecided_one_not_enough_data() -> None:
    closed = door(VM, type_="PUBLIC_RESTRICTED", attributes={"reason": "nacl_blocks"})
    found = routes([closed, door(DB, type_="PUBLIC_UNVERIFIED")], {"internet-exposed": {VM, DB}})
    assert found[("internet-exposed", VM)].worst_class == "blocked"
    assert reasons(found[("internet-exposed", VM)]) == [
        ("PUBLIC_RESTRICTED", "internet_restricted:nacl_blocks")
    ]
    assert found[("internet-exposed", DB)].worst_class == "unknown"


def test_a_door_argus_judged_closed_stays_closed_whatever_cloudfox_says() -> None:
    rows = [
        door(VM, type_="PUBLIC_RESTRICTED", attributes={"reason": "nacl_blocks"}),
        door(VM, type_="INTERNET_REACHABLE", origin="cloudfox"),
    ]
    found = routes(rows, {"internet-exposed": {VM}})
    assert len(found) == 1 and found[("internet-exposed", VM)].worst_class == "blocked"


def test_a_route_is_not_found_twice_for_a_rule_and_cloudfox_door() -> None:
    rows = [door(VM), door(VM, type_="INTERNET_REACHABLE", origin="cloudfox")]
    found = routes(rows, {"internet-exposed": {VM}})
    assert list(found) == [("internet-exposed", VM)]
    assert reasons(found[("internet-exposed", VM)]) == [("ROUTES_TO", "internet_rule")]


# ---- footholds (A1)


def test_a_workload_s_role_needs_a_foothold_so_no_route_through_it_is_confirmed() -> None:
    rows = [door(FN), edge(FN, ROLE, "RUNS_AS"), edge(ROLE, ADMIN, "IS_ADMIN")]
    route = routes(rows, {"internet-to-admin": {ADMIN}})[("internet-to-admin", FN)]
    assert reasons(route) == [
        ("ROUTES_TO", "internet_rule"),
        ("FOOTHOLD", "compromise_assumed"),
        ("RUNS_AS", "configuration"),
        ("IS_ADMIN", "admin_policy"),
    ]
    assert route.worst_class == "potential" and route.listed()[0].likelihood == "lower"


def test_a_public_exploit_makes_the_foothold_one_assumption() -> None:
    rows = [door(FN), edge(FN, ROLE, "RUNS_AS"), edge(ROLE, ADMIN, "IS_ADMIN")]
    found = routes(rows, {"internet-to-admin": {ADMIN}}, exploitable={FN: "CVE-2026-1234"})
    target = found[("internet-to-admin", FN)].listed()[0]
    foothold = target.steps[1]
    assert (foothold.reason, foothold.ref) == ("compromise_cve", "CVE-2026-1234")
    assert target.cls == "conditional" and target.likelihood == "higher"


def test_imdsv1_counts_only_before_an_instance_s_role() -> None:
    rows = [
        door(VM),
        edge(VM, ROLE, "RUNS_AS"),
        edge(ROLE, ADMIN, "IS_ADMIN"),
        edge(VM, DB, "CAN_CONNECT_TO"),
    ]
    found = routes(
        rows,
        {"internet-to-admin": {ADMIN}, "internet-lateral-ssh": {DB}},
        imds_v1={VM},
        types={VM: "aws_ec2_instance"},
    )
    assert reasons(found[("internet-to-admin", VM)])[1] == ("FOOTHOLD", "compromise_imdsv1")
    assert reasons(found[("internet-lateral-ssh", VM)])[1] == ("FOOTHOLD", "compromise_assumed")


def test_a_workload_secret_is_read_only_with_control_of_the_workload() -> None:
    found = routes([door(FN)], {"internet-to-workload-secret": {FN}})
    route = found[("internet-to-workload-secret", FN)]
    assert reasons(route) == [("ROUTES_TO", "internet_rule"), ("FOOTHOLD", "compromise_assumed")]
    assert route.worst_class == "potential"


# ---- identity moves


def test_a_role_without_an_administrator_is_no_admin_route() -> None:
    rows = [door(FN), edge(FN, ROLE, "RUNS_AS")]
    assert not routes(rows, {"internet-to-admin": {ADMIN}})


def test_a_trust_condition_is_an_assumption() -> None:
    other = f"arn:aws:iam::{A}:role/deploy"
    rows = [
        edge("internet", f"arn:aws:iam::{A}:user/ci", "HAS_CREDENTIAL"),
        edge(f"arn:aws:iam::{A}:user/ci", other, "CAN_ASSUME",
             attributes={"condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}),
        edge(other, ADMIN, "IS_ADMIN", origin="cloudfox"),
    ]  # fmt: skip
    route = routes(rows, {"internet-to-admin": {ADMIN}})[
        ("internet-to-admin", f"arn:aws:iam::{A}:user/ci")
    ]
    assert [r for _, r in reasons(route)] == ["credential", "trust_condition", "cloudfox_analysis"]
    assert route.worst_class == "potential"  # a leaked credential and a condition


def test_a_rule_and_cloudfox_drawing_one_step_make_one_target_through_the_surer_one() -> None:
    user = f"arn:aws:iam::{A}:user/ci"
    rows = [
        edge("internet", user, "HAS_CREDENTIAL"),
        edge(user, ADMIN, "IS_ADMIN"),
        edge(user, ADMIN, "IS_ADMIN", origin="cloudfox"),
    ]
    route = routes(rows, {"internet-to-admin": {ADMIN}})[("internet-to-admin", user)]
    assert route.count == 1 and reasons(route)[-1] == ("IS_ADMIN", "cloudfox_analysis")


def test_a_trust_loop_ends_and_the_walk_stops_at_its_depth() -> None:
    user = f"arn:aws:iam::{A}:user/ci"
    chain = [f"arn:aws:iam::{A}:role/r{i}" for i in range(MAX_DEPTH + 1)]
    rows = [edge("internet", user, "HAS_CREDENTIAL"), edge(user, chain[0], "CAN_ASSUME")]
    rows += [edge(a, b, "CAN_ASSUME") for a, b in pairwise(chain)]
    rows += [edge(chain[1], chain[0], "CAN_ASSUME")]  # a loop
    rows += [edge(chain[-1], ADMIN, "IS_ADMIN"), edge(chain[MAX_DEPTH - 2], ADMIN, "IS_ADMIN")]
    route = routes(rows, {"internet-to-admin": {ADMIN}})[("internet-to-admin", user)]
    # The administrator through the last role is one move too far; through r6 it is in reach.
    assert len(route.listed()[0].steps) == 1 + MAX_DEPTH
    assert route.listed()[0].steps[-2].target == chain[MAX_DEPTH - 2]


def test_the_strongest_route_is_listed_before_a_shorter_assumed_one() -> None:
    other = f"arn:aws:iam::{A}:role/ops"
    rows = [
        door(FN),
        edge(FN, ROLE, "RUNS_AS"),
        edge(ROLE, ADMIN, "CAN_ESCALATE_TO"),  # 1 move, by permission name: candidate
        edge(ROLE, other, "CAN_ASSUME"),  # 2 moves, configured
        edge(other, ADMIN, "IS_ADMIN"),
    ]
    route = routes(rows, {"internet-to-admin": {ADMIN}}, exploitable={FN: "CVE-1"})[
        ("internet-to-admin", FN)
    ]
    assert [t for t, _ in reasons(route)][-2:] == ["CAN_ASSUME", "IS_ADMIN"]
    assert route.worst_class == "conditional"


# ---- across accounts (A3)


ROLE_A = f"arn:aws:iam::{A}:role/shared"
USER_B = f"arn:aws:iam::{B}:user/deployer"


def _across(principal: str = f"arn:aws:iam::{B}:root", resources: list[str] | None = None):
    return [
        edge("internet", USER_B, "HAS_CREDENTIAL", conn=2),
        edge(USER_B, f"arn:aws:iam::{B}:root", "MAY_ASSUME", origin="rule:assume-permission@1",
             conn=2, attributes={"resources": resources or ["*"], "truncated": False}),
        edge(principal, ROLE_A, "CAN_ASSUME", origin="rule:role-trust@2"),
        edge(ROLE_A, ADMIN, "IS_ADMIN"),
        edge("internet", f"arn:aws:iam::{B}:root", "OUTSIDER", origin="rule:outsider-trust@1"),
    ]  # fmt: skip


def test_a_scanned_account_is_not_an_outsider_and_its_principals_route_is_found() -> None:
    found = routes(_across(), {"internet-to-admin": {ADMIN}}, scanned={A: 1, B: 2})
    assert ("internet-to-admin", f"arn:aws:iam::{B}:root") not in found
    route = found[("internet-to-admin", USER_B)]
    assert reasons(route)[1] == ("CAN_ASSUME", "cross_account_identity")
    assert route.crossed_ids() == [2, 1]


def test_a_bare_account_id_in_a_trust_is_that_account_s_root() -> None:
    found = routes(_across(principal=B), {"internet-to-admin": {ADMIN}}, scanned={A: 1, B: 2})
    assert ("internet-to-admin", USER_B) in found


def test_a_principal_allowed_another_role_only_does_not_cross() -> None:
    rows = _across(resources=[f"arn:aws:iam::{A}:role/other-*"])
    found = routes(rows, {"internet-to-admin": {ADMIN}}, scanned={A: 1, B: 2})
    assert ("internet-to-admin", USER_B) not in found


def test_an_unscanned_account_stays_an_outsider() -> None:
    found = routes(_across(), {"internet-to-admin": {ADMIN}}, scanned={A: 1})
    route = found[("internet-to-admin", f"arn:aws:iam::{B}:root")]
    assert [r for _, r in reasons(route)][:2] == ["outsider", "cross_account_trust"]


# ---- traffic


BUCKET = "arn:aws:s3:::uploads"
CDN = f"arn:aws:cloudfront::{A}:distribution/E1"
SITE = "arn:aws:s3:::site"


def test_a_trigger_is_an_assumption_unless_anyone_may_write_the_source() -> None:
    rows = [door(BUCKET, attributes={"via": "resource_policy"}), edge(BUCKET, FN, "TRIGGERS"),
            edge(FN, ROLE, "RUNS_AS"), edge(ROLE, ADMIN, "IS_ADMIN")]  # fmt: skip
    read_only = routes(rows, {"internet-to-admin": {ADMIN}})[("internet-to-admin", BUCKET)]
    assert reasons(read_only)[1] == ("TRIGGERS", "trigger_input")
    writable = routes(rows, {"internet-to-admin": {ADMIN}}, public_write={BUCKET})
    assert reasons(writable[("internet-to-admin", BUCKET)])[1] == (
        "TRIGGERS",
        "trigger_public_write",
    )


def test_a_static_site_is_not_a_data_route_unless_its_bucket_is_public() -> None:
    rows = [door(CDN), edge(CDN, SITE, "ROUTES_TO", origin="rule:cloudfront-origin@2")]
    assert not routes(rows, {"internet-to-data": {SITE}})
    # Nor is anything behind it: reading through a distribution writes nothing to the bucket.
    behind = [*rows, edge(SITE, FN, "TRIGGERS"), edge(FN, ROLE, "RUNS_AS"),
              edge(ROLE, ADMIN, "IS_ADMIN")]  # fmt: skip
    assert not routes(behind, {"internet-to-admin": {ADMIN}})
    exposed = routes(rows, {"internet-to-data": {SITE}}, exposed={SITE})
    assert exposed[("internet-to-data", CDN)].worst_class == "confirmed"


def test_a_database_reached_by_its_network_alone_is_potential() -> None:
    rows = [door(VM), edge(VM, DB, "CAN_CONNECT_TO")]
    found = routes(
        rows, {"internet-to-data": {DB}}, exploitable={VM: "CVE-2"},
        types={DB: "aws_rds_db_instance"},
    )  # fmt: skip
    route = found[("internet-to-data", VM)]
    assert reasons(route)[-1] == ("AUTHENTICATES", "data_auth_assumed")
    assert route.worst_class == "potential"


def test_a_dns_record_is_not_a_way_to_its_target() -> None:
    record = "arn:aws:route53:::hostedzone/Z1/A/app"
    rows = [door(VM), edge(VM, record, "ROUTES_TO"),
            edge(record, DB, "ROUTES_TO", origin="rule:route53-target@2")]  # fmt: skip
    assert not routes(rows, {"internet-to-data": {DB}})


# ---- listing


def test_a_route_lists_its_worst_targets_and_counts_and_crosses_every_one() -> None:
    user = f"arn:aws:iam::{A}:user/ci"
    roles = [f"arn:aws:iam::{A}:role/r{i:02}" for i in range(LIST_N + 5)]
    rows = [edge("internet", user, "HAS_CREDENTIAL")]
    rows += [edge(user, r, "CAN_ASSUME") for r in roles[:-1]]
    # The last target is reached only from another account's edge, and is the least sure.
    rows += [edge(user, roles[-1], "CAN_ESCALATE_TO", conn=3)]
    route = routes(rows, {"internet-to-admin": set(roles)}, scanned={A: 1, C: 3})[
        ("internet-to-admin", user)
    ]
    assert (route.count, len(route.listed())) == (LIST_N + 5, LIST_N)
    assert roles[-1] not in {t.target for t in route.listed()}
    assert route.crossed_ids() == [1, 3]  # §9 H1: an unlisted target's account counts


def test_an_unchanged_route_has_the_same_digest() -> None:
    rows = [door(FN), edge(FN, ROLE, "RUNS_AS"), edge(ROLE, ADMIN, "IS_ADMIN")]
    one = routes(rows, {"internet-to-admin": {ADMIN}})[("internet-to-admin", FN)]
    two = routes(rows, {"internet-to-admin": {ADMIN}})[("internet-to-admin", FN)]
    assert one.digest() == two.digest()
