"""Investigate -> Resource map and Attack paths (ADR-0033) over the synthetic prod estate, whose
front-door chain runs Route53 -> CloudFront -> HTTP API -> function -> role -> admin."""

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import TOOL_ORDER
from argus.collection.synthetic.estate import SCENARIO_INSTANCE
from argus.core.rawstore import FilesystemRawStore

pytestmark = pytest.mark.db


@pytest.fixture
def prod(owner: Engine, worker: Engine, store: FilesystemRawStore) -> int:
    target = make_demo(owner)  # seed 0: the prod profile
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, datetime.now(UTC).date())
    return target.connection_id


def _graph(client: TestClient, focus: str, **params: Any) -> dict[str, Any]:
    response = client.get("/api/v1/map/graph", params={"focus": focus, **params})
    assert response.status_code == 200, response.text
    graph: dict[str, Any] = response.json()
    return graph


def _named(graph: dict[str, Any], prefix: str) -> dict[str, Any]:
    return next(n for n in graph["nodes"] if (n["name"] or "").startswith(prefix))


def _record(client: TestClient, prefix: str) -> str:
    found = client.get("/api/v1/resources", params={"q": prefix, "limit": 50}).json()["items"]
    return str(
        next(
            r["resource_uid"]
            for r in found
            if r["type"] == "aws_route53_record" and (r["name"] or "").startswith(prefix)
        )
    )


def test_front_doors_then_the_chain_down_to_the_function(signed_in: TestClient, prod: int) -> None:
    doors = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "limit": 100}
    ).json()
    by_type: dict[str, list[dict[str, Any]]] = {}
    for door in doors["items"]:
        by_type.setdefault(door["node"]["type"] or door["node"]["kind"], []).append(door)
    assert {
        "aws_cloudfront_distribution",
        "aws_api_gatewayv2_api",
        "aws_api_gateway_rest_api",
        "aws_ec2_application_load_balancer",
        "aws_eks_cluster",
    } <= set(by_type)
    # A DNS record names an entry; it is not one (ADR-0035). Only a record whose chain ends
    # outside what Argus judges is a door, unknown (argus_v12): rest, an API custom domain
    # (which API it serves is not collected), and status, a vendor's host.
    records = {d["node"]["name"].split(".")[0]: d for d in by_type["aws_route53_record"]}
    assert sorted(records) == ["rest", "status"]
    assert {d["reach"] for d in records.values()} == {"unknown"}
    assert records["rest"]["missing"][0].startswith("dns_target:arn:aws:apigateway:")
    assert records["status"]["missing"][0].startswith("dns_target:external:status.")
    assert doors["total"] == len(doors["items"]) and doors["data_through"]
    # The edge ALB is found by our rule and by CloudFox.
    alb = next(
        d for d in by_type["aws_ec2_application_load_balancer"] if "edge-alb" in d["node"]["name"]
    )
    assert alb["via"] == ["cloudfox", "rule"]
    record = _record(signed_in, "app.")

    graph = _graph(signed_in, record, connection_id=prod, depth=3)
    assert not graph["truncated"]
    cdn = next(n for n in graph["nodes"] if n["type"] == "aws_cloudfront_distribution")
    api = next(n for n in graph["nodes"] if n["type"] == "aws_api_gatewayv2_api")
    function = _named(graph, "prod-orders-api")
    edges = {(e["source_uid"], e["target_uid"], e["type"]) for e in graph["edges"]}
    assert (record, cdn["uid"], "ROUTES_TO") in edges
    assert ("internet", cdn["uid"], "ROUTES_TO") in edges
    assert (cdn["uid"], api["uid"], "ROUTES_TO") in edges
    assert (api["uid"], function["uid"], "ROUTES_TO") in edges
    assert graph["nodes"][0]["uid"] == record and graph["nodes"][0]["expanded"]
    assert not function["expanded"]  # three hops away: the map can expand it next
    # An external host is a pseudo-node, never dropped.
    status = _graph(signed_in, _record(signed_in, "status."), connection_id=prod)
    assert any(n["kind"] == "external" for n in status["nodes"])


def test_identity_and_findings_per_tool(signed_in: TestClient, prod: int) -> None:
    doors = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "limit": 100}
    ).json()
    alb = next(d["node"] for d in doors["items"] if (d["node"]["name"] or "").endswith("edge-alb"))
    # The ALB's target group routes to the API function, which runs as a role CloudFox says
    # can escalate to administrator.
    graph = _graph(signed_in, alb["uid"], depth=3)
    function = _named(graph, "prod-orders-api")
    assert function["kind"] == "resource" and function["resource_id"]
    near = _graph(signed_in, function["uid"], depth=2, layer=["identity"])
    role = _named(near, "prod-orders-api-role")
    admin = next(n for n in near["nodes"] if n["kind"] == "admin")
    types = {(e["source_uid"], e["target_uid"]): e["type"] for e in near["edges"]}
    assert types[(function["uid"], role["uid"])] == "RUNS_AS"
    assert types[(role["uid"], admin["uid"])] == "CAN_PRIVESC_TO"
    # Only the asked layers: no ROUTES_TO in an identity-only view.
    assert {e["type"] for e in near["edges"]} <= {
        "RUNS_AS",
        "CAN_ASSUME",
        "IS_ADMIN",
        "CAN_PRIVESC_TO",
        "MEMBER_OF",
        "BELONGS_TO",
    }
    # Findings are counted per tool on the nodes that have them.
    tools = {tool for n in graph["nodes"] for tool in n["findings"]}
    assert tools <= {"prowler", "cloudfox"} and tools
    for n in graph["nodes"]:
        for counts in n["findings"].values():
            assert counts["open"] > 0 and counts["worst"] in {
                "critical",
                "high",
                "medium",
                "low",
                "informational",
            }


def test_many_neighbours_of_one_kind_come_back_as_a_group(
    signed_in: TestClient, prod: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("argus.relationships.graph.GROUP_OVER", 1)
    graph = _graph(signed_in, "internet", connection_id=prod)
    # Any kind with more than one front door (GROUP_OVER is 1 here) comes back as a group.
    group = next(g for g in graph["groups"] if g["edge_type"] == "ROUTES_TO")
    assert group["anchor_uid"] == "internet" and group["direction"] == "out"
    assert group["count"] >= 2
    # Its members are not drawn one by one (a Restricted door of that type still is: another
    # edge type, ADR-0033 amended 2026-10-21).
    types = {n["uid"]: n["type"] for n in graph["nodes"]}
    assert not any(
        e["source_uid"] == "internet"
        and e["type"] == "ROUTES_TO"
        and types.get(e["target_uid"]) == group["resource_type"]
        for e in graph["edges"]
    )
    page = signed_in.get(
        "/api/v1/map/group",
        params={
            "anchor": "internet",
            "connection_id": prod,
            "direction": "out",
            "edge_type": "ROUTES_TO",
            "resource_type": group["resource_type"],
            "limit": 2,
        },
    ).json()
    assert page["total"] == group["count"] and len(page["items"]) == 2
    names = [i["node"]["name"] for i in page["items"]]
    assert names == sorted(names, key=str.lower)
    assert all(i["edge"]["source_uid"] == "internet" for i in page["items"])


def test_the_map_walks_one_connection(
    signed_in: TestClient,
    prod: int,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
) -> None:
    """Depth used to reach other connections through shared nodes such as `internet`
    (argus_v10); another connection's resource is now a boundary node, never expanded."""
    other = make_demo(owner, seed=1)
    for tool in TOOL_ORDER:
        run_tool(worker, store, other, tool, datetime.now(UTC).date())
    for cid in (prod, other.connection_id):
        graph = _graph(signed_in, "internet", connection_id=cid, depth=3)
        assert graph["connection_id"] == cid
        resources = [n for n in graph["nodes"] if n["connection_id"] is not None]
        assert resources and {n["connection_id"] for n in resources if not n["boundary"]} == {cid}
        assert not any(n["expanded"] for n in graph["nodes"] if n["boundary"])
    # A resource's own connection is the default.
    door = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": other.connection_id}
    ).json()["items"][0]["node"]
    assert _graph(signed_in, door["uid"])["connection_id"] == other.connection_id


def test_the_map_cap_and_bad_requests(
    signed_in: TestClient, prod: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("argus.relationships.graph.MAX_NODES", 3)
    capped = _graph(signed_in, "internet", connection_id=prod, layer=["traffic", "network"])
    assert capped["truncated"] and len(capped["nodes"]) + len(capped["groups"]) <= 3
    unknown = signed_in.get(
        "/api/v1/map/graph", params={"focus": "arn:aws:ec2:us-east-1:1:instance/i-none"}
    )
    assert unknown.status_code == 422  # not in the inventory, and no connection to walk
    scoped = {"focus": "internet", "connection_id": prod}
    assert (
        signed_in.get("/api/v1/map/graph", params={**scoped, "connection_id": 999999}).status_code
        == 404
    )
    assert (
        signed_in.get("/api/v1/map/graph", params={**scoped, "layer": "bogus"}).status_code == 422
    )
    assert signed_in.get("/api/v1/map/graph", params={**scoped, "depth": 4}).status_code == 422
    assert (
        signed_in.get(
            "/api/v1/map/group",
            params={
                "anchor": "internet",
                "connection_id": prod,
                "direction": "out",
                "edge_type": "ROUTES_TO; DROP",
            },
        ).status_code
        == 422
    )


def test_attack_paths_list_detail_and_facets(signed_in: TestClient, prod: int) -> None:
    page = signed_in.get("/api/v1/attack-paths").json()
    # The scenario's chain to administrator; the exposed doors are one-step paths of their own
    # (ADR-0037, second amendment).
    top = next(p for p in page["items"] if p["rule_id"] == "internet-to-admin")
    assert top["severity"] == "critical" and top["rule_name"]
    assert "cloudfox" in top["evidence"] and "rule" in top["evidence"]
    assert top["base_severity"] == "high" and top["entry_confirmed"] is True
    detail = signed_in.get(f"/api/v1/attack-paths/{top['id']}").json()
    assert [n["uid"] for n in detail["nodes"]] == top["node_uids"]
    assert detail["nodes"][0]["kind"] == "internet" and detail["nodes"][-1]["kind"] == "admin"
    assert len(detail["edges"]) == len(detail["nodes"]) - 1
    assert detail["rule"]["technique"] and detail["rule"]["remediation"]
    [instance] = signed_in.get("/api/v1/resources", params={"q": SCENARIO_INSTANCE}).json()["items"]
    uid = instance["resource_uid"]
    through = signed_in.get("/api/v1/attack-paths", params={"through": uid}).json()
    assert through["items"] and all(uid in p["node_uids"] for p in through["items"])
    critical = signed_in.get("/api/v1/attack-paths", params={"severity": ["critical"]}).json()
    assert critical["items"] and {p["severity"] for p in critical["items"]} == {"critical"}
    assert len(page["items"]) == min(page["total"], 50) and critical["total"] <= page["total"]
    newest = signed_in.get("/api/v1/attack-paths", params={"order": "last_seen_desc", "limit": 1})
    assert newest.json()["total"] == page["total"] and len(newest.json()["items"]) == 1
    assert signed_in.get("/api/v1/attack-paths", params={"order": "rule_id"}).status_code == 422
    beyond = signed_in.get("/api/v1/attack-paths", params={"offset": 1000}).json()
    assert beyond["items"] == [] and beyond["total"] == page["total"]  # the UI moves back
    facets = signed_in.get("/api/v1/attack-paths/facets").json()
    assert top["category"] in facets["categories"]
    assert top["confidence"] in facets["confidences"]
    levels = ["blocked", "unknown", "candidate", "supported", "confirmed"]
    assert facets["confidences"] == sorted(facets["confidences"], key=levels.index)
    # Each step says how sure Argus is, why, and where it comes from; the path is its weakest.
    assert all(e["confidence"] in levels and e["confidence_why"] for e in detail["edges"])
    assert detail["edges"][0]["confidence"] == "confirmed"  # Argus's own internet check
    assert detail["edges"][0]["source"].startswith("rule internet-entry@")
    weakest = min((e["confidence"] for e in detail["edges"]), key=levels.index)
    assert detail["confidence"] == weakest
    same = signed_in.get("/api/v1/attack-paths", params={"confidence": [weakest]}).json()
    assert top["id"] in {p["id"] for p in same["items"]}
    assert {p["confidence"] for p in same["items"]} == {weakest}
    assert signed_in.get("/api/v1/attack-paths", params={"confidence": "sure"}).status_code == 422
    # Latent paths (blocked) are listed only when asked for (ADR-0037, amended 2026-10-21).
    assert "blocked" not in {p["confidence"] for p in page["items"]}
    if "blocked" in facets["confidences"]:
        latent = signed_in.get("/api/v1/attack-paths", params={"confidence": ["blocked"]}).json()
        assert latent["items"] and {p["confidence"] for p in latent["items"]} == {"blocked"}
        assert latent["items"][0]["severity"] != "critical"
    assert signed_in.get("/api/v1/attack-paths/999999").status_code == 404


def test_attack_paths_by_kind_with_their_first_step(signed_in: TestClient, prod: int) -> None:
    """Wave 4 (docs/ui/screens.md E12): the Kind filter, and each row's first step for the
    list's "how it gets in"."""
    page = signed_in.get("/api/v1/attack-paths").json()
    top = next(p for p in page["items"] if p["rule_id"] == "internet-to-admin")
    facets = signed_in.get("/api/v1/attack-paths/facets").json()
    assert {"id": "internet-to-admin", "name": top["rule_name"]} in facets["kinds"]
    names = [k["name"] or k["id"] for k in facets["kinds"]]
    assert names == sorted(names, key=str.lower)
    one_kind = signed_in.get("/api/v1/attack-paths", params={"kind": ["internet-to-admin"]})
    assert top["id"] in {p["id"] for p in one_kind.json()["items"]}
    assert {p["rule_id"] for p in one_kind.json()["items"]} == {"internet-to-admin"}
    assert signed_in.get("/api/v1/attack-paths", params={"kind": "a; DROP"}).status_code == 422
    detail = signed_in.get(f"/api/v1/attack-paths/{top['id']}").json()
    assert detail["edges"][0]["source_uid"] == "internet"
    assert top["entry_step"] == {k: detail["edges"][0][k] for k in ("type", "origin", "attributes")}
    # Steampipe alone makes paths since wave 1: the list's scan time counts it.
    assert page["data_through"] is not None


def test_a_resource_says_which_tools_scanned_its_account(signed_in: TestClient, prod: int) -> None:
    one = signed_in.get("/api/v1/resources", params={"limit": 1}).json()["items"][0]
    detail = signed_in.get(f"/api/v1/resources/{one['id']}").json()
    today = datetime.now(UTC).date().isoformat()
    assert detail["scanned"] == {"steampipe": today, "prowler": today, "cloudfox": today}


def test_the_front_door_chain_is_an_attack_path(signed_in: TestClient, prod: int) -> None:
    """The join no single tool makes: our rules route the internet to a function, CloudFox says
    its role escalates to admin. The search finds it without a rule for it (ADR-0037)."""
    page = signed_in.get(
        "/api/v1/attack-paths", params={"category": ["IAM privilege escalation"], "limit": 200}
    )
    paths = [p for p in page.json()["items"] if any(":function:" in uid for uid in p["node_uids"])]
    assert paths, "the demo's front-door chain no longer reaches an escalating role"
    assert {p["rule_id"] for p in paths} == {"internet-to-admin"}
    detail = signed_in.get(f"/api/v1/attack-paths/{paths[0]['id']}").json()
    kinds = [n["kind"] for n in detail["nodes"]]
    assert kinds[0] == "internet" and kinds[-1] == "admin"
    assert [e["type"] for e in detail["edges"]][-2] == "RUNS_AS"
    assert {e["origin"].split(":")[0] for e in detail["edges"]} >= {"rule", "cloudfox"}
    assert len(set(detail["node_uids"])) == len(detail["node_uids"])  # no node twice


def test_internet_only_where_traffic_can_arrive(signed_in: TestClient, prod: int) -> None:
    """argus_v10: an internet-facing ALB whose security group admits one address range is not
    a front door; the edge from `internet` says why (ADR-0035)."""
    doors = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "reach": ["open"], "limit": 100}
    ).json()
    assert not any((d["node"]["name"] or "").endswith("admin-alb") for d in doors["items"])
    # In the default Traffic layer: a door always shows its link (ADR-0033, amended 2026-10-21).
    graph = _graph(signed_in, "internet", connection_id=prod, layer=["traffic"])
    admin = _named(graph, "prod-admin-alb")
    [edge] = [
        e
        for e in graph["edges"]
        if e["target_uid"] == admin["uid"] and e["origin"].startswith("rule:")
    ]
    assert edge["type"] == "PUBLIC_RESTRICTED"
    evidence = edge["attributes"].pop("network")
    assert edge["attributes"] == {
        "via": "load_balancer",
        "reason": "sg_no_public_source",
        "sources": ["203.0.113.0/24"],
        "checked": ["security_groups", "route_table", "network_acl"],
        "open_ports": [],  # nothing open to the whole internet (ADR-0035, fourth amendment)
    }
    # The evidence (fifth amendment): one entry, no interface, nothing open to test the ACL.
    [entry] = evidence
    assert (entry["interface"], entry["public"], entry["open"]) == (
        None,
        ["ipv4"],
        {"ipv4": [], "ipv6": []},
    )
    assert entry["subnets"] and {s["acl"] for s in entry["subnets"]} == {None}
    assert "igw" in {s["route"] for s in entry["subnets"]}
    # Asked for, it is listed as restricted: CloudFox calls it public, Argus's rule says why not.
    restricted = signed_in.get(
        "/api/v1/map/front-doors",
        params={"connection_id": prod, "reach": ["restricted", "cloudfox_only"], "limit": 100},
    ).json()["items"]
    door = next(d for d in restricted if d["node"]["uid"] == admin["uid"])
    assert (door["reach"], door["via"]) == ("restricted", ["cloudfox", "rule"])
    assert (door["reason"], door["sources"]) == ("sg_no_public_source", ["203.0.113.0/24"])
    # The list carries the evidence the edge holds, for the why-line and the expanded row.
    assert door["network"] == evidence and door["state"] is None  # a load balancer: no state
    assert all(d["reach"] == "open" for d in doors["items"])


def test_one_door_list_opens_flows(signed_in: TestClient, prod: int) -> None:
    """argus_v11: one start list, every reach by default, open doors first; each door the
    rules found names its flow (ADR-0036), and the list narrows by region."""
    doors = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "limit": 100}
    ).json()["items"]
    order = [d["reach"] for d in doors]
    assert {"open", "restricted"} <= set(order)
    assert order == sorted(order, key=["open", "unknown", "restricted", "cloudfox_only"].index)
    for door in doors:
        if door["reach"] == "cloudfox_only":
            assert door["flow_id"] is None and door["resources"] is None
        else:
            assert door["flow_id"] and door["resources"] >= 1
            flow = signed_in.get(f"/api/v1/map/flows/{door['flow_id']}").json()
            assert (flow["entry_uid"], flow["reach"]) == (door["node"]["uid"], door["reach"])
        if door["reach"] != "restricted":
            assert (door["reason"], door["sources"]) == (None, [])
    # Region: only the doors there; a region with none gives an empty page, not an error.
    region = next(d["node"]["region"] for d in doors if d["node"]["region"])
    there = signed_in.get(
        "/api/v1/map/front-doors",
        params={"connection_id": prod, "region": [region], "limit": 100},
    ).json()
    assert there["items"] and all(d["node"]["region"] == region for d in there["items"])
    assert there["total"] == sum(d["node"]["region"] == region for d in doors)
    nowhere = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "region": ["xx-none-1"]}
    ).json()
    assert (nowhere["items"], nowhere["total"]) == ([], 0)
    # Paging keeps the order.
    first = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "limit": 2, "offset": 2}
    ).json()["items"]
    assert [d["node"]["uid"] for d in first] == [d["node"]["uid"] for d in doors[2:4]]


def test_front_doors_narrow_by_a_search(signed_in: TestClient, prod: int) -> None:
    """2026-10-15: a word keeps the doors whose name, uid or type holds it, in any case; the
    type's underscores read as spaces too, and LIKE's wildcards are taken literally."""
    doors = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "limit": 100}
    ).json()["items"]

    def search(q: str) -> list[str]:
        page = signed_in.get(
            "/api/v1/map/front-doors", params={"connection_id": prod, "q": q, "limit": 100}
        ).json()
        assert page["total"] == len(page["items"])
        return [d["node"]["uid"] for d in page["items"]]

    door = next(d for d in doors if d["node"]["type"] and d["node"]["name"])
    kind = door["node"]["type"]
    by_type = search(kind.split("_", 1)[1].upper())  # "LB" for aws_lb: any case
    assert door["node"]["uid"] in by_type
    assert set(by_type) <= {d["node"]["uid"] for d in doors}
    assert door["node"]["uid"] in search(kind.replace("_", " "))
    assert door["node"]["uid"] in search(door["node"]["name"][1:-1])
    assert search("no-such-door") == []
    assert search("%") == []  # a wildcard is a literal: no door names one
    too_long = {"connection_id": prod, "q": "x" * 201}
    assert signed_in.get("/api/v1/map/front-doors", params=too_long).status_code == 422


def test_routes_acls_and_missing_data_decide_the_reach(signed_in: TestClient, prod: int) -> None:
    """ADR-0035, second amendment: a public address with no route to an internet gateway, a
    subnet ACL that denies the port, and a VPC whose route tables were never collected. The
    dual-stack edge ALB is open over IPv4 and IPv6; the list orders open, unknown, restricted."""
    doors = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "limit": 100}
    ).json()["items"]
    by_name = {d["node"]["name"]: d for d in doors}
    edge = by_name["prod-edge-alb"]
    assert (edge["reach"], edge["open"]) == ("open", ["tcp/443"])
    assert edge["families"] == ["ipv4", "ipv6"]  # dual-stack, open to anywhere in both
    no_route = by_name["legacy-public-ip"]
    assert (no_route["reach"], no_route["reason"]) == ("restricted", "no_internet_route")
    acl = by_name["dmz-web-01"]
    assert (acl["reach"], acl["reason"]) == ("restricted", "nacl_blocks")
    unknown = by_name["legacy-vpc-app"]
    assert unknown["reach"] == "unknown" and unknown["reason"] is None
    [missing] = unknown["missing"]
    assert missing.startswith("route_table:subnet-")  # its VPC has no route table rows
    order = [d["reach"] for d in doors]
    assert order == sorted(order, key=["open", "unknown", "restricted", "cloudfox_only"].index)
    # An unknown door starts a flow of its own reach; the filter keeps only unknown doors.
    flow = signed_in.get(f"/api/v1/map/flows/{unknown['flow_id']}")
    assert flow.status_code == 200 and flow.json()["reach"] == "unknown"
    only = signed_in.get(
        "/api/v1/map/front-doors",
        params={"connection_id": prod, "reach": ["unknown"], "limit": 100},
    ).json()["items"]
    assert only and {d["reach"] for d in only} == {"unknown"}


def test_a_door_counts_prowlers_exposure_findings(signed_in: TestClient, prod: int) -> None:
    """A front door's "Prowler: N exposure checks failing" (ADR-0035, sixth amendment): the same
    findings as the Findings list on that resource, Prowler only, any reach."""
    doors = signed_in.get(
        "/api/v1/map/front-doors", params={"connection_id": prod, "limit": 100}
    ).json()["items"]
    counted = [d for d in doors if d["prowler_exposure"]]
    assert counted
    every_reach = ["confirmed", "restricted", "unknown", "not_covered"]
    for door in counted:
        listed = signed_in.get(
            "/api/v1/findings",
            params={
                "resource_id": door["node"]["resource_id"],
                "tool": "prowler",
                "reach": every_reach,
                "limit": 200,
            },
        ).json()
        assert listed["total"] == door["prowler_exposure"], door["node"]["name"]
    assert all(d["prowler_exposure"] == 0 for d in doors if d["node"]["resource_id"] is None)
