"""Investigate -> Resource Map and Security Map (ADR-0051) over the synthetic prod estate, whose
front-door chain runs Route53 -> CloudFront -> HTTP API -> function -> role -> admin. A request
reads up to three hops and walks on only from the connection's own resources; the screen grows
the map by asking again (Expand). The maps draw connections, not reach. The Resource Map reads
no security fact from any of its routes; the Security Map also draws the security lines."""

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.api.routes import resource_map
from argus.collection import TOOL_ORDER
from argus.core.rawstore import FilesystemRawStore
from argus.relationships import EDGE_ATTRIBUTES, SECURITY_EDGE_TYPES

pytestmark = pytest.mark.db

NODE_FIELDS = {
    "uid",
    "kind",
    "resource_id",
    "type",
    "name",
    "region",
    "connection_id",
    "deleted_on",
    "expanded",
    "boundary",
}


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


def _resource(client: TestClient, name: str, **params: Any) -> dict[str, Any]:
    """A resource found the way the map's start screen finds one: the Resources search."""
    found = client.get("/api/v1/resources", params={"q": name, "limit": 50, **params}).json()
    return next(r for r in found["items"] if (r["name"] or "").endswith(name))


def _record(client: TestClient, prefix: str) -> str:
    found = client.get("/api/v1/resources", params={"q": prefix, "limit": 50}).json()["items"]
    return str(
        next(
            r["resource_uid"]
            for r in found
            if r["type"] == "aws_route53_record" and (r["name"] or "").startswith(prefix)
        )
    )


def _edges(graph: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {(e["source_uid"], e["target_uid"], e["type"]) for e in graph["edges"]}


def test_the_chain_from_a_dns_record_down_to_the_function(signed_in: TestClient, prod: int) -> None:
    record = _record(signed_in, "app.")
    # One hop: the record and the distribution it names, and nothing further.
    first = _graph(signed_in, record, connection_id=prod)
    assert not first["truncated"]
    cdn = next(n for n in first["nodes"] if n["type"] == "aws_cloudfront_distribution")
    assert (record, cdn["uid"], "ROUTES_TO") in _edges(first)
    assert first["nodes"][0]["uid"] == record and first["nodes"][0]["expanded"]
    assert not cdn["expanded"]  # the map can expand it next
    assert not any(n["type"] == "aws_api_gatewayv2_api" for n in first["nodes"])
    # Expand, hop by hop, as the screen does.
    second = _graph(signed_in, cdn["uid"], connection_id=prod)
    api = next(n for n in second["nodes"] if n["type"] == "aws_api_gatewayv2_api")
    assert ("internet", cdn["uid"], "ROUTES_TO") in _edges(second)
    assert (cdn["uid"], api["uid"], "ROUTES_TO") in _edges(second)
    third = _graph(signed_in, api["uid"], connection_id=prod)
    function = _named(third, "prod-orders-api")
    assert (api["uid"], function["uid"], "ROUTES_TO") in _edges(third)
    # An external host is a pseudo-node, never dropped.
    status = _graph(signed_in, _record(signed_in, "status."), connection_id=prod)
    assert any(n["kind"] == "external" for n in status["nodes"])


def test_the_map_says_which_scans_it_shows(signed_in: TestClient, prod: int) -> None:
    today = datetime.now(UTC).date().isoformat()
    graph = _graph(signed_in, "internet", connection_id=prod)
    assert graph["days"] == {"rule_day": today, "cloudfox_day": today}
    assert graph["data_through"] == today
    # No past day: what the first map took is not part of the contract.
    old = signed_in.get(
        "/api/v1/map/graph",
        params={"focus": "internet", "connection_id": prod, "as_of": "2026-01-01"},
    ).json()
    assert old["data_through"] == today
    assert old["nodes"] == graph["nodes"] and old["edges"] == graph["edges"]


def test_a_connection_with_no_scan_has_an_empty_map(signed_in: TestClient, owner: Engine) -> None:
    empty = make_demo(owner, seed=2).connection_id
    graph = _graph(signed_in, "internet", connection_id=empty)
    assert graph["edges"] == [] and graph["groups"] == []
    assert graph["days"] == {"rule_day": None, "cloudfox_day": None}
    assert graph["data_through"] is None  # "no scan yet", never a day


def test_identity_lines_and_no_security_fact_on_a_node(signed_in: TestClient, prod: int) -> None:
    alb = _resource(signed_in, "edge-alb", connection_id=prod)
    # The edge ALB is found by our rule and by CloudFox: two lines from the internet.
    from_internet = _graph(
        signed_in, "internet", connection_id=prod, layer=["traffic"], map="security"
    )["edges"]
    assert {
        (e["type"], e["origin"].split(":")[0])
        for e in from_internet
        if e["source_uid"] == "internet" and e["target_uid"] == alb["resource_uid"]
    } == {("ROUTES_TO", "rule"), ("INTERNET_REACHABLE", "cloudfox")}
    # The ALB's target group routes to the API function, which runs as a role CloudFox says
    # can escalate to administrator.
    graph = _graph(signed_in, alb["resource_uid"])
    # One of its target groups holds the function: expand each, as a person would.
    beyond = [
        n
        for group in graph["nodes"]
        if group["type"] == "aws_ec2_target_group"
        for n in _graph(signed_in, group["uid"])["nodes"]
    ]
    function = next(n for n in beyond if (n["name"] or "").startswith("prod-orders-api"))
    assert function["kind"] == "resource" and function["resource_id"]
    near = _graph(signed_in, function["uid"], layer=["identity"])
    role = _named(near, "prod-orders-api-role")
    assert (function["uid"], role["uid"], "RUNS_AS") in _edges(near)
    further = _graph(signed_in, role["uid"], layer=["identity"], map="security")
    admin = next(n for n in further["nodes"] if n["kind"] == "admin")
    assert (role["uid"], admin["uid"], "CAN_PRIVESC_TO") in _edges(further)
    # The Resource Map draws how they connect, never the security judgement.
    plain = _graph(signed_in, role["uid"], layer=["identity"])
    assert not any(e["type"] in SECURITY_EDGE_TYPES for e in plain["edges"])
    assert not any(n["kind"] == "admin" for n in plain["nodes"])
    # Only the asked layers: no ROUTES_TO in an identity-only view.
    assert {e["type"] for g in (near, further) for e in g["edges"]} <= {
        "RUNS_AS",
        "CAN_ASSUME",
        "IS_ADMIN",
        "CAN_PRIVESC_TO",
        "MEMBER_OF",
        "BELONGS_TO",
    }
    # The Infrastructure view (ADR-0051): a node says what and where, nothing about findings,
    # vulnerabilities or reach.
    assert all(set(n) == NODE_FIELDS for g in (graph, near, further) for n in g["nodes"])
    # One hop: only the focus has had its neighbours read.
    assert [n["uid"] for n in near["nodes"] if n["expanded"]] == [function["uid"]]


def test_many_neighbours_of_one_kind_come_back_as_a_group(
    signed_in: TestClient, prod: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("argus.relationships.graph.GROUP_OVER", 1)
    graph = _graph(signed_in, "internet", connection_id=prod)
    # Any kind with more than one front door (GROUP_OVER is 1 here) comes back as a group.
    group = next(g for g in graph["groups"] if g["edge_type"] == "ROUTES_TO")
    assert group["anchor_uid"] == "internet" and group["direction"] == "out"
    assert group["count"] >= 2
    # Its members are not drawn one by one.
    types = {n["uid"]: n["type"] for n in graph["nodes"]}
    assert not any(
        e["source_uid"] == "internet"
        and e["type"] == "ROUTES_TO"
        and types.get(e["target_uid"]) == group["resource_type"]
        for e in graph["edges"]
    )
    query = {
        "anchor": "internet",
        "connection_id": prod,
        "direction": "out",
        "edge_type": "ROUTES_TO",
        "resource_type": group["resource_type"],
    }
    page = signed_in.get("/api/v1/map/group", params={**query, "limit": 2}).json()
    assert page["total"] == group["count"] and len(page["items"]) == 2
    assert page["data_through"] == datetime.now(UTC).date().isoformat()
    names = [i["node"]["name"] for i in page["items"]]
    assert names == sorted(names, key=str.lower)
    assert all(i["edge"]["source_uid"] == "internet" for i in page["items"])
    assert all(set(i["node"]) == NODE_FIELDS for i in page["items"])
    # The pages do not overlap, and one past the end is empty with the same total.
    rest = signed_in.get("/api/v1/map/group", params={**query, "limit": 100, "offset": 2}).json()
    first = {i["node"]["uid"] for i in page["items"]}
    assert first.isdisjoint(i["node"]["uid"] for i in rest["items"])
    assert len(first) + len(rest["items"]) == group["count"]


def test_the_map_walks_one_connection(
    signed_in: TestClient,
    prod: int,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
) -> None:
    """A read stays in its connection: a node such as `internet`, which every account has,
    shows only that connection's lines, and another connection's resource is a boundary node."""
    other = make_demo(owner, seed=1)
    for tool in TOOL_ORDER:
        run_tool(worker, store, other, tool, datetime.now(UTC).date())
    for cid in (prod, other.connection_id):
        graph = _graph(signed_in, "internet", connection_id=cid)
        assert graph["connection_id"] == cid
        resources = [n for n in graph["nodes"] if n["connection_id"] is not None]
        assert resources and {n["connection_id"] for n in resources if not n["boundary"]} == {cid}
        assert not any(n["expanded"] for n in graph["nodes"] if n["boundary"])
    # A resource's own connection is the default.
    resource = signed_in.get(
        "/api/v1/resources", params={"connection_id": other.connection_id, "limit": 1}
    ).json()["items"][0]
    assert _graph(signed_in, resource["resource_uid"])["connection_id"] == other.connection_id


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
    nowhere = {**scoped, "focus": "arn:aws:ec2:us-east-1:111111111111:instance/i-none"}
    assert signed_in.get("/api/v1/map/graph", params=nowhere).status_code == 404
    bad_graphs: list[dict[str, Any]] = [
        {**scoped, "layer": "bogus"},
        {**scoped, "origin": "probe"},
        {**scoped, "connection_id": 0},
        {**scoped, "focus": "x" * 2049},
        {**scoped, "depth": 0},
        {**scoped, "depth": 4},
        {**scoped, "map": "attack"},
    ]
    for params in bad_graphs:
        assert signed_in.get("/api/v1/map/graph", params=params).status_code == 422, params
    assert (
        signed_in.get("/api/v1/map/graph", params={**scoped, "connection_id": 999999}).status_code
        == 404
    )
    group = {"anchor": "internet", "connection_id": prod, "direction": "out"}
    bad_groups: list[dict[str, Any]] = [
        {**group, "edge_type": "ROUTES_TO; DROP"},
        {**group, "edge_type": "ROUTES_TO", "direction": "both"},
        {**group, "edge_type": "ROUTES_TO", "limit": 101},
        {**group, "edge_type": "ROUTES_TO", "offset": -1},
        {"anchor": "internet", "direction": "out", "edge_type": "ROUTES_TO"},
    ]
    for params in bad_groups:
        assert signed_in.get("/api/v1/map/group", params=params).status_code == 422, params


def test_the_map_needs_a_session(client: TestClient) -> None:
    for path in (
        "/api/v1/map/graph?focus=internet",
        "/api/v1/map/group?anchor=internet",
        "/api/v1/map/types",
        "/api/v1/map/resources",
        "/api/v1/map/resource/1",
    ):
        assert client.get(path).status_code == 401


def test_the_map_draws_connections_not_reach(
    signed_in: TestClient, prod: int, owner: Engine
) -> None:
    """The map shows dependencies and connections. The internet-facing ALB whose security group
    admits one address range is a door the rules judge closed (PUBLIC_RESTRICTED): the map draws
    only CloudFox's line to it, never the verdict, and no map edge carries the rules' evidence.
    The verdict and its evidence stay on the edge row, where the Resources sheet reads them
    (ADR-0035)."""
    graph = _graph(signed_in, "internet", connection_id=prod, layer=["traffic"], map="security")
    assert {e["type"] for e in graph["edges"]} <= {"ROUTES_TO", "TRIGGERS", "INTERNET_REACHABLE"}
    assert all(set(e["attributes"]) <= set(EDGE_ATTRIBUTES) for e in graph["edges"])
    admin = _named(graph, "prod-admin-alb")
    assert [
        (e["type"], e["origin"]) for e in graph["edges"] if e["target_uid"] == admin["uid"]
    ] == [("INTERNET_REACHABLE", "cloudfox")]
    with owner.connect() as conn:
        attributes = conn.execute(
            text(
                "SELECT attributes FROM edge WHERE source_uid = 'internet' "
                "AND type = 'PUBLIC_RESTRICTED' AND target_uid = :u"
            ),
            {"u": admin["uid"]},
        ).scalar_one()
    assert (attributes["reason"], attributes["sources"]) == (
        "sg_no_public_source",
        ["203.0.113.0/24"],
    )
    assert attributes["network"]  # the evidence, one entry per interface
    # A group page's edges are plain too.
    page = signed_in.get(
        "/api/v1/map/group",
        params={
            "anchor": "internet",
            "connection_id": prod,
            "direction": "out",
            "edge_type": "ROUTES_TO",
            "resource_type": admin["type"],
            "limit": 20,
        },
    ).json()
    assert all(set(i["edge"]["attributes"]) <= set(EDGE_ATTRIBUTES) for i in page["items"])


def test_three_hops_in_one_read_and_the_walk_stops_at_pseudo_nodes(
    signed_in: TestClient, prod: int
) -> None:
    record = _record(signed_in, "app.")
    deep = _graph(signed_in, record, connection_id=prod, depth=3)
    by_type = {n["type"]: n for n in deep["nodes"]}
    cdn, api = by_type["aws_cloudfront_distribution"], by_type["aws_api_gatewayv2_api"]
    # record -> distribution -> API -> function: three hops, one request.
    assert (record, cdn["uid"], "ROUTES_TO") in _edges(deep)
    assert (cdn["uid"], api["uid"], "ROUTES_TO") in _edges(deep)
    assert any(e["source_uid"] == api["uid"] for e in deep["edges"])
    assert record in {n["uid"] for n in deep["nodes"] if n["expanded"]}
    assert cdn["expanded"] and api["expanded"]
    # `internet` reaches the distribution, so it is drawn at hop two, and never walked past:
    # its only lines are to resources the walk expanded, never to its other front doors.
    expanded = {n["uid"] for n in deep["nodes"] if n["expanded"]}
    internet = next(n for n in deep["nodes"] if n["uid"] == "internet")
    assert not internet["expanded"]
    assert all(e["target_uid"] in expanded for e in deep["edges"] if e["source_uid"] == "internet")
    # Every node met is drawn once, and the default depth is one hop.
    assert len({n["uid"] for n in deep["nodes"]}) == len(deep["nodes"])
    one = _graph(signed_in, record, connection_id=prod)
    assert [n["uid"] for n in one["nodes"] if n["expanded"]] == [record]


def test_the_resource_map_never_draws_a_security_line(signed_in: TestClient, prod: int) -> None:
    every = ["traffic", "identity", "network", "policy", "data"]
    security_types = set(SECURITY_EDGE_TYPES)
    plain = _graph(signed_in, "internet", connection_id=prod, layer=every, depth=3)
    assert not any(e["type"] in security_types for e in plain["edges"])
    assert not any(g["edge_type"] in security_types for g in plain["groups"])
    secure = _graph(signed_in, "internet", connection_id=prod, layer=every, depth=3, map="security")
    assert any(e["type"] in security_types for e in secure["edges"])
    # A group of a security line has no members on the Resource Map: the same group, with a
    # real member type, lists them on the Security Map.
    types = {n["uid"]: n["type"] for n in secure["nodes"]}
    reached = next(
        types[e["target_uid"]]
        for e in secure["edges"]
        if e["type"] == "INTERNET_REACHABLE" and types.get(e["target_uid"])
    )
    group = {
        "anchor": "internet",
        "connection_id": prod,
        "direction": "out",
        "edge_type": "INTERNET_REACHABLE",
        "resource_type": reached,
    }
    shown = signed_in.get("/api/v1/map/group", params={**group, "map": "security"}).json()
    assert shown["total"] > 0 and shown["items"]
    hidden = signed_in.get("/api/v1/map/group", params=group).json()
    assert hidden["total"] == 0 and hidden["items"] == []


# Words a Resource Map response must never carry: a finding, a vulnerability, reach, risk or a
# CloudFox loot command (owner, 2026-11-13: "Leave out").
SECURITY_WORDS = (
    "finding",
    "severity",
    "vulnerab",
    "cve",
    "exploit",
    "reach",
    "risk",
    "command",
    "loot",
    "door",
    "verdict",
    "misconfig",
)


def _field_names(model: Any, seen: set[Any] | None = None) -> set[str]:
    seen = seen if seen is not None else set()
    if model in seen or not hasattr(model, "model_fields"):
        return set()
    seen.add(model)
    names: set[str] = set()
    for name, info in model.model_fields.items():
        names.add(name)
        for arg in getattr(info.annotation, "__args__", ()) or ():
            names |= _field_names(arg, seen)
            for inner in getattr(arg, "__args__", ()) or ():
                names |= _field_names(inner, seen)
        names |= _field_names(info.annotation, seen)
    return names


def test_the_plain_routes_carry_no_security_field() -> None:
    for model in (
        resource_map.MapTypesOut,
        resource_map.MapResourcePage,
        resource_map.MapResource,
        resource_map.MapGraph,
        resource_map.GroupPage,
    ):
        names = _field_names(model)
        assert names, model
        leaked = {n for n in names for w in SECURITY_WORDS if w in n.lower()}
        assert not leaked, (model.__name__, leaked)


def test_the_resource_maps_start_search_and_panel(signed_in: TestClient, prod: int) -> None:
    today = datetime.now(UTC).date().isoformat()
    types = signed_in.get("/api/v1/map/types", params={"connection_id": prod}).json()
    summary = signed_in.get("/api/v1/resources/summary", params={"connection_id": prod}).json()
    assert types["by_type"] == summary["by_type"]  # one count, two screens
    assert types["data_through"] == today
    kind = types["by_type"][0]["type"]
    page = signed_in.get(
        "/api/v1/map/resources", params={"type": kind, "connection_id": prod, "limit": 5}
    ).json()
    listed = signed_in.get(
        "/api/v1/resources", params={"type": kind, "connection_id": prod, "limit": 5}
    ).json()
    assert [r["id"] for r in page["items"]] == [r["id"] for r in listed["items"]]
    assert page["total"] == listed["total"]
    assert set(page["items"][0]) == set(resource_map.ResourceOut.model_fields)
    found = signed_in.get("/api/v1/map/resources", params={"q": "edge-alb"}).json()
    alb = next(r for r in found["items"] if (r["name"] or "").endswith("edge-alb"))
    panel = signed_in.get(f"/api/v1/map/resource/{alb['id']}").json()
    full = signed_in.get(f"/api/v1/resources/{alb['id']}").json()
    assert panel["resource_uid"] == alb["resource_uid"]
    assert panel["config"] == full["config"] and panel["tags"] == full["tags"]
    assert panel["data_through"] == today
    # Its lines are the Resource Map's: no security type, no verdict, no evidence.
    assert {e["type"] for e in full["edges"]} & {"INTERNET_REACHABLE"}
    assert not any(e["type"] in SECURITY_EDGE_TYPES for e in panel["edges"])
    assert not any(e["type"].startswith("PUBLIC_") for e in panel["edges"])
    assert all(set(e["attributes"]) <= set(EDGE_ATTRIBUTES) for e in panel["edges"])
    assert signed_in.get("/api/v1/map/resource/999999999").status_code == 404
