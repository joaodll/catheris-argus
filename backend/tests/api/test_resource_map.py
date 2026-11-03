"""Investigate -> Resource map and Attack paths (ADR-0033) over the synthetic prod estate, whose
front-door chain runs Route53 -> CloudFront -> HTTP API -> function -> role -> admin. The map
draws connections, not reach (round M3a)."""

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from neo4j.exceptions import ClientError, ServiceUnavailable, SessionExpired, TransientError
from sqlalchemy import Engine, text
from tests.conftest import Settle
from tests.ingest.conftest import make_demo, run_tool

from argus import graph
from argus.collection import TOOL_ORDER, CollectTarget
from argus.collection.synthetic.estate import SCENARIO_INSTANCE
from argus.connections import demo_account_id
from argus.core.rawstore import FilesystemRawStore
from argus.graph import client
from argus.relationships import EDGE_ATTRIBUTES, MapScope

pytestmark = [pytest.mark.db, pytest.mark.graph]


@pytest.fixture
def prod(owner: Engine, worker: Engine, store: FilesystemRawStore, settle: Settle) -> int:
    target = make_demo(owner)  # seed 0: the prod profile
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, datetime.now(UTC).date())
    settle(datetime.now(UTC).date())  # the graph loop's evaluation (ADR-0044, M2)
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


def test_the_chain_from_a_dns_record_down_to_the_function(
    signed_in: TestClient, prod: int, owner: Engine
) -> None:
    # A DNS record names an entry; it is not one (ADR-0035). Only a record whose chain ends
    # outside what Argus judges is a door, unknown (argus_v12): rest, an API custom domain
    # (which API it serves is not collected), and status, a vendor's host. The rule draws it;
    # the map does not (a verdict, not a connection: round M3a), Attack paths and Findings do.
    with owner.connect() as conn:
        unknown = {
            r.name.split(".")[0]: r.missing
            for r in conn.execute(
                text("""
                SELECT r.name, e.attributes -> 'missing' ->> 0 AS missing
                FROM edge e JOIN resource r ON r.id = e.target_resource_id
                WHERE e.source_uid = 'internet' AND e.type = 'PUBLIC_UNVERIFIED'
                  AND r.type = 'aws_route53_record' AND e.connection_id = :c
            """),
                {"c": prod},
            )
        }
    assert sorted(unknown) == ["rest", "status"]
    assert unknown["rest"].startswith("dns_target:arn:aws:apigateway:")
    assert unknown["status"].startswith("dns_target:external:status.")
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
    alb = _resource(signed_in, "edge-alb", connection_id=prod)
    # The edge ALB is found by our rule and by CloudFox: two lines from the internet.
    from_internet = _graph(signed_in, "internet", connection_id=prod, layer=["traffic"])["edges"]
    assert {
        (e["type"], e["origin"].split(":")[0])
        for e in from_internet
        if e["source_uid"] == "internet" and e["target_uid"] == alb["resource_uid"]
    } == {("ROUTES_TO", "rule"), ("INTERNET_REACHABLE", "cloudfox")}
    # The ALB's target group routes to the API function, which runs as a role CloudFox says
    # can escalate to administrator.
    graph = _graph(signed_in, alb["resource_uid"], depth=3)
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
    monkeypatch.setattr("argus.graph.resource_map.GROUP_OVER", 1)
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
    settle: Settle,
) -> None:
    """Depth used to reach other connections through shared nodes such as `internet`
    (argus_v10); another connection's resource is now a boundary node, never expanded."""
    other = make_demo(owner, seed=1)
    for tool in TOOL_ORDER:
        run_tool(worker, store, other, tool, datetime.now(UTC).date())
    settle(datetime.now(UTC).date())
    for cid in (prod, other.connection_id):
        graph = _graph(signed_in, "internet", connection_id=cid, depth=3)
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
    monkeypatch.setattr("argus.graph.resource_map.MAX_NODES", 3)
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
    assert page["not_listed"] == {"paths": 0, "latent": 0, "worst": None}
    # The scenario's chain to administrator; the exposed doors are one-step paths of their own
    # (ADR-0037, second amendment).
    top = next(p for p in page["items"] if p["rule_id"] == "internet-to-admin")
    assert top["severity"] == "critical" and top["rule_name"]
    assert "cloudfox" in top["evidence"] and "rule" in top["evidence"]
    assert top["base_severity"] == "high" and top["entry_confirmed"] is True
    # Inside one account: the entry's connection is the only one (ADR-0044, M2).
    assert top["accounts"] == [{"connection_id": prod, "name": top["connection"]}]
    # Evaluated from the newest scans: nothing to say about the graph.
    assert page["graph"]["behind"] is False and page["graph"]["failed"] is False
    assert page["graph"]["evaluated_at"]
    passing = signed_in.get(
        "/api/v1/attack-paths", params={"connection_id": prod, "passing_through": True}
    ).json()
    assert passing["total"] == page["total"]
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
    assert detail["scanned"] == {
        "steampipe": today,
        "prowler": today,
        "cloudfox": today,
        "vulnerabilities": today,
    }


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


def test_the_map_draws_connections_not_reach(
    signed_in: TestClient, prod: int, owner: Engine
) -> None:
    """Round M3a (the owner's decision, 2026-11-01): the map shows dependencies and connections.
    argus_v10's internet-facing ALB whose security group admits one address range is a door the
    rules judge closed (PUBLIC_RESTRICTED): the map draws only CloudFox's line to it, never the
    verdict, and no map edge carries the rules' evidence. The verdict and its evidence stay on
    the edge row, where Attack paths and the Resources sheet read them (ADR-0035)."""
    graph = _graph(signed_in, "internet", connection_id=prod, layer=["traffic"])
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
    assert attributes["network"]  # the evidence, one entry per interface (fifth amendment)
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


@pytest.mark.parametrize(
    "failure",
    [
        ServiceUnavailable("connection refused"),
        SessionExpired("gone"),
        TransientError("transaction timed out"),
        ClientError("failed to obtain a connection from the pool within 5.0s (timeout)"),
        client.GraphNotConfigured("no password"),
    ],
    ids=["down", "session-lost", "over-its-timeout", "pool-full", "no-login"],
)
def test_the_map_says_so_when_the_graph_cannot_answer(
    signed_in: TestClient, prod: int, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    """ADR-0044, M-1: 503 with Retry-After, never an empty map, and nothing of the error."""

    def fails(*_args: Any, **_kwargs: Any) -> Any:
        raise failure

    monkeypatch.setattr(client, "read", fails)
    for path, params in (
        ("/api/v1/map/graph", {"focus": "internet", "connection_id": prod}),
        (
            "/api/v1/map/group",
            {"anchor": "internet", "connection_id": prod, "direction": "out", "edge_type": "X"},
        ),
    ):
        answer = signed_in.get(path, params=params)
        assert answer.status_code == 503
        assert answer.headers["Retry-After"]
        assert answer.json() == {"detail": "the graph is unavailable; try again shortly"}


def test_a_wrong_query_is_a_bug_and_not_an_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    def fails(*_args: Any, **_kwargs: Any) -> Any:
        raise ClientError("syntax error")

    monkeypatch.setattr(client, "read", fails)
    with pytest.raises(ClientError):
        graph.neighbourhood(
            None,  # type: ignore[arg-type]
            focus="internet",
            scope=MapScope(1, "100000000010"),
            depth=1,
        )


def test_a_node_carries_its_facts_and_the_counts_match_their_screens(
    signed_in: TestClient, owner: Engine, prod: int
) -> None:
    """The overlay (ADR-0044, M-5): stored facts only, and each number is what its link lists."""
    with owner.connect() as conn:
        path = conn.execute(
            text(
                "SELECT entry_uid, target_uid FROM attack_path WHERE state = 'open' "
                "AND confidence IS DISTINCT FROM 'blocked' AND entry_uid <> target_uid LIMIT 1"
            )
        ).one()
        cve = conn.execute(
            text(
                "SELECT r.resource_uid, count(*) AS n, "
                "count(*) FILTER (WHERE v.exploit_available) AS exploitable "
                "FROM finding f JOIN resource r ON r.id = f.resource_id "
                "LEFT JOIN finding_vulnerability v ON v.finding_id = f.id "
                "WHERE f.tool = 'vulnerabilities' AND f.state IN ('open', 'reopened') "
                "AND r.connection_id = :c GROUP BY 1 LIMIT 1"
            ),
            {"c": prod},
        ).first()
    entry = _graph(signed_in, path.entry_uid, connection_id=prod)["nodes"][0]
    listed = signed_in.get("/api/v1/attack-paths", params={"through": path.entry_uid}).json()
    assert entry["attack_paths"]["on"] == listed["total"] > 0
    assert entry["attack_paths"]["entry"] >= 1
    if cve is not None:
        node = _graph(signed_in, cve.resource_uid, connection_id=prod)["nodes"][0]
        assert node["vulnerabilities"]["open"] == cve.n
        assert node["vulnerabilities"]["exploitable"] == cve.exploitable
    # Nothing to say about the internet, and no fact is a zero.
    internet = _graph(signed_in, "internet", connection_id=prod)["nodes"][0]
    assert internet["attack_paths"] is None and internet["vulnerabilities"] is None


def test_the_map_says_how_current_it_is(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    prod: int,
) -> None:
    """ADR-0044, M-3: the days its state was projected from, and whether a newer scan waits."""

    def state() -> dict[str, Any]:
        answer = _graph(signed_in, "internet", connection_id=prod)
        assert isinstance(answer["graph"], dict)
        assert "as_of" not in answer
        return answer["graph"]

    today = datetime.now(UTC).date()
    current = state()
    assert (current["behind"], current["failed"]) == (False, False)
    assert current["resource_day"] == today.isoformat()
    target = CollectTarget(prod, "demo", demo_account_id(0), 0)
    run_tool(worker, store, target, "prowler", today)  # not in the graph yet
    assert state()["behind"] is True
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE graph_projection SET status = 'failed', error = 'test' "
                "WHERE connection_id = :c"
            ),
            {"c": prod},
        )
    assert state()["failed"] is True
