"""Flow mode (ADR-0036): from each internet entry, the whole chain, computed in ingest.

The prod demo's chain: Route53 app.<zone> -> CloudFront -> HTTP API -> orders-api function, which
uses its role to read and write the orders table and send to the orders queue; the queue
triggers the worker and a pipe to the fulfil state machine."""

from datetime import UTC, date, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import TOOL_ORDER, FilesystemRawStore
from argus.relationships import flows as flows_module

pytestmark = pytest.mark.db


@pytest.fixture
def prod(owner: Engine, worker: Engine, store: FilesystemRawStore) -> int:
    target = make_demo(owner)
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, datetime.now(UTC).date())
    return target.connection_id


def _flow(client: TestClient, connection_id: int, entry_type: str, **params: object) -> dict:
    """The flow of the first front door of this type: the doors list is where flows start."""
    page = client.get(
        "/api/v1/map/front-doors", params={"connection_id": connection_id, "limit": 100, **params}
    ).json()
    door = next(d for d in page["items"] if d["node"]["type"] == entry_type)
    detail = client.get(f"/api/v1/map/flows/{door['flow_id']}").json()
    return {"door": door, "page": page, **detail}


def test_the_front_door_chain_is_one_flow(signed_in: TestClient, prod: int) -> None:
    flow = _flow(signed_in, prod, "aws_cloudfront_distribution")
    by_uid = {n["uid"]: n for n in flow["nodes"]}
    named = {n["name"]: n for n in flow["nodes"] if n["name"]}
    steps = {(s["source_uid"], s["target_uid"], s["kind"]) for s in flow["steps"]}
    cdn = flow["entry_uid"]
    record = next(n for n in flow["nodes"] if n["type"] == "aws_route53_record")
    api = next(n for n in flow["nodes"] if n["type"] == "aws_api_gatewayv2_api")
    fn = next(n for name, n in named.items() if name.endswith("orders-api"))
    table = next(
        n
        for name, n in named.items()
        if name.endswith("-orders") and n["type"] == "aws_dynamodb_table"
    )
    # Internet -> record -> CloudFront -> API -> function -> (via its role) -> table.
    assert ("internet", record["uid"], "dns") in steps
    assert (record["uid"], cdn, "edge") in steps
    assert (cdn, api["uid"], "edge") in steps
    assert (api["uid"], fn["uid"], "edge") in steps
    uses = next(
        s for s in flow["steps"] if s["source_uid"] == fn["uid"] and s["target_uid"] == table["uid"]
    )
    assert uses["kind"] == "uses" and uses["via_uid"].endswith("orders-api-role")
    # Columns grow left to right.
    col = {s["target_uid"]: s["col"] for s in flow["steps"] if s["target_uid"]}
    assert col[record["uid"]] < col[cdn] < col[api["uid"]] < col[fn["uid"]] < col[table["uid"]]
    # The role is a chip on the function, not a node of the flow.
    chips = {(c["node_uid"], c["kind"]) for c in flow["chips"]}
    assert (fn["uid"], "role") in chips
    assert not any(n["type"] == "aws_iam_role" for n in by_uid.values())
    assert flow["reach"] == "open" and not flow["truncated"]
    assert all(e["id"] in {i for s in flow["steps"] for i in s["edge_ids"]} for e in flow["edges"])


def test_a_cname_chain_is_drawn_record_by_record(signed_in: TestClient, prod: int) -> None:
    """shop CNAME www, an alias to the edge load balancer (argus_v12)."""
    flow = _flow(signed_in, prod, "aws_ec2_application_load_balancer", reach=["open"])
    names = {n["uid"]: (n["name"] or "").split(".")[0] for n in flow["nodes"]}
    names["internet"] = "internet"
    steps = [
        (s["col"], s["kind"], names[s["source_uid"]], names[s["target_uid"]])
        for s in flow["steps"]
        if s["col"] <= 3
    ]
    alb = names[flow["entry_uid"]]
    assert steps == [
        (1, "dns", "internet", "shop"),
        (2, "edge", "shop", "www"),
        (3, "edge", "www", alb),
    ]


def test_restricted_entries_have_flows_of_their_own(signed_in: TestClient, prod: int) -> None:
    flow = _flow(signed_in, prod, "aws_ec2_application_load_balancer", reach=["restricted"])
    assert flow["door"]["node"]["name"].endswith("admin-alb")
    assert flow["reach"] == flow["door"]["reach"] == "restricted"
    assert flow["door"]["resources"] >= 1 and not flow["door"]["truncated"]


def test_a_rerun_reuses_shapes_and_replaces_the_day(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    day = date(2026, 10, 9)
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", day)
    tables = ("flow", "flow_shape", "flow_step", "flow_chip", "flow_snapshot")

    def counts() -> dict[str, int]:
        with owner.connect() as conn:
            return {t: conn.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() for t in tables}  # noqa: S608

    first = counts()
    assert first["flow"] == first["flow_snapshot"] > 0
    run_tool(worker, store, target, "steampipe", day)
    assert counts() == first
    run_tool(worker, store, target, "steampipe", date(2026, 10, 10))
    after = counts()
    with owner.connect() as conn:
        by_day = dict(
            conn.execute(text("SELECT snapshot_date, count(*) FROM flow_snapshot GROUP BY 1")).all()
        )
        shared = conn.execute(
            text("""
                SELECT count(*) FROM flow_snapshot a JOIN flow_snapshot b
                  ON b.flow_id = a.flow_id AND b.shape_id = a.shape_id
                WHERE a.snapshot_date = :a AND b.snapshot_date = :b
            """),
            {"a": day, "b": date(2026, 10, 10)},
        ).scalar_one()
    # The first day is kept; the next day's unchanged flows point to the same shapes (the
    # synthetic estate churns a little, so not every one).
    assert by_day[day] == first["flow_snapshot"] and by_day[date(2026, 10, 10)] > 0
    assert shared > by_day[day] // 2
    assert after["flow_shape"] < first["flow_shape"] + by_day[date(2026, 10, 10)]


def test_fan_out_becomes_a_group_and_caps_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    edges = flows_module._Edges()
    edges.add(1, "internet", "lb", "ROUTES_TO")
    for i in range(30):
        edges.add(10 + i, "lb", f"i-{i:02}", "ROUTES_TO")
    edges.add(99, "lb", "fn", "ROUTES_TO")
    edges.add(100, "fn", "fn", "TRIGGERS")  # a cycle: never drawn
    types = {f"i-{i:02}": "aws_ec2_instance" for i in range(30)} | {"fn": "aws_lambda_function"}
    depths = {"lb": 0, "fn": 1} | {f"i-{i:02}": 1 for i in range(30)}
    flow = flows_module._shape("lb", "open", depths, edges, types)
    steps, count, truncated = flow.steps, flow.node_count, flow.truncated
    group = next(s for s in steps if s.kind == "group")
    assert (group.source, group.group_type, group.group_count) == ("lb", "aws_ec2_instance", 30)
    assert [(s.source, s.target) for s in steps if s.kind == "edge"] == [
        ("internet", "lb"),
        ("lb", "fn"),
    ]
    assert count == 2 and not truncated
    monkeypatch.setattr(flows_module, "MAX_DRAWN", 1)
    assert flows_module._shape("lb", "open", depths, edges, types).truncated


def test_a_dns_chain_is_drawn_back_to_the_outermost_record() -> None:
    """www CNAME shop CNAME app, an alias to the load balancer (argus_v12): every record in
    order, one column per hop; a record naming one nearer the internet (a cycle) and a
    distribution routing to the same door are not part of the chain."""
    edges = flows_module._Edges()
    edges.add(1, "internet", "alb", "ROUTES_TO")
    edges.add(2, "app", "alb", "ROUTES_TO")
    edges.add(3, "shop", "app", "ROUTES_TO")
    edges.add(4, "www", "shop", "ROUTES_TO")
    edges.add(5, "app", "www", "ROUTES_TO")
    edges.add(6, "cdn", "alb", "ROUTES_TO")
    record = "aws_route53_record"
    types: dict[str, str | None] = {
        "app": record,
        "shop": record,
        "www": record,
        "cdn": "aws_cloudfront_distribution",
        "alb": "aws_ec2_application_load_balancer",
    }
    flow = flows_module._shape("alb", "open", {"alb": 0}, edges, types)
    steps = [(s.col, s.kind, s.source, s.target) for s in flow.steps]
    assert steps == [
        (1, "dns", "internet", "www"),
        (2, "edge", "www", "shop"),
        (3, "edge", "shop", "app"),
        (4, "edge", "app", "alb"),
    ]
    assert flow.node_count == 4 and flow.depth == 4
