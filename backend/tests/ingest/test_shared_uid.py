"""A resource uid has one owning connection (ADR-0034).

The first real AWS run failed with a duplicate key on resource_snapshot (2026-10-09): a uid
already owned by another connection, with a snapshot row that day, was inserted again. Every
retry that day failed the same way.
"""

from dataclasses import replace
from datetime import date

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo

from argus.inventory import load_inventory
from argus.inventory.load import OWNED_ELSEWHERE
from argus.inventory.steampipe import InventoryBatch, InventoryResource, config_hash
from argus.relationships import DerivedEdge, load_edges

pytestmark = pytest.mark.db
DAY = date(2026, 10, 9)
SHARED = "arn:aws:apigateway:us-east-1::/domainnames/shared.example.com"


def _resource(uid: str, note: str) -> InventoryResource:
    config = {"domain_name": uid.rsplit("/", 1)[-1], "note": note}
    return InventoryResource(
        uid=uid,
        type="aws_api_gateway_domain_name",
        region="us-east-1",
        native_id=uid.rsplit("/", 1)[-1],
        name=None,
        vpc_id=None,
        tags={},
        config=config,
        config_hash=config_hash(config),
    )


def _batch(*resources: InventoryResource) -> InventoryBatch:
    return InventoryBatch(
        resources=list(resources),
        tables_seen=frozenset({"aws_api_gateway_domain_name"}),
        complete=True,
    )


def _load(worker: Engine, connection_id: int, batch: InventoryBatch) -> dict[str, int]:
    with worker.begin() as conn:
        return load_inventory(conn, batch=batch, connection_id=connection_id, day=DAY)


@pytest.mark.parametrize("first", [0, 1], ids=["a-first", "b-first"])
def test_a_uid_two_connections_report_stays_with_its_first_owner(
    owner: Engine, worker: Engine, first: int
) -> None:
    targets = [make_demo(owner, seed=1), make_demo(owner, seed=2)]
    a, b = targets[first], targets[1 - first]
    own_a = _resource(f"arn:aws:apigateway:us-east-1::/domainnames/a-{first}.example.com", "a")
    own_b = _resource(f"arn:aws:apigateway:us-east-1::/domainnames/b-{first}.example.com", "b")
    _load(worker, a.connection_id, _batch(_resource(SHARED, "as a sees it"), own_a))
    stats = _load(worker, b.connection_id, _batch(_resource(SHARED, "as b sees it"), own_b))
    # Re-runs of the same day, in both orders: the failing case before ADR-0034.
    _load(worker, a.connection_id, _batch(_resource(SHARED, "as a sees it"), own_a))
    again = _load(worker, b.connection_id, _batch(_resource(SHARED, "as b sees it"), own_b))

    assert stats["owned_elsewhere"] == again["owned_elsewhere"] == 1
    assert stats["snapshot_rows"] == again["snapshot_rows"] == 1
    with owner.connect() as conn:
        owner_id, note = conn.execute(
            text(
                "SELECT r.connection_id, rc.config->>'note' FROM resource r "
                "JOIN resource_config rc ON rc.id = r.config_id WHERE r.resource_uid = :u"
            ),
            {"u": SHARED},
        ).one()
        snapshots = conn.execute(
            text(
                "SELECT count(*) FROM resource_snapshot s JOIN resource r ON r.id = s.resource_id "
                "WHERE r.resource_uid = :u AND s.snapshot_date = :d"
            ),
            {"u": SHARED, "d": DAY},
        ).scalar_one()
        unresolved = conn.execute(
            text("SELECT connection_id, reason FROM unresolved_ref WHERE raw_ref = :u"),
            {"u": SHARED},
        ).all()
    assert (owner_id, note) == (a.connection_id, "as a sees it")
    assert snapshots == 1
    assert [(r.connection_id, r.reason) for r in unresolved] == [(b.connection_id, OWNED_ELSEWHERE)]


def test_two_connections_deriving_the_same_edge_each_keep_their_own(
    owner: Engine, worker: Engine
) -> None:
    a, b = make_demo(owner, seed=1), make_demo(owner, seed=2)
    edge = DerivedEdge("internet", SHARED, "ROUTES_TO", "rule:internet-entry@1", {})
    for target in (a, b, a):
        with worker.begin() as conn:
            loaded = load_edges(
                conn,
                edges=[replace(edge)],
                connection_id=target.connection_id,
                day=DAY,
                origin_prefix="rule:",
            )
        assert loaded == 1
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT e.connection_id, count(s.edge_id) FROM edge e "
                "LEFT JOIN edge_snapshot s ON s.edge_id = e.id AND s.snapshot_date = :d "
                "GROUP BY 1 ORDER BY 1"
            ),
            {"d": DAY},
        ).all()
    assert [tuple(r) for r in rows] == sorted([(a.connection_id, 1), (b.connection_id, 1)])
