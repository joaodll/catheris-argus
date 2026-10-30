"""edge_load (migration 0016): the day each edge family was loaded, which effective_days
reads. A load with no edges counts: an account whose edges all went away shows none."""

from datetime import date, timedelta

import pytest
from sqlalchemy import Engine
from tests.ingest.conftest import make_demo

from argus import relationships
from argus.relationships import DerivedEdge

pytestmark = pytest.mark.db
DAY = date(2026, 9, 10)
EDGE = DerivedEdge("internet", "arn:aws:s3:::b", "ROUTES_TO", "rule:internet-entry@1", {})


def test_each_load_records_its_day_even_without_edges(owner: Engine, worker: Engine) -> None:
    cid = make_demo(owner).connection_id
    with worker.begin() as conn:
        relationships.load_edges(
            conn, edges=[EDGE], connection_id=cid, day=DAY, origin_prefix="rule:"
        )
        assert relationships.effective_days(
            conn, connection_id=cid, day=DAY + timedelta(days=3)
        ) == {
            "rule_day": DAY,
            "cloudfox_day": None,
        }
        later = DAY + timedelta(days=2)
        relationships.load_edges(
            conn, edges=[], connection_id=cid, day=later, origin_prefix="rule:"
        )
        assert relationships.effective_days(conn, connection_id=cid, day=later)["rule_day"] == later
        # Before the window's start, nothing stands.
        far = DAY + timedelta(days=40)
        assert relationships.effective_days(conn, connection_id=cid, day=far)["rule_day"] is None
        assert relationships.delete_loads_before(conn, cutoff=later) == 1
