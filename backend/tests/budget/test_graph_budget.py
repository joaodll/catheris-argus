"""The graph read model's budget (ADR-0044): how long Memgraph takes to be rebuilt from Postgres,
to re-sync one connection, to be verified, and to evaluate the attack paths across every
account (round M2), on a skewed estate (graph_estate.py: 300,000 resources over 36 accounts by
default).

Opt-in, because it generates its own estate (minutes) and no API query reads the graph. It
needs a Postgres with more memory than compose.yaml's development 1 GiB (on 2026-10-31 a backend
was killed generating 300,000 resources there); the spike measured 1M on 8 GiB:
    ARGUS_GRAPH_BUDGET=1 docker compose run --rm test pytest tests/budget/test_graph_budget.py -s
    (ARGUS_GRAPH_BUDGET_RESOURCES=1000000 for the 12-24 month target)
"""

import os
import time

import pytest
from sqlalchemy import Engine, text
from tests.budget import graph_estate
from tests.conftest import RULES_DIR

from argus import graph
from argus.graph import client

pytestmark = [
    pytest.mark.db,
    pytest.mark.graph,
    pytest.mark.skipif(
        not os.environ.get("ARGUS_GRAPH_BUDGET"), reason="opt-in: ARGUS_GRAPH_BUDGET=1"
    ),
]
# Ceilings at the default 300,000 resources; scaled with the estate's size.
SCALE = graph_estate.RESOURCES / 300_000
REBUILD_S = 300 * SCALE
LARGEST_SYNC_S = 30 * SCALE
VERIFY_S = 60 * SCALE
EVALUATE_S = 300 * SCALE


def test_rebuild_resync_verify_and_paths_within_budget(migrated: Engine) -> None:
    with migrated.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE connection, scan_run, resource, resource_config, edge, audit_log "
                "RESTART IDENTITY CASCADE"
            )
        )
    print(f"\nestate: {graph_estate.generate(migrated)}")
    with client.write_session() as session:
        session.run("MATCH (n) DETACH DELETE n").consume()

    started = time.perf_counter()
    done = graph.reconcile(migrated, today=graph_estate.TODAY)
    rebuild = time.perf_counter() - started
    assert done == {"synced": graph_estate.ACCOUNTS, "failed": 0, "removed": 0}

    started = time.perf_counter()
    assert graph.reconcile(migrated, today=graph_estate.TODAY) == {
        "synced": 0,
        "failed": 0,
        "removed": 0,
    }
    noop = time.perf_counter() - started

    with migrated.begin() as conn:
        largest, edges = conn.execute(
            text(
                "SELECT connection_id, edge_count FROM graph_projection "
                "ORDER BY edge_count DESC LIMIT 1"
            )
        ).one()
        conn.execute(
            text(
                "UPDATE graph_projection SET status = 'failed', error = 'budget' "
                "WHERE connection_id = :c"
            ),
            {"c": largest},
        )
    started = time.perf_counter()
    graph.reconcile(migrated, today=graph_estate.TODAY)
    resync = time.perf_counter() - started

    started = time.perf_counter()
    assert graph.verify(migrated, today=graph_estate.TODAY) == {
        "checked": graph_estate.ACCOUNTS,
        "drifted": 0,
    }
    verify = time.perf_counter() - started

    started = time.perf_counter()
    paths = graph.evaluate_paths(migrated, today=graph_estate.TODAY, rules_dir=RULES_DIR)
    evaluate = time.perf_counter() - started
    assert paths is not None and paths["paths"] > 0
    with migrated.connect() as conn:
        crossing = conn.execute(
            text("SELECT count(*) FROM attack_path WHERE cardinality(connection_ids) > 1")
        ).scalar_one()

    print(
        f"graph budget at {graph_estate.RESOURCES:,} resources: full rebuild {rebuild:.1f} s, "
        f"no-op reconcile {noop:.2f} s, re-sync of the largest connection ({edges:,} edges) "
        f"{resync:.1f} s, verify {verify:.1f} s, attack paths {evaluate:.1f} s "
        f"({paths['paths']:,} paths, {crossing:,} across accounts, {paths['cut']:,} cut)"
    )
    assert rebuild < REBUILD_S
    assert resync < LARGEST_SYNC_S
    assert verify < VERIFY_S
    assert evaluate < EVALUATE_S
