from datetime import date, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus.collection import CollectOptions, FilesystemRawStore, collect, source_for
from argus.collection.synthetic.estate import SCENARIO_INSTANCE, SCENARIO_ROLE, SCENARIO_SG
from argus.ingest import ingest_run, register_run
from argus.relationships import load_rules

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def test_steampipe_run_loads_inventory_and_snapshot(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    outcome = run_tool(worker, store, target, "steampipe", DAY)
    assert outcome.status == "complete"
    resources = _count(owner, "SELECT count(*) FROM resource")
    assert resources == outcome.loaded["resources"] > 100
    assert (
        _count(owner, "SELECT count(*) FROM resource_snapshot WHERE snapshot_date = :d", d=DAY)
        == resources
    )
    assert _count(owner, "SELECT count(*) FROM scan_run WHERE ingested_at IS NULL") == 0


def test_replaying_a_run_changes_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    outcome = run_tool(worker, store, target, "steampipe", DAY)
    tables = ("resource", "resource_config", "resource_snapshot", "edge", "edge_snapshot")
    before = {t: _count(owner, f"SELECT count(*) FROM {t}") for t in tables}  # noqa: S608
    ingest_run(worker, store=store, scan_run_id=outcome.scan_run_id, rules_dir=RULES_DIR)
    after = {t: _count(owner, f"SELECT count(*) FROM {t}") for t in tables}  # noqa: S608
    assert before == after


def test_unchanged_configurations_are_stored_once(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    configs_day1 = _count(owner, "SELECT count(*) FROM resource_config")
    run_tool(worker, store, target, "steampipe", DAY + timedelta(days=1))
    configs_day2 = _count(owner, "SELECT count(*) FROM resource_config")
    assert configs_day2 < configs_day1 * 1.2  # mostly unchanged: shared rows


def test_secrets_never_reach_postgres(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    with owner.connect() as conn:
        blob = " ".join(conn.execute(text("SELECT config::text FROM resource_config")).scalars())
    assert "pw-" not in blob  # Lambda DB_PASSWORD values
    assert "IyEvYmluL2Jhc2g" not in blob  # EC2 user data
    assert '"HttpTokens": "required"' in blob or '"HttpTokens": "optional"' in blob


def test_iam_users_and_their_access_keys_are_inventoried(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Key ids and last use are kept for the operator (NOT_SECRET_COLUMNS); a key is part of
    its user, not an asset of its own, and belongs to it (rule access-key-user)."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    with owner.connect() as conn:
        users = _count(owner, "SELECT count(*) FROM resource WHERE type = 'aws_iam_user'")
        keys = conn.execute(
            text(
                "SELECT r.native_id, r.resource_uid, rc.config FROM resource r "
                "JOIN resource_config rc ON rc.id = r.config_id WHERE r.type = 'aws_iam_access_key'"
            )
        ).all()
        owned = _count(
            owner,
            "SELECT count(*) FROM edge e JOIN resource k ON k.id = e.source_resource_id "
            "JOIN resource u ON u.id = e.target_resource_id WHERE e.type = 'BELONGS_TO' "
            "AND k.type = 'aws_iam_access_key' AND u.type = 'aws_iam_user'",
        )
        assets = (
            conn.execute(
                text(
                    "SELECT dimension FROM metric_daily WHERE metric = 'assets.by_type' "
                    "AND connection_id = :c"
                ),
                {"c": target.connection_id},
            )
            .scalars()
            .all()
        )
    assert users > 0 and keys
    for native_id, uid, config in keys:
        assert config["access_key_id"] == native_id and uid.endswith(f"/accesskey/{native_id}")
    assert owned == len(keys)
    if assets:  # the asset metric names types: a key is not one
        assert "aws_iam_access_key" not in assets


def test_every_rule_fires_on_prod_and_the_scenario_edges_exist(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    with owner.connect() as conn:
        origins = set(conn.execute(text("SELECT DISTINCT origin FROM edge")).scalars())
        edges = conn.execute(
            text("""
            SELECT e.type, src.name AS src, tgt.name AS tgt, e.source_uid, e.attributes
            FROM edge e LEFT JOIN resource src ON src.id = e.source_resource_id
            LEFT JOIN resource tgt ON tgt.id = e.target_resource_id""")
        ).all()
    assert origins == {r.origin for r in load_rules(RULES_DIR)}
    found = {(e.type, e.src or e.source_uid, e.tgt) for e in edges}
    assert ("MEMBER_OF", SCENARIO_INSTANCE, SCENARIO_SG) in found
    assert ("RUNS_AS", SCENARIO_INSTANCE, SCENARIO_ROLE) in found
    assert ("ALLOWS_INGRESS", "internet", SCENARIO_SG) in found
    ingress = next(e for e in edges if e.type == "ALLOWS_INGRESS" and e.tgt == SCENARIO_SG)
    assert ingress.attributes["to_port"] == 22


_BY_TYPE = """
    SELECT count(*) FROM resource_snapshot s JOIN resource r ON r.id = s.resource_id
    WHERE s.snapshot_date = :d AND r.type = ANY(CAST(:types AS text[]))"""


def test_a_partial_run_is_complete_for_every_table_but_its_incomplete_ones(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Per-table completeness (argus_v8): the tables a throttled run lost carry forward and
    delete nothing; every other table is complete, so its churned resources are deleted."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    later = DAY + timedelta(days=30)  # inside the 31-day carry-forward window, with churn
    partial = run_tool(
        worker, store, target, "steampipe", later, CollectOptions(synthetic_throttle_share=1.0)
    )
    assert partial.status == "partial"
    with owner.connect() as conn:
        lost = conn.execute(
            text("SELECT incomplete_tables FROM scan_run WHERE snapshot_date = :d"), {"d": later}
        ).scalar_one()
    assert len(lost) == 3
    assert partial.loaded["carried_forward"] > 0
    assert partial.loaded["deleted"] > 0  # churn in the complete tables
    assert _count(owner, _BY_TYPE, d=later, types=lost) == _count(
        owner, _BY_TYPE, d=DAY, types=lost
    )
    assert (
        _count(
            owner,
            "SELECT count(*) FROM resource "
            "WHERE deleted_on = :d AND type = ANY(CAST(:t AS text[]))",
            d=later,
            t=lost,
        )
        == 0
    )


def test_a_complete_run_marks_churned_resources_deleted(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    later = DAY + timedelta(days=90)
    outcome = run_tool(worker, store, target, "steampipe", later)
    assert outcome.loaded["deleted"] > 0
    assert _count(owner, "SELECT count(*) FROM resource WHERE deleted_on = :d", d=later) > 0


def test_a_tampered_run_is_recorded_as_failed(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    path, manifest = collect(
        source_for("demo"),
        store,
        target=target,
        tool="steampipe",
        day=DAY,
        run_uid=uuid4(),
        options=CollectOptions(synthetic_throttle_share=0.0),
    )
    next((store.root / path).glob("*.jsonl")).write_text("{}\n")
    with worker.begin() as conn:
        scan_run_id = register_run(
            conn, connection_id=target.connection_id, raw_path=path, manifest=manifest
        )
    outcome = ingest_run(worker, store=store, scan_run_id=scan_run_id, rules_dir=RULES_DIR)
    assert outcome.status == "failed"
    assert _count(owner, "SELECT count(*) FROM resource") == 0
    with owner.connect() as conn:
        status, log_tail = conn.execute(text("SELECT status, log_tail FROM scan_run")).one()
    assert status == "failed" and "do not match" in log_tail
