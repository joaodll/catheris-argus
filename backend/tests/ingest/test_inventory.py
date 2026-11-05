import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus import inventory, relationships
from argus.collection import CollectOptions, FilesystemRawStore, collect, source_for
from argus.collection.synthetic.estate import SCENARIO_INSTANCE, SCENARIO_ROLE, SCENARIO_SG
from argus.core.manifest import Manifest, ManifestFile
from argus.core.rawstore import RawRun
from argus.core.redaction import REDACTED
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


def test_a_load_leaves_fresh_statistics_on_its_partitions(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    outcome = run_tool(worker, store, target, "steampipe", DAY)
    # The worker does not own the partition: only the ingest's own ANALYZE can set this so soon.
    assert (
        _count(owner, "SELECT reltuples FROM pg_class WHERE relname = 'resource_snapshot_202610'")
        == outcome.loaded["resources"]
    )


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


def test_a_secret_named_tag_is_redacted_like_the_configuration(tmp_path: Path) -> None:
    """Tags were stored from the row, apart from its redacted configuration."""
    leak = "not-real-" + "tag-value"
    row = {
        "arn": "arn:aws:s3:::tagged",
        "name": "tagged",
        "tags": json.dumps({"db_password": leak, "Environment": "prod", "owner": "team-a"}),
    }
    (tmp_path / "aws_s3_bucket.jsonl").write_text(json.dumps(row) + "\n")
    files = [ManifestFile(path="aws_s3_bucket.jsonl", bytes=1, sha256="0" * 64)]
    now = datetime.now(UTC)
    manifest = Manifest(
        run_uid=uuid4(),
        tool="steampipe",
        tool_version="1.34.1",
        account_id="210987654321",
        source="aws",
        snapshot_date=DAY,
        region_scope=[],
        started_at=now,
        finished_at=now,
        status="complete",
        exit_code=0,
        throttle_events=0,
        files=files,
    )
    [resource] = inventory.parse_steampipe(RawRun(manifest=manifest, root=tmp_path)).resources
    assert resource.tags == {"db_password": REDACTED, "Environment": "prod", "owner": "team-a"}
    assert leak not in json.dumps(resource.config)


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
    later = DAY + timedelta(days=60)  # the previous scan however old (no window), with churn
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


def test_the_latest_inventory_stands_however_old(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Every screen shows each account's latest scan (owner's decision, 2026-11-01): 60 days
    later, the inventory and the rule edges of the last Steampipe run still stand, read through
    resource_load and edge_load."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    later = DAY + timedelta(days=60)
    with owner.connect() as conn:
        loads = conn.execute(
            text("SELECT snapshot_date, resources FROM resource_load WHERE connection_id = :c"),
            {"c": target.connection_id},
        ).all()
        assert inventory.effective_day(conn, connection_id=target.connection_id, day=later) == DAY
        assert (
            relationships.effective_days(conn, connection_id=target.connection_id, day=later)[
                "rule_day"
            ]
            == DAY
        )
        one = conn.execute(
            text("SELECT min(id) FROM resource WHERE connection_id = :c"),
            {"c": target.connection_id},
        ).scalar_one()
        as_of = inventory.resource_at(conn, resource_id=one, day=later)
    assert [(d, n > 0) for d, n in loads] == [(DAY, True)]
    assert as_of is not None and as_of["seen_on"] == DAY and as_of["config"] is not None
