"""CloudFox through the real ingest, into Postgres: its edges and attacker-view findings, with no
secret value anywhere it stores (a test per adapter, CLAUDE.md), its loot commands (ADR-0038), and
a partial run that resolves nothing."""

from datetime import date, timedelta

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import TOOL_ORDER, CollectOptions, FilesystemRawStore
from argus.findings import ResolvedCommand, commands_for_resource, load_commands

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)
# Every secret value the synthetic estate plants in CloudFox's env-vars starts with this.
PLANTED = "pw-"


def _day(
    worker: Engine,
    store: FilesystemRawStore,
    target,  # type: ignore[no-untyped-def]
    day: date,
    cloudfox_options: CollectOptions | None = None,
) -> None:
    for tool in TOOL_ORDER:
        if tool == "cloudfox" and cloudfox_options:
            run_tool(worker, store, target, tool, day, cloudfox_options)
        else:
            run_tool(worker, store, target, tool, day)


def test_cloudfox_edges_and_secret_findings_without_values(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        edges = conn.execute(
            text("SELECT type, e::text AS row FROM edge e WHERE origin = 'cloudfox'")
        ).all()
        found = conn.execute(
            text("SELECT check_id, title, f::text AS row FROM finding f WHERE tool = 'cloudfox'")
        ).all()
        commands = conn.execute(text("SELECT c::text AS row FROM finding_command c")).all()
    assert {"CAN_PRIVESC_TO", "IS_ADMIN", "CAN_ASSUME"} <= {e.type for e in edges}
    secrets = [f for f in found if f.check_id == "cloudfox_env_var_secret"]
    assert secrets and all("DB_PASSWORD" in s.title for s in secrets)
    assert {f.check_id for f in found} == {
        "cloudfox_env_var_secret",
        "cloudfox_role_privesc_to_admin",
        "cloudfox_cross_account_root_trust_no_external_id",
        "cloudfox_public_endpoint",
    }
    assert commands, "expected synthetic loot commands"
    assert not any(PLANTED in row.row for row in (*edges, *found, *commands))


def test_loot_commands_load_and_a_partial_run_keeps_them(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        rows = conn.execute(
            text("SELECT label, resource_id FROM finding_command WHERE connection_id = :c"),
            {"c": target.connection_id},
        ).all()
    # The synthetic estate writes bucket, SSM and nmap loot; every command resolved to a
    # resource (ADR-0038: unresolved ones are recorded, not stored).
    assert rows, "expected synthetic loot commands"
    assert {"check", "reads_data", "acts_on_target"} & {r.label for r in rows}
    assert all(r.resource_id is not None for r in rows)
    before = len(rows)

    # A partial run changes nothing (current state, ADR-0038).
    _day(
        worker,
        store,
        target,
        DAY + timedelta(days=1),
        cloudfox_options=CollectOptions(synthetic_throttle_share=1.0),
    )
    with owner.connect() as conn:
        after = conn.execute(
            text("SELECT count(*) FROM finding_command WHERE connection_id = :c"),
            {"c": target.connection_id},
        ).scalar_one()
    assert after == before


def test_loot_commands_report_uids_not_inventoried_and_read_per_connection(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.begin() as conn:
        run_id = conn.execute(
            text("SELECT max(id) FROM scan_run WHERE connection_id = :c AND tool = 'cloudfox'"),
            {"c": target.connection_id},
        ).scalar_one()
        bucket = conn.execute(
            text("SELECT resource_uid FROM finding_command WHERE connection_id = :c LIMIT 1"),
            {"c": target.connection_id},
        ).scalar_one()
        commands = [
            ResolvedCommand(bucket, "check", "tool look", None, "bucket-commands.txt", 0),
            ResolvedCommand("arn:aws:s3:::not-inventoried", "check", "tool look", None, "x", 1),
        ]
        missing = load_commands(
            conn, connection_id=target.connection_id, scan_run_id=run_id, commands=commands
        )
        assert missing == ["arn:aws:s3:::not-inventoried"]
        shown = commands_for_resource(conn, connection_id=target.connection_id, resource_uid=bucket)
        assert [c.command for c in shown] == ["tool look"]
        # Another connection's commands never show on this connection's resource (ADR-0034).
        other = commands_for_resource(
            conn, connection_id=target.connection_id + 1000, resource_uid=bucket
        )
        assert other == []


def test_a_partial_cloudfox_run_resolves_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A scan timeout never looks like a fix."""
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        opened = conn.execute(
            text("SELECT count(*) FROM finding WHERE tool = 'cloudfox' AND state = 'open'")
        ).scalar_one()
    assert opened
    _day(
        worker,
        store,
        target,
        DAY + timedelta(days=1),
        cloudfox_options=CollectOptions(synthetic_throttle_share=1.0),
    )
    with owner.connect() as conn:
        resolved = conn.execute(
            text("SELECT count(*) FROM finding WHERE tool = 'cloudfox' AND state = 'resolved'")
        ).scalar_one()
    assert resolved == 0
