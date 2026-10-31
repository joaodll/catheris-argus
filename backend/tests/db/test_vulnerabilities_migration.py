"""Migration 0033 (ADR-0042): vulnerabilities rows fit the new checks and tables, a folder
stored under the tool's first name moves to its name, and a downgrade removes every row, its
history and the tool in schedules and settings, then restores the checks."""

from datetime import date
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from tests.conftest import alembic_config
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import FilesystemRawStore

pytestmark = pytest.mark.db


def _vulnerability_rows(owner: Engine, connection_id: int, day: date) -> int:
    with owner.begin() as conn:
        run_id = conn.execute(
            text("""
            INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source,
                                  snapshot_date, status, started_at, raw_path)
            VALUES (:u, :c, 'vulnerabilities', '1.34.0', 'synthetic', :d, 'complete', now(),
                    'raw/x')
            RETURNING id
        """),
            {"u": uuid4(), "c": connection_id, "d": day},
        ).scalar_one()
        resource_id, resource_uid = conn.execute(
            text("SELECT id, resource_uid FROM resource WHERE connection_id = :c LIMIT 1"),
            {"c": connection_id},
        ).one()
        finding_id = conn.execute(
            text("""
            INSERT INTO finding (finding_uid, tool, check_id, connection_id, region,
                                 resource_uid, resource_id, severity, status, title, state,
                                 first_seen, last_seen)
            VALUES ('vuln-test-1', 'vulnerabilities', 'CVE-2024-0001', :c, 'us-east-1', :ru,
                    :r, 'critical', 'FAIL', 'CVE-2024-0001 - openssl', 'open', :d, :d)
            RETURNING id
        """),
            {"c": connection_id, "ru": resource_uid, "r": resource_id, "d": day},
        ).scalar_one()
        params = {"f": finding_id, "r": resource_id, "c": connection_id, "run": run_id, "d": day}
        for statement in (
            "INSERT INTO finding_vulnerability (finding_id, scanner, kind, vulnerability_id, "
            "package_name, fixed_version, exploit_available) "
            "VALUES (:f, 'aws-inspector', 'package', 'CVE-2024-0001', 'openssl', '3.0.14', true)",
            "INSERT INTO vulnerability_coverage (resource_id, scanner, scan_type, connection_id, "
            "active, status_code, scan_run_id) "
            "VALUES (:r, 'aws-inspector', 'package', :c, true, 'ACTIVE', :run)",
            "INSERT INTO finding_snapshot (snapshot_date, finding_id, status, severity, muted) "
            "VALUES (:d, :f, 1, 1, false)",
            "INSERT INTO finding_event (occurred_on, finding_id, event, scan_run_id) "
            "VALUES (:d, :f, 'opened', :run)",
            "INSERT INTO finding_check_text (tool, check_id, tool_version, description) "
            "VALUES ('vulnerabilities', 'CVE-2024-0001', '1.34.0', 'openssl')",
            "INSERT INTO run_request (connection_id, tool, reason, status, requested_by, "
            "finished_at, scan_run_id) "
            "VALUES (:c, 'vulnerabilities', 'manual', 'finished', 't', now(), :run)",
            "INSERT INTO schedule (name, tools, cron, updated_by) "
            "VALUES ('both', ARRAY['steampipe', 'vulnerabilities'], '0 3 * * *', 't'), "
            "('only-vulnerabilities', ARRAY['vulnerabilities'], '0 4 * * *', 't')",
            "INSERT INTO platform_setting (topic, value, updated_by) VALUES ('raw_storage', "
            '\'{"bucket": null, "prefixes": {"steampipe": "raw/steampipe", '
            '"vulnerabilities": "raw/vulnerabilities"}}\', \'t\') '
            "ON CONFLICT (topic) DO UPDATE SET value = EXCLUDED.value",
        ):
            conn.execute(text(statement), params)
    return finding_id


def test_vulnerability_rows_go_in_and_a_downgrade_removes_them(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    day = date.today()
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", day)
    _vulnerability_rows(owner, target.connection_id, day)

    try:
        command.downgrade(alembic_config(), "0032")
        with owner.begin() as conn:
            for table in ("finding", "finding_check_text", "run_request", "scan_run"):
                left = conn.execute(
                    text(f"SELECT count(*) FROM {table} WHERE tool = 'vulnerabilities'")  # noqa: S608
                ).scalar_one()
                assert left == 0, table
            assert conn.execute(text("SELECT count(*) FROM finding_event")).scalar_one() == 0
            rows = conn.execute(text("SELECT name, tools FROM schedule")).all()
            schedules = {r.name: r.tools for r in rows}
            assert schedules == {"both": ["steampipe"]}
            prefixes = conn.execute(
                text("SELECT value -> 'prefixes' FROM platform_setting WHERE topic = 'raw_storage'")
            ).scalar_one()
            assert prefixes == {"steampipe": "raw/steampipe"}
            assert conn.execute(
                text("SELECT to_regclass('finding_vulnerability') IS NULL")
            ).scalar_one()
            steampipe_runs = conn.execute(
                text("SELECT count(*) FROM scan_run WHERE tool = 'steampipe'")
            ).scalar_one()
            assert steampipe_runs == 1
        with pytest.raises(IntegrityError), owner.begin() as conn:
            conn.execute(text("UPDATE schedule SET tools = ARRAY['steampipe', 'vulnerabilities']"))
    finally:
        command.upgrade(alembic_config(), "head")


def test_a_package_finding_needs_its_cve_and_a_url_must_be_http(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    day = date.today()
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", day)
    finding_id = _vulnerability_rows(owner, target.connection_id, day)
    bad = (
        "UPDATE finding_vulnerability SET vulnerability_id = NULL",
        "UPDATE finding_vulnerability SET reference_url = 'javascript:alert(1)'",
        "UPDATE finding_vulnerability SET kind = 'network_reachability'",
        "UPDATE finding_vulnerability SET scanner = 'AWS Inspector'",
    )
    for statement in bad:
        with pytest.raises(IntegrityError), owner.begin() as conn:
            conn.execute(text(f"{statement} WHERE finding_id = :f"), {"f": finding_id})
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE finding_vulnerability SET vulnerability_id = NULL, "
                "kind = 'code' WHERE finding_id = :f"
            ),
            {"f": finding_id},
        )


@pytest.mark.parametrize(
    ("stored", "moved"),
    [("raw/inspector", "raw/vulnerabilities"), ("custom/vulns", "custom/vulns")],
    ids=["default-folder", "custom-folder"],
)
def test_a_folder_stored_under_the_first_name_moves_to_the_tool(
    owner: Engine, stored: str, moved: str
) -> None:
    command.downgrade(alembic_config(), "0032")
    try:
        with owner.begin() as conn:
            conn.execute(
                text("""
                INSERT INTO platform_setting (topic, value, updated_by)
                VALUES ('raw_storage',
                        jsonb_build_object('bucket', NULL, 'prefixes', jsonb_build_object(
                          'steampipe', 'raw/steampipe', 'inspector', CAST(:p AS text))),
                        't')
                ON CONFLICT (topic) DO UPDATE SET value = EXCLUDED.value
            """),
                {"p": stored},
            )
        command.upgrade(alembic_config(), "head")
        with owner.begin() as conn:
            prefixes = conn.execute(
                text("SELECT value -> 'prefixes' FROM platform_setting WHERE topic = 'raw_storage'")
            ).scalar_one()
        assert prefixes == {"steampipe": "raw/steampipe", "vulnerabilities": moved}
    finally:
        command.upgrade(alembic_config(), "head")
