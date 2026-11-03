"""Migration 0039 (ADR-0045): the path and graph tables go, the path metrics go and every other
metric stays, and the worker no longer holds TEMPORARY by name. A downgrade brings the tables back
empty, in a shape an older release can write to."""

from datetime import date

import pytest
from alembic import command
from sqlalchemy import Connection, Engine, text
from tests.conftest import alembic_config
from tests.ingest.conftest import make_demo

pytestmark = pytest.mark.db
DAY = date(2026, 10, 30)


def _tables(conn: Connection) -> set[str]:
    rows = conn.execute(
        text(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
            "AND tablename IN ('attack_path', 'graph_projection')"
        )
    )
    return set(rows.scalars())


def _named_temporary_grant(conn: Connection) -> bool:
    """Whether argus_worker holds TEMPORARY by name, not through PUBLIC's default."""
    return bool(
        conn.execute(
            text("""
            SELECT EXISTS (
              SELECT 1
              FROM pg_database d, aclexplode(d.datacl) a
              WHERE d.datname = current_database()
                AND a.privilege_type = 'TEMPORARY'
                AND a.grantee = 'argus_worker'::regrole
            )
        """)
        ).scalar_one()
    )


def _put_metric(conn: Connection, connection_id: int, metric: str) -> None:
    conn.execute(
        text("""
            INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
            VALUES (:d, :c, :m, 'x', 1)
        """),
        {"d": DAY, "c": connection_id, "m": metric},
    )


def test_the_upgrade_drops_paths_and_keeps_other_metrics(owner: Engine) -> None:
    connection_id = make_demo(owner).connection_id
    try:
        command.downgrade(alembic_config(), "0038")
        with owner.begin() as conn:
            assert _tables(conn) == {"attack_path", "graph_projection"}
            assert _named_temporary_grant(conn)
            conn.execute(text("SELECT argus_ensure_partitions(:d, :d)"), {"d": DAY})
            for metric in (
                "attack_paths.open_by_severity",
                "attack_paths.open_by_category",
                "attack_paths.not_listed",
                "findings.open_by_severity",
            ):
                _put_metric(conn, connection_id, metric)

        command.upgrade(alembic_config(), "0039")

        with owner.connect() as conn:
            assert _tables(conn) == set()
            assert not _named_temporary_grant(conn)
            kept = conn.execute(
                text(
                    "SELECT metric FROM metric_daily WHERE connection_id = :c AND dimension = 'x'"
                ),
                {"c": connection_id},
            ).scalars()
            assert list(kept) == ["findings.open_by_severity"]
    finally:
        command.upgrade(alembic_config(), "head")


def test_a_downgrade_brings_back_writable_empty_tables(owner: Engine) -> None:
    connection_id = make_demo(owner).connection_id
    try:
        command.downgrade(alembic_config(), "0038")
        with owner.begin() as conn:
            assert conn.execute(text("SELECT count(*) FROM attack_path")).scalar_one() == 0
            assert conn.execute(text("SELECT count(*) FROM graph_projection")).scalar_one() == 0
            # The roles an older release runs as keep what 0001 and 0034 gave them.
            for role, table, privilege, held in (
                ("argus_api", "attack_path", "SELECT", True),
                ("argus_api", "attack_path", "INSERT", False),
                ("argus_worker", "attack_path", "INSERT", True),
                ("argus_worker", "attack_path", "DELETE", False),
                ("argus_api", "graph_projection", "SELECT", True),
                ("argus_api", "graph_projection", "INSERT", False),
                ("argus_worker", "graph_projection", "DELETE", True),
            ):
                assert (
                    conn.execute(
                        text("SELECT has_table_privilege(:r, :t, :p)"),
                        {"r": role, "t": table, "p": privilege},
                    ).scalar_one()
                    is held
                ), (role, table, privilege)
            # Every column 0038's code wrote, so an older release works against this shape.
            conn.execute(
                text("""
                INSERT INTO attack_path (path_id, rule_id, rule_version, category, severity,
                                         connection_id, connection_ids, entry_uid, target_uid,
                                         node_uids, edge_ids, state, first_seen, last_seen,
                                         base_severity, entry_confirmed, has_failing, confidence)
                VALUES (sha256(CAST('p' AS bytea)), 'r', 1, 'c', 'high', :c, ARRAY[:c], 'i', 't',
                        ARRAY['i', 't'], ARRAY[]::bigint[], 'open', :d, :d,
                        'high', true, false, 'blocked')
            """),
                {"c": connection_id, "d": DAY},
            )
            conn.execute(
                text("""
                INSERT INTO graph_projection (connection_id, ruleset, node_count, edge_count,
                                              checksum, status)
                VALUES (:c, 'r', 0, 0, sha256(CAST('x' AS bytea)), 'synced')
            """),
                {"c": connection_id},
            )
    finally:
        command.upgrade(alembic_config(), "head")
