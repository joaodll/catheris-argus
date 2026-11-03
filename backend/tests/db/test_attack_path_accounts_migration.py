"""Migration 0035 (ADR-0044, M2): a path found before it was found inside one account, so it is
backfilled with that account alone and with the day it was last seen; the entry's connection
stays first in `connection_ids`; a downgrade drops the columns and keeps the paths."""

from datetime import date

import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from tests.conftest import alembic_config
from tests.ingest.conftest import make_demo

pytestmark = pytest.mark.db
DAY = date(2026, 10, 30)


def _path(conn, connection_id: int, ids: list[int] | None = None) -> None:  # type: ignore[no-untyped-def]
    columns = "connection_ids, " if ids is not None else ""
    values = ":ids, " if ids is not None else ""
    conn.execute(
        text(f"""
        INSERT INTO attack_path (path_id, rule_id, rule_version, category, severity,
                                 connection_id, {columns}entry_uid, target_uid, node_uids,
                                 edge_ids, state, first_seen, last_seen)
        VALUES (sha256(CAST(:p AS bytea)), 'internet-to-admin', 1, 'IAM privilege escalation',
                'high', :c, {values}'i', 't', ARRAY['internet', 'i', 't'], ARRAY[]::bigint[],
                'open', :d, :d)
    """),  # noqa: S608 - two fixed fragments
        {"p": f"p{connection_id}-{ids}", "c": connection_id, "ids": ids, "d": DAY},
    )


def test_old_paths_are_backfilled_and_a_downgrade_keeps_them(owner: Engine) -> None:
    connection_id = make_demo(owner).connection_id
    try:
        command.downgrade(alembic_config(), "0034")
        with owner.begin() as conn:
            _path(conn, connection_id)
        command.upgrade(alembic_config(), "0035")
        with owner.begin() as conn:
            ids, seen_at = conn.execute(
                text("SELECT connection_ids, last_seen_at FROM attack_path")
            ).one()
            assert ids == [connection_id]
            assert seen_at.isoformat() == f"{DAY.isoformat()}T00:00:00+00:00"
        command.downgrade(alembic_config(), "0034")
        with owner.begin() as conn:
            assert conn.execute(text("SELECT count(*) FROM attack_path")).scalar_one() == 1
    finally:
        command.upgrade(alembic_config(), "head")


def test_0038_drops_last_seen_at_and_its_downgrade_restores_it(owner: Engine) -> None:
    connection_id = make_demo(owner).connection_id
    with owner.begin() as conn:
        _path(conn, connection_id, [connection_id])
    try:
        command.downgrade(alembic_config(), "0037")
        with owner.connect() as conn:
            seen_at = conn.execute(text("SELECT last_seen_at FROM attack_path")).scalar_one()
            assert seen_at.isoformat() == f"{DAY.isoformat()}T00:00:00+00:00"
    finally:
        command.upgrade(alembic_config(), "head")
    with owner.connect() as conn:
        assert conn.execute(
            text("SELECT has_database_privilege('argus_worker', current_database(), 'TEMPORARY')")
        ).scalar_one()
        assert not conn.execute(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_name = 'attack_path' AND column_name = 'last_seen_at'"
            )
        ).scalar_one()


def test_the_entry_account_comes_first(owner: Engine) -> None:
    entry = make_demo(owner, seed=0).connection_id
    other = make_demo(owner, seed=1).connection_id
    with owner.begin() as conn:
        _path(conn, entry, [entry, other])
    for ids in ([other, entry], []):
        with pytest.raises(IntegrityError), owner.begin() as conn:
            _path(conn, entry, ids)
