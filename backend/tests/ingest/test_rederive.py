"""After a rule upgrade the worker derives again at start (ADR-0035, fifth amendment, point 6):
each enabled connection whose latest rule load has another rule set, on that load's day,
under an advisory lock, resolving nothing."""

import logging
import threading
import time
from datetime import date

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus.collection import TOOL_ORDER, CollectTarget, FilesystemRawStore
from argus.ingest import rederive_stale
from argus.ingest.pipeline import REDERIVE_LOCK, rule_set
from argus.ingest.rederive import REDERIVE_ONCE_LOCK

pytestmark = pytest.mark.db
DAY = date(2026, 10, 20)
TODAY = date(2026, 10, 21)
OLD_ORIGIN = "rule:internet-entry@1"


def _scanned(owner: Engine, worker: Engine, store: FilesystemRawStore, seed: int = 0) -> int:
    target = make_demo(owner, seed)
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, DAY)
    return target.connection_id


def _rulesets(owner: Engine, cid: int) -> set[str | None]:
    with owner.connect() as conn:
        return set(
            conn.execute(
                text("SELECT ruleset FROM edge_load WHERE connection_id = :c AND family = 'rule'"),
                {"c": cid},
            ).scalars()
        )


def _as_before_the_upgrade(owner: Engine, cid: int) -> None:
    """The day's rule load as an older release left it: no rule set, and one edge of a rule
    version this release no longer has."""
    with owner.begin() as conn:
        conn.execute(
            text("UPDATE edge_load SET ruleset = NULL WHERE connection_id = :c"), {"c": cid}
        )
        conn.execute(
            text("""
                WITH old AS (
                  INSERT INTO edge (edge_key, source_uid, target_uid, type, origin, attributes,
                                    first_seen, last_seen, connection_id)
                  VALUES (decode(md5('old-' || :c), 'hex') || decode(md5('edge'), 'hex'),
                          'internet', 'arn:aws:s3:::gone', 'ROUTES_TO', :o, '{}', :d, :d, :c)
                  RETURNING id)
                INSERT INTO edge_snapshot (snapshot_date, edge_id) SELECT :d, id FROM old
            """),
            {"c": cid, "o": OLD_ORIGIN, "d": DAY},
        )


def _old_edges(owner: Engine, cid: int) -> int:
    with owner.connect() as conn:
        n: int = conn.execute(
            text(
                "SELECT count(*) FROM edge e JOIN edge_snapshot s ON s.edge_id = e.id "
                "WHERE e.connection_id = :c AND s.snapshot_date = :d AND e.origin = :o"
            ),
            {"c": cid, "d": DAY, "o": OLD_ORIGIN},
        ).scalar_one()
    return n


def _paths(owner: Engine, cid: int) -> dict[str, int]:
    with owner.connect() as conn:
        rows = conn.execute(
            text("SELECT state, count(*) FROM attack_path WHERE connection_id = :c GROUP BY 1"),
            {"c": cid},
        ).all()
    return {r.state: r.count for r in rows}


def test_a_load_with_the_current_rules_is_left_alone(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    cid = _scanned(owner, worker, store)
    assert _rulesets(owner, cid) == {rule_set(RULES_DIR)}
    assert rederive_stale(worker, rules_dir=RULES_DIR, today=TODAY) == []


def test_a_load_from_before_the_upgrade_is_derived_again(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    cid = _scanned(owner, worker, store)
    paths = _paths(owner, cid)
    _as_before_the_upgrade(owner, cid)
    assert _old_edges(owner, cid) == 1

    assert rederive_stale(worker, rules_dir=RULES_DIR, today=TODAY) == [cid]
    assert _rulesets(owner, cid) == {rule_set(RULES_DIR)}
    assert _old_edges(owner, cid) == 0  # the day's rule edges are the current rules' only
    assert _paths(owner, cid) == paths  # found again, nothing resolved
    assert rederive_stale(worker, rules_dir=RULES_DIR, today=TODAY) == []


def test_a_disabled_connection_waits_for_its_next_run(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    cid = _scanned(owner, worker, store)
    _as_before_the_upgrade(owner, cid)
    with owner.begin() as conn:
        conn.execute(text("UPDATE connection SET enabled = false WHERE id = :c"), {"c": cid})
    assert rederive_stale(worker, rules_dir=RULES_DIR, today=TODAY) == []
    assert _old_edges(owner, cid) == 1


def test_one_worker_re_derives_at_a_time(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    cid = _scanned(owner, worker, store)
    _as_before_the_upgrade(owner, cid)
    with owner.connect() as other:
        other.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), {"k": REDERIVE_ONCE_LOCK})
        try:
            assert rederive_stale(worker, rules_dir=RULES_DIR, today=TODAY) == []
        finally:
            other.execute(
                text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": REDERIVE_ONCE_LOCK}
            )
    assert rederive_stale(worker, rules_dir=RULES_DIR, today=TODAY) == [cid]


def test_a_re_derive_waits_for_the_ingests_running_now(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Every ingest holds the re-derive lock shared (ADR-0039): a re-derive starts once they
    end, instead of interleaving with one or being skipped."""
    cid = _scanned(owner, worker, store)
    _as_before_the_upgrade(owner, cid)
    done: list[list[int]] = []
    with owner.connect() as ingest:
        ingest.execute(text("SELECT pg_advisory_lock_shared(hashtext(:k))"), {"k": REDERIVE_LOCK})
        thread = threading.Thread(
            target=lambda: done.append(rederive_stale(worker, rules_dir=RULES_DIR, today=TODAY))
        )
        thread.start()
        time.sleep(0.5)
        assert not done  # waiting for the ingest
        ingest.execute(text("SELECT pg_advisory_unlock_shared(hashtext(:k))"), {"k": REDERIVE_LOCK})
        thread.join(timeout=60)
    assert done == [[cid]]


def test_paths_keep_cloudfoxs_newest_evidence(
    owner: Engine, worker: Engine, store: FilesystemRawStore, caplog: pytest.LogCaptureFixture
) -> None:
    """CloudFox ran a day after Steampipe: the rule edges are re-derived on Steampipe's day, the
    paths evaluated on CloudFox's, so they keep its newer edges."""
    cid = _scanned(owner, worker, store)
    later = date(2026, 10, 21)
    with owner.connect() as conn:
        target = conn.execute(
            text("SELECT id, account_id, demo_seed FROM connection WHERE id = :c"), {"c": cid}
        ).one()
    run_tool(
        worker,
        store,
        CollectTarget(cid, "demo", target.account_id, target.demo_seed),
        "cloudfox",
        later,
    )
    _as_before_the_upgrade(owner, cid)
    caplog.set_level(logging.INFO, logger="argus.ingest.rederive")
    assert rederive_stale(worker, rules_dir=RULES_DIR, today=later) == [cid]
    [record] = [r for r in caplog.records if r.getMessage() == "re-derived after a rule upgrade"]
    assert (record.__dict__["day"], record.__dict__["paths_day"]) == (
        DAY.isoformat(),
        later.isoformat(),
    )
