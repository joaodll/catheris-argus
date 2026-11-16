"""An evaluation over the synthetic estate (ADR-0052): routes are worked out, as argus_paths, and
an unchanged estate writes nothing."""

import importlib
from datetime import UTC, date, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError
from tests.conftest import RULES_DIR
from tests.ingest.conftest import make_demo, run_tool

from argus import attackpaths, ingest
from argus.attackpaths import store
from argus.collection import TOOL_ORDER
from argus.core.rawstore import FilesystemRawStore
from argus.scheduling import paths

pytestmark = pytest.mark.db
# The module, not the package's evaluate() function of the same name.
evaluate_module = importlib.import_module("argus.attackpaths.evaluate")


@pytest.fixture
def estate(owner: Engine, worker: Engine, store: FilesystemRawStore) -> list[int]:
    ids = []
    for seed in (0, 1):
        target = make_demo(owner, seed)
        for tool in TOOL_ORDER:
            run_tool(worker, store, target, tool, datetime.now(UTC).date())
        ids.append(target.connection_id)
    return ids


def test_routes_are_worked_out_once_as_the_paths_role(
    estate: list[int], paths_role: Engine, owner: Engine
) -> None:
    assert paths.run_pending(paths_role, rules_dir=RULES_DIR)
    with owner.connect() as conn:
        last = conn.execute(
            text("SELECT status, error, routes FROM route_evaluation ORDER BY id DESC LIMIT 1")
        ).one()
        by_kind = dict(
            conn.execute(text("SELECT kind, count(*) FROM route GROUP BY kind")).tuples().all()
        )
    assert last.status == "complete", last.error
    assert last.routes and by_kind, by_kind
    # Nothing changed since: not due, and a forced second walk writes nothing.
    assert not paths.run_pending(paths_role, rules_dir=RULES_DIR)


def _counts(owner: Engine) -> tuple[int, int, int]:
    with owner.connect() as conn:
        return tuple(
            conn.execute(
                text(
                    "SELECT (SELECT count(*) FROM route), (SELECT count(*) FROM route_target), "
                    "(SELECT count(*) FROM route_node)"
                )
            ).one()
        )  # type: ignore[return-value]


def _evaluate(engine: Engine, today: date | None = None) -> attackpaths.Written:
    with (
        engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn,
        conn.begin(),
    ):
        runs = {k: (r.run_id, r.status) for k, r in ingest.newest_runs(conn).items()}
        return attackpaths.evaluate(
            conn, rules_dir=RULES_DIR, runs=runs, today=today or datetime.now(UTC).date()
        )


def test_an_unchanged_estate_writes_nothing(estate: list[int], paths_role: Engine) -> None:
    first = _evaluate(paths_role)
    again = _evaluate(paths_role)
    assert first.opened == first.routes > 0
    assert (again.opened, again.changed, again.resolved) == (0, 0, 0)


def test_a_route_gone_is_fixed_only_where_every_crossed_run_is_complete(
    estate: list[int], paths_role: Engine, owner: Engine
) -> None:
    _evaluate(paths_role)
    with owner.connect() as conn:
        rid, kind, crossed = conn.execute(
            text(
                "SELECT id, kind, crossed_connection_ids FROM route "
                "ORDER BY cardinality(crossed_connection_ids) DESC, id LIMIT 1"
            )
        ).one()
    complete = {(c, t): (1, "complete") for c in estate for t in TOOL_ORDER}
    kinds = {k.id: k for k in attackpaths.load_kinds(RULES_DIR)}
    for c in crossed:
        for tool in ("steampipe", "cloudfox", "prowler", "vulnerabilities"):
            partial = {**complete, (c, tool): (2, "partial")}
            with paths_role.begin() as conn:
                store.write(conn, [], kinds=kinds, runs=partial, today=datetime.now(UTC).date())
                state = conn.execute(text("SELECT state FROM route WHERE id = :r"), {"r": rid})
                held = state.scalar_one()
                conn.rollback()
            if tool in store.WHERE_RUN and kinds[kind].entry == "only":
                continue  # an exposure reads Steampipe and CloudFox only
            assert held != "resolved", (c, tool)
    with paths_role.begin() as conn:
        written = store.write(conn, [], kinds=kinds, runs=complete, today=datetime.now(UTC).date())
    assert written.resolved > 0


def test_a_fixed_route_found_again_reopens(estate: list[int], paths_role: Engine) -> None:
    _evaluate(paths_role)
    complete = {(c, t): (1, "complete") for c in estate for t in TOOL_ORDER}
    kinds = {k.id: k for k in attackpaths.load_kinds(RULES_DIR)}
    with paths_role.begin() as conn:
        store.write(conn, [], kinds=kinds, runs=complete, today=datetime.now(UTC).date())
    again = _evaluate(paths_role)
    assert again.opened == again.routes
    with paths_role.connect() as conn:
        states = set(conn.execute(text("SELECT DISTINCT state FROM route")).scalars())
    assert states == {"reopened"}


def test_a_failed_evaluation_writes_nothing(
    estate: list[int], paths_role: Engine, owner: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert paths.run_pending(paths_role, rules_dir=RULES_DIR)
    before = _counts(owner)
    with owner.begin() as conn:  # the inputs change, so a new evaluation is due
        conn.execute(
            text(
                "UPDATE edge_load SET ruleset = encode(sha256('changed'), 'hex') "
                "WHERE family = 'rule'"
            )
        )
    real = store.write

    def write_then_fail(conn: Any, *args: Any, **kwargs: Any) -> Any:
        real(conn, *args, **kwargs)
        conn.execute(text("DELETE FROM route"))
        raise RuntimeError("out of memory")

    monkeypatch.setattr(evaluate_module, "write", write_then_fail)
    assert paths.run_pending(paths_role, rules_dir=RULES_DIR)
    assert _counts(owner) == before
    with owner.connect() as conn:
        last = conn.execute(
            text("SELECT status, error FROM route_evaluation ORDER BY id DESC LIMIT 1")
        ).one()
    assert last.status == "failed" and "out of memory" in last.error
    # Not retried at once, as long as nothing else changes.
    assert not paths.run_pending(paths_role, rules_dir=RULES_DIR)


def test_retention_purges_routes_fixed_before_the_history_kept(
    estate: list[int], paths_role: Engine, worker: Engine
) -> None:
    _evaluate(paths_role)
    complete = {(c, t): (1, "complete") for c in estate for t in TOOL_ORDER}
    kinds = {k.id: k for k in attackpaths.load_kinds(RULES_DIR)}
    with paths_role.begin() as conn:
        store.write(conn, [], kinds=kinds, runs=complete, today=date(2026, 1, 1))
    with worker.begin() as conn:
        assert attackpaths.purge_resolved(conn, cutoff=date(2026, 1, 2)) > 0
        assert conn.execute(text("SELECT count(*) FROM route_target")).scalar_one() == 0


def test_the_paths_role_reads_no_configuration_and_no_credential(paths_role: Engine) -> None:
    for statement in (
        "SELECT config FROM resource_config LIMIT 1",
        "SELECT tags FROM resource LIMIT 1",
        "SELECT secret_ciphertext FROM connection LIMIT 1",
        "SELECT name FROM connection LIMIT 1",
        "SELECT * FROM audit_log LIMIT 1",
    ):
        with paths_role.connect() as conn, pytest.raises(ProgrammingError):
            conn.execute(text(statement))


def test_the_scheduler_tells_when_routes_are_due_reading_no_scan_data(
    estate: list[int], scheduler: Engine, paths_role: Engine
) -> None:
    assert paths.due(scheduler, rules_dir=RULES_DIR, now=datetime.now(UTC))
    assert paths.run_pending(paths_role, rules_dir=RULES_DIR)
    assert not paths.due(scheduler, rules_dir=RULES_DIR, now=datetime.now(UTC))


def test_one_evaluation_at_a_time(estate: list[int], paths_role: Engine, owner: Engine) -> None:
    with owner.connect() as held:
        held.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), {"k": paths.PATHS_LOCK})
        held.commit()
        assert not paths.run_pending(paths_role, rules_dir=RULES_DIR)  # turned away, not queued
        held.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": paths.PATHS_LOCK})
        held.commit()
    assert paths.run_pending(paths_role, rules_dir=RULES_DIR)


def test_a_deleted_connection_does_not_keep_a_route_open(estate: list[int]) -> None:
    kinds = {k.id: k for k in attackpaths.load_kinds(RULES_DIR)}
    runs = {(estate[0], t): (1, "complete") for t in TOOL_ORDER}
    crossed = [estate[0], 999]
    assert not store.resolvable(crossed, kinds["internet-to-admin"], runs)
    assert store.resolvable(crossed, kinds["internet-to-admin"], runs, existing={estate[0]})
