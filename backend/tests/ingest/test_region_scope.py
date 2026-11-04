"""A run says nothing about a region it did not scan (owner, 2026-11-03). Narrowing "AWS regions to
scan" must not mark that region's resources deleted or its CVEs resolved: to anyone reading the
history, both would look like something that really happened in the account."""

from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool
from tests.ingest.test_inspector_adapter import _run as _inspector_run
from tests.ingest.test_steampipe_json_text import ACCOUNT
from tests.ingest.test_steampipe_json_text import _run as _steampipe_run

from argus.collection import FilesystemRawStore
from argus.core.rawstore import RawRun
from argus.findings import load_vulnerabilities
from argus.findings.inspector import parse_inspector
from argus.ingest.pipeline import rule_set
from argus.inventory import load_inventory, parse_steampipe
from argus.relationships import write_edges

pytestmark = pytest.mark.db

DAY = date(2026, 10, 2)
NEXT = DAY + timedelta(days=15)
KEPT = f"arn:aws:sns:us-east-1:{ACCOUNT}:kept"
GONE = f"arn:aws:sns:us-east-1:{ACCOUNT}:gone"
DROPPED = f"arn:aws:sns:eu-west-1:{ACCOUNT}:in-a-dropped-region"
GLOBAL_GONE = f"arn:aws:sns::{ACCOUNT}:global-and-gone"


def _topic(uid: str, region: str | None = None) -> dict[str, object]:
    return {
        "topic_arn": uid,
        "akas": [uid],
        "title": uid.rsplit(":", 1)[-1],
        "region": region or uid.split(":")[3],
    }


def _steampipe(
    tmp_path: Path, name: str, rows: list[dict[str, object]], scope: list[str]
) -> RawRun:
    root = tmp_path / name
    root.mkdir()
    run = _steampipe_run(root, {"aws_sns_topic": rows})
    return RawRun(manifest=run.manifest.model_copy(update={"region_scope": scope}), root=root)


def _load(worker: Engine, connection_id: int, run: RawRun, day: date) -> dict[str, int]:
    with worker.begin() as conn:
        return load_inventory(
            conn, batch=parse_steampipe(run), connection_id=connection_id, day=day
        )


def _everywhere(tmp_path: Path, worker: Engine, connection_id: int) -> None:
    """The first scan, of every region."""
    rows = [_topic(KEPT), _topic(GONE), _topic(DROPPED), _topic(GLOBAL_GONE, "global")]
    _load(worker, connection_id, _steampipe(tmp_path, "first", rows, []), DAY)


def _state(owner: Engine, uid: str, day: date) -> tuple[date | None, bool]:
    with owner.connect() as conn:
        row = conn.execute(
            text("""
            SELECT r.deleted_on, EXISTS (SELECT 1 FROM resource_snapshot s
                                         WHERE s.resource_id = r.id AND s.snapshot_date = :d)
            FROM resource r WHERE r.resource_uid = :u
        """),
            {"d": day, "u": uid},
        ).one()
    return row[0], row[1]


def test_a_narrowed_run_leaves_the_regions_it_did_not_scan(
    tmp_path: Path, owner: Engine, worker: Engine
) -> None:
    connection_id = make_demo(owner).connection_id
    _everywhere(tmp_path, worker, connection_id)
    narrowed = _steampipe(tmp_path, "narrowed", [_topic(KEPT)], ["us-east-1"])
    stats = _load(worker, connection_id, narrowed, NEXT)

    assert _state(owner, DROPPED, NEXT) == (None, True)  # not deleted, and still on the day
    assert _state(owner, KEPT, NEXT) == (None, True)
    # What the run did scan keeps its meaning: gone from a scanned region is deleted, and a global
    # resource is reported from any region.
    assert _state(owner, GONE, NEXT) == (NEXT, False)
    assert _state(owner, GLOBAL_GONE, NEXT) == (NEXT, False)
    assert stats["deleted"] == 2 and stats["carried_forward"] == 1
    # The day's count holds what the day shows.
    with owner.connect() as conn:
        counted = conn.execute(
            text(
                "SELECT resources FROM resource_load "
                "WHERE connection_id = :c AND snapshot_date = :d"
            ),
            {"c": connection_id, "d": NEXT},
        ).scalar_one()
    assert counted == 2


def test_a_run_of_every_region_still_deletes_what_is_gone(
    tmp_path: Path, owner: Engine, worker: Engine
) -> None:
    connection_id = make_demo(owner).connection_id
    _everywhere(tmp_path, worker, connection_id)
    _load(worker, connection_id, _steampipe(tmp_path, "all", [_topic(KEPT)], []), NEXT)
    assert _state(owner, DROPPED, NEXT) == (NEXT, False)
    assert _state(owner, GONE, NEXT) == (NEXT, False)


def test_adding_a_region_back_finds_what_is_there_and_what_is_gone(
    tmp_path: Path, owner: Engine, worker: Engine
) -> None:
    connection_id = make_demo(owner).connection_id
    _everywhere(tmp_path, worker, connection_id)
    _load(
        worker, connection_id, _steampipe(tmp_path, "narrow", [_topic(KEPT)], ["us-east-1"]), NEXT
    )
    later = NEXT + timedelta(days=15)
    _load(worker, connection_id, _steampipe(tmp_path, "back", [_topic(KEPT)], []), later)
    assert _state(owner, DROPPED, later) == (later, False)


def test_edges_stay_with_the_resources_a_narrowed_run_carries(
    tmp_path: Path, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    # Nothing scanned in any region the estate has, so only global resources can go.
    narrowed = _steampipe(tmp_path, "narrowed", [], ["ap-south-1"])
    _load(worker, target.connection_id, narrowed, NEXT)
    write_edges(
        worker,
        rules_dir=RULES_DIR,
        connection_id=target.connection_id,
        day=NEXT,
        ruleset=rule_set(RULES_DIR),
    )
    sql = """
        SELECT count(*) FROM edge_snapshot es JOIN edge e ON e.id = es.edge_id
        JOIN resource a ON a.id = e.source_resource_id
        JOIN resource b ON b.id = e.target_resource_id
        WHERE es.snapshot_date = :d AND e.connection_id = :c
          AND a.region <> 'global' AND b.region <> 'global' AND e.origin LIKE 'rule:%'
    """
    with owner.connect() as conn:
        before = conn.execute(text(sql), {"d": DAY, "c": target.connection_id}).scalar_one()
        after = conn.execute(text(sql), {"d": NEXT, "c": target.connection_id}).scalar_one()
    assert before > 0 and after == before


def _no_cves(tmp_path: Path, name: str, scope: list[str]) -> RawRun:
    """A complete vulnerabilities run that reports nothing, for these regions."""
    root = tmp_path / name
    root.mkdir()
    run = _inspector_run(root, {"aws_inspector2_finding": [], "aws_inspector2_coverage": []})
    return RawRun(manifest=run.manifest.model_copy(update={"region_scope": scope}), root=root)


def _load_cves(owner: Engine, worker: Engine, connection_id: int, run: RawRun) -> dict[str, Any]:
    with owner.connect() as conn:
        scan_run_id = conn.execute(
            text(
                "SELECT max(id) FROM scan_run WHERE connection_id = :c AND tool = 'vulnerabilities'"
            ),
            {"c": connection_id},
        ).scalar_one()
    with worker.begin() as conn:
        return load_vulnerabilities(
            conn,
            batch=parse_inspector(run),
            connection_id=connection_id,
            day=NEXT,
            account_id=run.manifest.account_id,
            scan_run_id=scan_run_id,
        )


def test_a_narrowed_run_resolves_no_cve_outside_its_regions(
    tmp_path: Path, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "vulnerabilities", DAY)
    states = """
        SELECT region, state, count(*) FROM finding
        WHERE tool = 'vulnerabilities' AND connection_id = :c GROUP BY region, state
    """
    with owner.connect() as conn:
        before = {tuple(r) for r in conn.execute(text(states), {"c": target.connection_id})}
    regions = sorted({region for region, _, _ in before})
    assert regions and {state for _, state, _ in before} == {"open"}

    # A region where the account has no CVE: nothing resolves anywhere.
    elsewhere = _load_cves(
        owner, worker, target.connection_id, _no_cves(tmp_path, "elsewhere", ["ap-south-1"])
    )
    assert elsewhere["resolved"] == 0
    with owner.connect() as conn:
        assert {tuple(r) for r in conn.execute(text(states), {"c": target.connection_id})} == before

    # One region: its CVEs resolve, and the others stay open.
    one = _load_cves(owner, worker, target.connection_id, _no_cves(tmp_path, "one", [regions[0]]))
    assert one["resolved"] > 0
    with owner.connect() as conn:
        after = {tuple(r)[:2] for r in conn.execute(text(states), {"c": target.connection_id})}
    assert (regions[0], "resolved") in after and (regions[0], "open") not in after
    assert {(region, "open") for region in regions[1:]} <= after


def test_a_narrowed_run_keeps_the_scan_coverage_of_regions_it_did_not_scan(
    tmp_path: Path, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "vulnerabilities", DAY)
    count = "SELECT count(*) FROM vulnerability_coverage WHERE connection_id = :c"
    with owner.connect() as conn:
        before = conn.execute(text(count), {"c": target.connection_id}).scalar_one()
    assert before > 0

    _load_cves(owner, worker, target.connection_id, _no_cves(tmp_path, "elsewhere", ["ap-south-1"]))
    with owner.connect() as conn:
        assert conn.execute(text(count), {"c": target.connection_id}).scalar_one() == before

    # A run of every region replaces it, as before.
    _load_cves(owner, worker, target.connection_id, _no_cves(tmp_path, "all", []))
    with owner.connect() as conn:
        assert conn.execute(text(count), {"c": target.connection_id}).scalar_one() == 0
