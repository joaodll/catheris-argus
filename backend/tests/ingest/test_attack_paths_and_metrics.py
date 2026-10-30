from datetime import date, timedelta

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import TOOL_ORDER, CollectOptions, FilesystemRawStore
from argus.collection.synthetic.estate import (
    SCENARIO_INSTANCE,
    SCENARIO_PEER,
    SCENARIO_ROLE,
    UNKNOWN_INSTANCE,
)
from argus.findings import ResolvedCommand, commands_for_resource, load_commands
from argus.retention import run_retention

pytestmark = pytest.mark.db
DAY = date(2026, 10, 2)


def _day(
    worker: Engine,
    store: FilesystemRawStore,
    target,
    day: date,  # type: ignore[no-untyped-def]
    cloudfox_options: CollectOptions | None = None,
) -> None:
    for tool in TOOL_ORDER:
        options = cloudfox_options if tool == "cloudfox" and cloudfox_options else None
        if options:
            run_tool(worker, store, target, tool, day, options)
        else:
            run_tool(worker, store, target, tool, day)


def _metric(engine: Engine, metric: str, dimension: str, connection_id: int, day: date) -> float:
    with engine.connect() as conn:
        value = conn.execute(
            text(
                "SELECT value FROM metric_daily WHERE metric = :m AND dimension = :d "
                "AND connection_id = :c AND snapshot_date = :day"
            ),
            {"m": metric, "d": dimension, "c": connection_id, "day": day},
        ).scalar_one()
    return float(value)


def test_the_scenario_becomes_a_critical_path_joined_to_a_failing_check(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        instance_uid = conn.execute(
            text("SELECT resource_uid FROM resource WHERE name = :n"), {"n": SCENARIO_INSTANCE}
        ).scalar_one()
        paths = conn.execute(
            text(
                "SELECT rule_id, category, severity, confidence, node_uids FROM attack_path "
                "WHERE state = 'open'"
            )
        ).all()
    iam = [p for p in paths if p.rule_id == "internet-to-admin" and p.node_uids[1] == instance_uid]
    assert iam, paths
    path = iam[0]
    # The search (ADR-0037): internet -> the instance -> its role -> administrator.
    assert path.node_uids[0] == "internet"
    assert path.node_uids[2].endswith(f":role/{SCENARIO_ROLE}")
    assert path.node_uids[3] == f"admin:{target.account_id}"
    assert path.category == "IAM privilege escalation"
    # Base high, +1 because Argus confirmed the entry, kept because the instance has a failing
    # critical Prowler check (SSH open to the internet). Its weakest step is the role the
    # instance runs as: supported by configuration.
    assert path.severity == "critical"
    assert path.confidence == "supported"


def test_cloudfox_edges_and_secret_findings_without_values(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        types = set(
            conn.execute(text("SELECT DISTINCT type FROM edge WHERE origin = 'cloudfox'")).scalars()
        )
        found = conn.execute(
            text("SELECT check_id, title, f::text AS row FROM finding f WHERE tool = 'cloudfox'")
        ).all()
    assert {"CAN_PRIVESC_TO", "IS_ADMIN", "CAN_ASSUME"} <= types
    secrets = [f for f in found if f.check_id == "cloudfox_env_var_secret"]
    assert secrets and all("DB_PASSWORD" in s.title for s in secrets)
    assert {f.check_id for f in found} == {
        "cloudfox_env_var_secret",
        "cloudfox_role_privesc_to_admin",
        "cloudfox_cross_account_root_trust_no_external_id",
        "cloudfox_public_endpoint",
    }
    assert not any("pw-" in f.row for f in found)


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


def test_a_partial_cloudfox_run_resolves_no_path(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    _day(
        worker,
        store,
        target,
        DAY + timedelta(days=1),
        cloudfox_options=CollectOptions(synthetic_throttle_share=1.0),
    )
    with owner.connect() as conn:
        resolved = conn.execute(
            text("SELECT count(*) FROM attack_path WHERE state = 'resolved'")
        ).scalar_one()
        open_paths = conn.execute(
            text("SELECT count(*) FROM attack_path WHERE state = 'open'")
        ).scalar_one()
    assert resolved == 0 and open_paths > 0


def test_overview_metrics_for_each_connection_and_all(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    prod, staging = make_demo(owner, 0), make_demo(owner, 1)
    _day(worker, store, prod, DAY)
    _day(worker, store, staging, DAY)
    for metric, dimension in (
        ("assets.total", ""),
        ("checks.status", "PASS"),
        ("findings.open_by_severity", "critical"),
        ("threatscore.score", ""),
        ("compliance.score", "cis_6.0_aws"),
    ):
        for cid in (prod.connection_id, staging.connection_id, 0):
            _metric(owner, metric, dimension, cid, DAY)
    assert _metric(owner, "assets.total", "", 0, DAY) == (
        _metric(owner, "assets.total", "", prod.connection_id, DAY)
        + _metric(owner, "assets.total", "", staging.connection_id, DAY)
    )
    num = sum(
        _metric(owner, "threatscore.numerator", "", c, DAY)
        for c in (prod.connection_id, staging.connection_id)
    )
    den = sum(
        _metric(owner, "threatscore.denominator", "", c, DAY)
        for c in (prod.connection_id, staging.connection_id)
    )
    assert _metric(owner, "threatscore.score", "", 0, DAY) == pytest.approx(100 * num / den)
    assert 0 < _metric(owner, "threatscore.score", "", 0, DAY) < 100
    with owner.connect() as conn:
        pillars = set(
            conn.execute(
                text(
                    "SELECT dimension FROM metric_daily WHERE metric = 'threatscore.score' "
                    "AND connection_id = 0 AND dimension <> ''"
                )
            ).scalars()
        )
    assert {"1. IAM", "2. Attack Surface"} <= pillars
    assert _metric(owner, "attack_paths.open_by_category", "IAM privilege escalation", 0, DAY) >= 1


def test_retention_drops_old_history_and_prunes_demo_raw(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    old = DAY - timedelta(days=400)
    run_tool(worker, store, target, "steampipe", old)
    run_tool(worker, store, target, "steampipe", DAY)
    result = run_retention(worker, store=store, today=DAY, retention_days=180, demo_raw_days=7)
    assert f"resource_snapshot_{old:%Y%m}" in result.partitions_dropped
    assert result.demo_runs_pruned == 1
    with owner.connect() as conn:
        days = set(
            conn.execute(text("SELECT DISTINCT snapshot_date FROM resource_snapshot")).scalars()
        )
    assert days == {DAY}


def test_the_scenario_also_yields_lateral_movement_to_the_private_peer(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        peer_uid = conn.execute(
            text("SELECT resource_uid FROM resource WHERE name = :n"), {"n": SCENARIO_PEER}
        ).scalar_one()
        targets = set(
            conn.execute(
                text("SELECT target_uid FROM attack_path WHERE rule_id = 'internet-lateral-ssh'")
            ).scalars()
        )
    assert peer_uid in targets


def _uid(engine: Engine, name: str) -> str:
    with engine.connect() as conn:
        uid: str = conn.execute(
            text("SELECT resource_uid FROM resource WHERE name = :n"), {"n": name}
        ).scalar_one()
    return uid


def test_the_search_trusts_argus_over_cloudfox_and_shows_what_it_cannot_tell(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """ADR-0037: a door Argus calls restricted starts only latent paths (blocked), even when
    CloudFox calls it public; a door Argus cannot judge starts a path whose confidence is
    Unknown. Latent paths are not counted on the Overview."""
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        restricted = set(
            conn.execute(
                text(
                    "SELECT target_uid FROM edge WHERE source_uid = 'internet' "
                    "AND type = 'PUBLIC_RESTRICTED'"
                )
            ).scalars()
        )
        cloudfox_public = set(
            conn.execute(
                text(
                    "SELECT target_uid FROM edge WHERE source_uid = 'internet' "
                    "AND origin = 'cloudfox'"
                )
            ).scalars()
        )
        entries = set(
            conn.execute(
                text(
                    "SELECT entry_uid FROM attack_path WHERE state = 'open' "
                    "AND confidence <> 'blocked'"
                )
            ).scalars()
        )
        latent = conn.execute(
            text(
                "SELECT entry_uid, confidence FROM attack_path WHERE state = 'open' "
                "AND entry_uid = ANY(CAST(:r AS text[]))"
            ),
            {"r": sorted(restricted)},
        ).all()
        counted = conn.execute(
            text(
                "SELECT COALESCE(sum(value), 0) FROM metric_daily WHERE connection_id = :c "
                "AND snapshot_date = :d AND metric = 'attack_paths.open_by_severity'"
            ),
            {"c": target.connection_id, "d": DAY},
        ).scalar_one()
        not_blocked = conn.execute(
            text(
                "SELECT count(*) FROM attack_path WHERE connection_id = :c AND state = 'open' "
                "AND confidence <> 'blocked'"
            ),
            {"c": target.connection_id},
        ).scalar_one()
        unknown = conn.execute(
            text(
                "SELECT rule_id, confidence, severity FROM attack_path "
                "WHERE state = 'open' AND entry_uid = :e"
            ),
            {"e": _uid(owner, UNKNOWN_INSTANCE)},
        ).all()
    assert restricted & cloudfox_public, "the demo lost its restricted door CloudFox calls public"
    assert not entries & restricted
    assert latent and {p.confidence for p in latent} == {"blocked"}
    assert counted == not_blocked
    assert ("internet-to-admin", "unknown") in {(p.rule_id, p.confidence) for p in unknown}
    # Not raised: Argus did not confirm the entry.
    assert all(p.severity != "critical" for p in unknown)


def test_the_search_stops_at_the_cap(
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("argus.attackpaths.search.MAX_PATHS", 2)
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM attack_path WHERE state = 'open'")
        ).scalar_one()
    assert count == 2
    assert "attack paths cut at the cap" in caplog.text


def test_a_complete_run_closes_paths_of_a_kind_that_is_gone(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A path a pre-ADR-0037 rule found, still open on the day of the upgrade, is resolved by
    that day's complete run: no kind can find it again."""
    target = make_demo(owner)
    with owner.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO attack_path (path_id, rule_id, rule_version, category, severity,
                                     connection_id, entry_uid, target_uid, node_uids, edge_ids,
                                     state, first_seen, last_seen)
            VALUES (sha256('old'::bytea), 'internet-chain-to-admin', 1,
                    'IAM privilege escalation', 'high', :c, 'internet', 'admin:x',
                    ARRAY['internet', 'admin:x'], ARRAY[]::bigint[], 'open', :d, :d)
        """),
            {"c": target.connection_id, "d": DAY},
        )
    _day(worker, store, target, DAY)
    with owner.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM attack_path WHERE rule_id = 'internet-chain-to-admin'")
        ).scalar_one()
    assert state == "resolved"


def test_paths_follow_every_ingest_and_a_late_run_closes_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Paths are computed after every ingest, on the latest day either edge family stands for
    (ADR-0037, second amendment): a Steampipe retry that lands after the next day's CloudFox
    run evaluates that later day and resolves nothing, and Prowler updates severities."""
    target = make_demo(owner)
    _day(worker, store, target, DAY)
    later = DAY + timedelta(days=1)

    def paths() -> dict[str, tuple[str, date]]:
        with owner.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT encode(path_id, 'hex') AS pid, state, last_seen FROM attack_path "
                    "WHERE connection_id = :c"
                ),
                {"c": target.connection_id},
            )
            return {r.pid: (r.state, r.last_seen) for r in rows}

    before = paths()
    assert before and {s for s, _ in before.values()} == {"open"}
    run_tool(worker, store, target, "cloudfox", later)
    run_tool(worker, store, target, "steampipe", DAY)  # the late retry
    after = paths()
    assert after.keys() == before.keys()
    assert set(after.values()) == {("open", later)}
    run_tool(worker, store, target, "prowler", later + timedelta(days=1))
    assert {s for s, _ in paths().values()} == {"open"}


def test_prowler_alone_leaves_attack_paths_not_covered(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Paths follow every ingest, but a connection with no edges yet has nothing to search: no
    path metrics, so the Overview says "not covered", never 0 paths."""
    target = make_demo(owner)
    run_tool(worker, store, target, "prowler", DAY)
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT count(*) FROM metric_daily WHERE connection_id = :c "
                "AND metric LIKE 'attack_paths.%'"
            ),
            {"c": target.connection_id},
        ).scalar_one()
    assert rows == 0
