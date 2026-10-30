"""One run, from committed raw files to canonical rows, snapshots, paths and metrics.

    steampipe  inventory -> relationship rules -> inventory metrics
    prowler    findings lifecycle + compliance -> findings metrics
    cloudfox   cloudfox edges + attacker findings -> attack paths -> path metrics

A run that failed collection, or whose raw output cannot be trusted (no manifest, files that
do not match it, an unsupported tool version), is recorded as failed, resolves nothing, and
its tool's metrics carry the previous day forward, so charts show neither a gap nor a false
improvement. Attack paths are only resolved when the day's CloudFox run is complete.

An unexpected error while loading is recorded the same way, so the Runs tab shows the run as
failed with the error in its log tail, and the worker retries it like any failed run. A
Steampipe or CloudFox load commits before its rules run, so a failure in the rules can leave
that day's rows in place; the retry replaces them.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import Connection, Engine, text

from argus import connections, metrics
from argus.attackpaths import (
    PUBLIC_ENDPOINT_CHECK,
    evaluate_paths,
    load_cloudfox,
    load_path_kinds,
    parse_cloudfox,
)
from argus.attackpaths.cloudfox import UnsupportedVersionError as CloudFoxVersionError
from argus.attackpaths.engine import PATH_METRICS
from argus.core.manifest import Manifest
from argus.core.rawstore import RawRun, RawRunError, RawStore, read_run
from argus.core.redaction import redact_text
from argus.findings import (
    FINDING_ADDITIVE_METRICS,
    PROWLER_EXPOSURE_CHECKS,
    carry_forward_compliance,
    load_prowler,
    parse_prowler,
    put_findings_metrics,
    rederive_scores,
    set_reach,
)
from argus.findings.prowler import UnsupportedVersionError as ProwlerVersionError
from argus.inventory import (
    INVENTORY_METRICS,
    load_inventory,
    parse_steampipe,
    put_inventory_metrics,
)
from argus.inventory.steampipe import UnsupportedVersionError as SteampipeVersionError
from argus.relationships import (
    internet_reach,
    latest_load_day,
    load_rules,
    write_edges,
    write_flows,
)

log = logging.getLogger("argus.ingest")
# Held shared by every ingest and exclusive by a re-derive after a rule upgrade (rederive.py),
# so the two never interleave on one connection's edges, flows and paths (ADR-0039).
REDERIVE_LOCK = "argus.rederive"
VERSION_ERRORS = (SteampipeVersionError, ProwlerVersionError, CloudFoxVersionError)
TOOL_METRICS = {
    "steampipe": INVENTORY_METRICS,
    "prowler": FINDING_ADDITIVE_METRICS,
    "cloudfox": PATH_METRICS,
}


@dataclass
class IngestOutcome:
    scan_run_id: int
    status: str
    loaded: dict[str, int] = field(default_factory=dict)
    error: str | None = None


@dataclass(frozen=True)
class _Run:
    scan_run_id: int
    connection_id: int
    account_id: str
    tool: str
    day: date
    raw_path: str
    status: str


def register_run(conn: Connection, *, connection_id: int, raw_path: str, manifest: Manifest) -> int:
    scan_run_id: int = conn.execute(
        text("""
            INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source,
                                  snapshot_date, region_scope, status, started_at, finished_at,
                                  raw_path, exit_code, throttle_events, api_regions, log_tail,
                                  denied_actions, raw_encryption, command, incomplete_tables,
                                  refused_actions, not_applicable_tables, refused_tables)
            VALUES (:uid, :c, :tool, :version, :source, :day, :regions, :status, :started,
                    :finished, :path, :exit, :throttle, :api_regions, :log, :denied,
                    :encryption, :command, :incomplete, :refused, :not_applicable,
                    :refused_tables)
            RETURNING id
        """),
        {
            "uid": manifest.run_uid,
            "c": connection_id,
            "tool": manifest.tool,
            "version": manifest.tool_version,
            "source": manifest.source,
            "day": manifest.snapshot_date,
            "regions": manifest.region_scope,
            "status": manifest.status,
            "started": manifest.started_at,
            "finished": manifest.finished_at,
            "path": raw_path,
            "exit": manifest.exit_code,
            "throttle": manifest.throttle_events,
            "api_regions": manifest.api_regions,
            "log": redact_text(manifest.log_tail),  # the manifest is input: redact again
            "denied": manifest.denied_actions,
            "encryption": manifest.raw_encryption,
            "command": redact_text(manifest.command)[:1000],  # input too
            "incomplete": manifest.incomplete_tables,
            "refused": manifest.refused_actions,
            "not_applicable": manifest.not_applicable_tables,
            "refused_tables": manifest.refused_tables,
        },
    ).scalar_one()
    return scan_run_id


def register_failed_run(
    conn: Connection,
    *,
    connection_id: int,
    tool: str,
    source: str,
    day: date,
    run_uid: UUID,
    raw_path: str,
    started_at: datetime,
    error: str,
) -> int:
    """Records a request that failed before a manifest could be registered (no bucket set, a
    manifest the database refused), so the Runs tab shows it with the reason instead of
    nothing. raw_path is where the run was archived, or "" when collection never ran. The
    caller passes the run to ingest_run, which carries the tool's metrics forward."""
    scan_run_id: int = conn.execute(
        text("""
            INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source,
                                  snapshot_date, status, started_at, finished_at, raw_path,
                                  exit_code, log_tail)
            VALUES (:uid, :c, :tool, 'unknown', :source, :day, 'failed', :started,
                    greatest(now(), :started), :path, -1, :log)
            RETURNING id
        """),
        {
            "uid": run_uid,
            "c": connection_id,
            "tool": tool,
            "source": source,
            "day": day,
            "started": started_at,
            "path": raw_path,
            "log": redact_text(f"argus: the run ended before it was recorded: {error}")[-4000:],
        },
    ).scalar_one()
    return scan_run_id


def _load_run(engine: Engine, scan_run_id: int) -> _Run:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT s.connection_id, c.account_id, s.tool, s.snapshot_date, s.raw_path, "  # noqa: S608
                f"s.status FROM scan_run s JOIN ({connections.DIRECTORY_SQL}) c "
                "ON c.id = s.connection_id WHERE s.id = :i"
            ),
            {"i": scan_run_id},
        ).one()
    return _Run(
        scan_run_id,
        row.connection_id,
        row.account_id,
        row.tool,
        row.snapshot_date,
        row.raw_path,
        row.status,
    )


def _fail(engine: Engine, run: _Run, reason: str | None) -> IngestOutcome:
    """Records the failure and carries the tool's metrics forward for the day."""
    with engine.begin() as conn:
        conn.execute(text("SELECT argus_ensure_partitions(:d, :d)"), {"d": run.day})
        conn.execute(
            text(
                "UPDATE scan_run SET status = 'failed', ingested_at = now(), "
                "log_tail = CASE WHEN CAST(:r AS text) IS NULL THEN log_tail ELSE "
                "right(coalesce(log_tail, '') || E'\\n' || :r, 4000) END WHERE id = :i"
            ),
            {
                "r": redact_text(f"ingest refused the run: {reason}") if reason else None,
                "i": run.scan_run_id,
            },
        )
        if run.tool == "prowler":
            # Before the metrics: a load takes the compliance lock, then the metrics lock.
            carry_forward_compliance(conn, day=run.day, connection_id=run.connection_id)
        tool_metrics = TOOL_METRICS[run.tool]
        metrics.copy_previous(
            conn, day=run.day, connection_id=run.connection_id, metrics=tool_metrics
        )
        metrics.rollup(conn, day=run.day, metrics=tool_metrics)
        if run.tool == "prowler":
            rederive_scores(conn, connection_id=run.connection_id, day=run.day)
    return IngestOutcome(run.scan_run_id, "failed", error=reason)


def _steampipe(engine: Engine, run: _Run, raw: RawRun, rules_dir: Path) -> dict[str, int]:
    batch = parse_steampipe(raw)
    with engine.begin() as conn:
        loaded = load_inventory(conn, batch=batch, connection_id=run.connection_id, day=run.day)
    loaded["edges"] = write_edges(
        engine,
        rules_dir=rules_dir,
        connection_id=run.connection_id,
        day=run.day,
        ruleset=rule_set(rules_dir),
    )
    loaded["flows"] = write_flows(engine, connection_id=run.connection_id, day=run.day)
    with engine.begin() as conn:
        put_inventory_metrics(conn, connection_id=run.connection_id, day=run.day)
        loaded["reach_checked"] = check_reach(conn, connection_id=run.connection_id, day=run.day)
    loaded |= evaluate_after(
        engine,
        rules_dir=rules_dir,
        connection_id=run.connection_id,
        day=run.day,
        resolve=batch.complete,
    )
    return loaded


def paths_day(conn: Connection, *, connection_id: int, day: date) -> date:
    """Where paths are evaluated after a run of `day`: the latest day either edge family stands
    for, never an earlier one, so a run that lands late (a retry after the next day's runs)
    never evaluates an older picture (ADR-0037, second amendment)."""
    latest = latest_load_day(conn, connection_id=connection_id)
    return max(day, latest) if latest else day


def evaluate_after(
    engine: Engine, *, rules_dir: Path, connection_id: int, day: date, resolve: bool
) -> dict[str, int]:
    """Attack paths after any ingest (ADR-0037, second amendment): Steampipe changes the rule
    edges, CloudFox its own, Prowler the severities. Resolves only when asked and when the
    paths are evaluated on the run's own day: a late run never closes what a later day found.
    With no edge load yet (Prowler before Steampipe and CloudFox) there is nothing to search,
    and the Overview keeps "not covered" instead of 0 paths."""
    with engine.connect() as conn:
        if latest_load_day(conn, connection_id=connection_id) is None:
            return {}
        on = paths_day(conn, connection_id=connection_id, day=day)
    paths = evaluate_paths(
        engine,
        rules_dir=rules_dir,
        connection_id=connection_id,
        day=on,
        resolve=resolve and on == day,
    )
    return {f"paths_{k}": v for k, v in paths.items()}


def rule_set(rules_dir: Path) -> str:
    """What derived a day's edges, reach checks and paths: a SHA-256 of every relationship
    rule's and path kind's id and version (edge_load.ruleset, ADR-0035 fifth amendment) and of
    the checks whose findings carry Argus's reach (sixth amendment). So a release that starts
    checking more findings re-derives once at start, and findings already stored get their
    verdict then, not at the next scan."""
    names = [f"relationship:{r.id}@{r.version}" for r in load_rules(rules_dir)]
    names += [f"path:{k.id}@{k.version}" for k in load_path_kinds(rules_dir)]
    names += [f"reach:{c}" for c in (PUBLIC_ENDPOINT_CHECK, *PROWLER_EXPOSURE_CHECKS)]
    return hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()


def check_reach(conn: Connection, *, connection_id: int, day: date) -> int:
    """CloudFox calls an endpoint public from its settings, and Prowler a port exposed when a
    group is open; Argus's internet rules say whether traffic can really arrive, and why
    (ADR-0035, sixth amendment). Run after every tool and after a re-derive, whichever comes
    last. Returns how many findings changed."""
    reach = internet_reach(conn, connection_id=connection_id, day=day)
    doors = {uid: (d.reach, d.reason) for uid, d in reach.doors.items()}
    endpoints = set_reach(
        conn, connection_id=connection_id, check_ids=(PUBLIC_ENDPOINT_CHECK,), doors=doors
    )
    exposure = set_reach(
        conn,
        connection_id=connection_id,
        check_ids=PROWLER_EXPOSURE_CHECKS,
        doors=doors,
        rules_judge=True,
        rule_day=reach.day,
    )
    return endpoints + exposure


def _prowler(engine: Engine, run: _Run, raw: RawRun, rules_dir: Path) -> dict[str, int]:
    batch = parse_prowler(raw)
    with engine.begin() as conn:
        loaded = load_prowler(
            conn,
            batch=batch,
            connection_id=run.connection_id,
            day=run.day,
            account_id=run.account_id,
            scan_run_id=run.scan_run_id,
        )
        put_findings_metrics(conn, connection_id=run.connection_id, day=run.day)
        loaded["reach_checked"] = check_reach(conn, connection_id=run.connection_id, day=run.day)
    # Prowler changes severities (a failing finding on the way), never which paths exist.
    loaded |= evaluate_after(
        engine, rules_dir=rules_dir, connection_id=run.connection_id, day=run.day, resolve=False
    )
    return loaded


def _cloudfox(engine: Engine, run: _Run, raw: RawRun, rules_dir: Path) -> dict[str, int]:
    batch = parse_cloudfox(raw)
    with engine.begin() as conn:
        loaded = load_cloudfox(
            conn,
            batch=batch,
            connection_id=run.connection_id,
            day=run.day,
            account_id=run.account_id,
            scan_run_id=run.scan_run_id,
        )
        loaded["reach_checked"] = check_reach(conn, connection_id=run.connection_id, day=run.day)
    return loaded | evaluate_after(
        engine,
        rules_dir=rules_dir,
        connection_id=run.connection_id,
        day=run.day,
        resolve=batch.complete,
    )


def ingest_run(
    engine: Engine, *, store: RawStore, scan_run_id: int, rules_dir: Path
) -> IngestOutcome:
    """Ingests one registered run, holding the re-derive lock shared on a connection of its own
    for the whole run: it spans several transactions."""
    with engine.connect() as lock:
        lock.execute(text("SELECT pg_advisory_lock_shared(hashtext(:k))"), {"k": REDERIVE_LOCK})
        lock.commit()
        try:
            return _ingest(engine, store=store, scan_run_id=scan_run_id, rules_dir=rules_dir)
        finally:
            lock.execute(
                text("SELECT pg_advisory_unlock_shared(hashtext(:k))"), {"k": REDERIVE_LOCK}
            )
            lock.commit()


def _ingest(engine: Engine, *, store: RawStore, scan_run_id: int, rules_dir: Path) -> IngestOutcome:
    run = _load_run(engine, scan_run_id)
    if run.status == "failed":
        return _fail(engine, run, None)
    try:
        raw = read_run(store, run.raw_path)
    except (RawRunError, ValueError) as exc:
        return _fail(engine, run, str(exc))

    with engine.begin() as conn:
        conn.execute(text("SELECT argus_ensure_partitions(:d, :d)"), {"d": run.day})
    try:
        if run.tool == "steampipe":
            loaded = _steampipe(engine, run, raw, rules_dir)
        elif run.tool == "prowler":
            loaded = _prowler(engine, run, raw, rules_dir)
        else:
            loaded = _cloudfox(engine, run, raw, rules_dir)
    except VERSION_ERRORS as exc:
        return _fail(engine, run, str(exc))
    except Exception as exc:  # any other ingest error: the run must not stay "complete"
        log.exception("ingest failed", extra={"scan_run_id": scan_run_id, "tool": run.tool})
        return _fail(engine, run, f"{type(exc).__name__}: {exc}")

    with engine.begin() as conn:
        conn.execute(
            text("UPDATE scan_run SET ingested_at = now() WHERE id = :i"), {"i": scan_run_id}
        )
    log.info(
        "run ingested",
        extra={"scan_run_id": scan_run_id, "tool": run.tool, "day": run.day.isoformat(), **loaded},
    )
    return IngestOutcome(scan_run_id, run.status, loaded)
