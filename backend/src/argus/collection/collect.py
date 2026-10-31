"""Run one tool against one account into the raw store.

collect() is the single path every source goes through: the source writes files into a
staging directory, then the manifest is built from what is actually on disk and committed
last. A source that raises still produces a committed manifest with status "failed", so a
broken run is visible in run status instead of silently missing. A run the archive refuses
(an S3 upload that fails) is returned as failed too. Anything else that raises after staging
deletes the staged output first. The archive's encryption is reported, not enforced (ADR-0031).
"""

import logging
import traceback
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol
from uuid import UUID

from argus.core.manifest import Manifest, RunStatus, Tool
from argus.core.rawstore import KMS_ENCRYPTION, RawStore, RawStoreError, describe_files
from argus.core.redaction import redact_text

if TYPE_CHECKING:
    from argus.collection.aws.access import AwsAccess

# Throttling layer 1: Steampipe first (cheapest, and it tells us which regions are in use),
# then Prowler, then CloudFox, then Inspector's findings (ADR-0042), after the inventory its
# CVEs attach to.
TOOL_ORDER: tuple[Tool, ...] = ("steampipe", "prowler", "cloudfox", "inspector")
LOG_TAIL_CHARS = 4000
MAX_COMMAND_CHARS = 1000

log = logging.getLogger("argus.collection")


@dataclass(frozen=True)
class CollectTarget:
    connection_id: int
    kind: Literal["demo", "aws"]
    account_id: str
    demo_seed: int | None = None


@dataclass(frozen=True)
class CollectOptions:
    # Demo connections only: the share of runs the synthetic source throttles.
    synthetic_throttle_share: float = 0.05
    # 1 for the first try. The synthetic source varies throttling by attempt, so a retry can
    # succeed where the first attempt was throttled.
    attempt: int = 1
    # AWS connections only: how to reach the account, and the scan's scope (settings).
    aws_access: "AwsAccess | None" = field(default=None, repr=False)
    aws_regions: tuple[str, ...] = ()
    cloudfox_max_goroutines: int = 5
    steampipe_parallel_tables: int = 4


@dataclass
class Outcome:
    status: RunStatus
    exit_code: int
    tool_version: str
    started_at: datetime
    finished_at: datetime
    region_scope: list[str]
    throttle_events: int = 0
    api_regions: int | None = None
    log_lines: list[str] = field(default_factory=list)
    denied_actions: list[str] = field(default_factory=list)
    command: str = ""  # the tool's command line; "" for the synthetic source
    incomplete_tables: list[str] = field(default_factory=list)  # Steampipe only
    refused_actions: list[str] = field(default_factory=list)  # by the resource's own policy
    not_applicable_tables: list[str] = field(default_factory=list)  # Steampipe only
    refused_tables: list[str] = field(default_factory=list)  # Steampipe only


class Source(Protocol):
    name: Literal["synthetic", "aws"]

    def collect(
        self,
        *,
        target: CollectTarget,
        tool: Tool,
        day: date,
        run_uid: UUID,
        out_dir: Path,
        options: CollectOptions,
    ) -> Outcome: ...


def collect(
    source: Source,
    store: RawStore,
    *,
    target: CollectTarget,
    tool: Tool,
    day: date,
    run_uid: UUID,
    options: CollectOptions | None = None,
) -> tuple[str, Manifest]:
    path = store.path_for(tool, target.account_id, day, run_uid)
    run_dir = store.staging_dir(path)
    try:
        return path, _collect_staged(
            source,
            store,
            path=path,
            run_dir=run_dir,
            target=target,
            tool=tool,
            day=day,
            run_uid=run_uid,
            options=options or CollectOptions(),
        )
    except BaseException:
        # Nothing reaches the caller, so nothing would delete the staged output (S3: raw files
        # on the worker's disk that can hold secret values, ADR-0032). The caller records the
        # failure.
        store.release(path)
        raise


def _collect_staged(
    source: Source,
    store: RawStore,
    *,
    path: str,
    run_dir: Path,
    target: CollectTarget,
    tool: Tool,
    day: date,
    run_uid: UUID,
    options: CollectOptions,
) -> Manifest:
    started = datetime.now(UTC)
    context = {"tool": tool, "run_uid": str(run_uid), "connection_id": target.connection_id}
    try:
        outcome = source.collect(
            target=target,
            tool=tool,
            day=day,
            run_uid=run_uid,
            out_dir=run_dir,
            options=options,
        )
    except Exception as exc:  # the run fails; the manifest still records why
        log.exception("collection raised", extra=context)
        outcome = Outcome(
            status="failed",
            exit_code=-1,
            tool_version="unknown",
            started_at=started,
            finished_at=datetime.now(UTC),
            region_scope=[],
            log_lines=traceback.format_exception_only(exc),
        )
    manifest = _manifest(
        source=source,
        target=target,
        tool=tool,
        day=day,
        run_uid=run_uid,
        outcome=outcome,
        run_dir=run_dir,
    )
    # Never the tool's output: CloudFox prints secret values. Counts and states only.
    log.info(
        "collection finished",
        extra={
            **context,
            "status": manifest.status,
            "exit_code": manifest.exit_code,
            "seconds": int((manifest.finished_at - manifest.started_at).total_seconds()),
            "throttle_events": manifest.throttle_events,
            "files": len(manifest.files),
            # The run's size: what staging must hold (ADR-0032).
            "bytes": sum(f.bytes for f in manifest.files),
            "denied_actions": len(manifest.denied_actions),
        },
    )
    try:
        manifest = store.commit(path, manifest)
    except RawStoreError as exc:  # not archived, so not kept: the run fails and resolves nothing
        log.exception("raw output not archived", extra=context)
        tail = redact_text(f"{manifest.log_tail}\nraw output not archived: {exc}")
        return manifest.model_copy(update={"status": "failed", "log_tail": tail[-LOG_TAIL_CHARS:]})
    log.info(
        "raw output stored",
        extra={**context, "files": len(manifest.files), "encryption": manifest.raw_encryption},
    )
    if manifest.raw_encryption is not None and manifest.raw_encryption not in KMS_ENCRYPTION:
        log.warning(
            "raw output stored without KMS: the bucket's default encryption is not SSE-KMS, "
            "and raw output can hold secret values (ADR-0031)",
            extra={**context, "encryption": manifest.raw_encryption},
        )
    return manifest


def _manifest(
    *,
    source: Source,
    target: CollectTarget,
    tool: Tool,
    day: date,
    run_uid: UUID,
    outcome: Outcome,
    run_dir: Path,
) -> Manifest:
    return Manifest(
        run_uid=run_uid,
        tool=tool,
        tool_version=outcome.tool_version,
        account_id=target.account_id,
        source=source.name,
        snapshot_date=day,
        region_scope=outcome.region_scope,
        started_at=outcome.started_at,
        finished_at=outcome.finished_at,
        status=outcome.status,
        exit_code=outcome.exit_code,
        throttle_events=outcome.throttle_events,
        api_regions=outcome.api_regions,
        # Console output can print secret values (CloudFox env-vars); the tail is redacted
        # before it is written anywhere it could be read back.
        log_tail=redact_text("\n".join(outcome.log_lines))[-LOG_TAIL_CHARS:],
        files=describe_files(run_dir),
        denied_actions=outcome.denied_actions,
        command=redact_text(outcome.command)[:MAX_COMMAND_CHARS],
        incomplete_tables=outcome.incomplete_tables,
        refused_actions=outcome.refused_actions,
        not_applicable_tables=outcome.not_applicable_tables,
        refused_tables=outcome.refused_tables,
    )
