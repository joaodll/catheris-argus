"""SyntheticSource: writes what Prowler, CloudFox, Steampipe or the vulnerabilities collector
(AWS Inspector's export, on a demo AWS account) would write for a demo account.

Run outcomes are deterministic per (account, tool, day):
- Throttling: a share of runs (an administration setting) reports ThrottlingException lines
  and loses part of its output, so the run is "partial" and must resolve nothing.
- Failure: Prowler on the staging profile fails every 47th day, killed mid-write with an
  unterminated OCSF file and exit code 1.
"""

from datetime import date, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

from argus.collection.collect import CollectOptions, CollectTarget, Outcome
from argus.collection.synthetic import cloudfox, inspector, prowler, steampipe
from argus.collection.synthetic.estate import Estate, day_number
from argus.collection.synthetic.model import h, u
from argus.collection.tables import steampipe_tables
from argus.core.manifest import Tool

FAIL_EVERY_DAYS = 47
SECONDS_PER_ROW = {"steampipe": 0.02, "prowler": 0.05, "cloudfox": 0.03, "vulnerabilities": 0.01}


class SyntheticSource:
    name: Literal["synthetic", "aws"] = "synthetic"

    def collect(
        self,
        *,
        target: CollectTarget,
        tool: Tool,
        day: date,
        run_uid: UUID,
        out_dir: Path,
        options: CollectOptions,
    ) -> Outcome:
        if target.demo_seed is None:
            raise ValueError("a demo connection needs a demo seed")
        model = Estate(target.account_id, target.demo_seed)
        estate = model.at(day)
        account = target.account_id
        throttle_key = (account, tool, day, "throttle") + (
            () if options.attempt == 1 else (options.attempt,)
        )
        throttled = u(*throttle_key) < options.synthetic_throttle_share
        failed = (
            tool == "prowler"
            and model.profile.label == "staging"
            and day_number(day) % FAIL_EVERY_DAYS == 0
        )
        throttle_events = 3 + h(account, tool, day, "events") % 40 if throttled else 0
        started = prowler.scan_time_for(estate, h(account, "offset") % 180)
        log_lines = [f"[synthetic] {tool} for account {account} on {day.isoformat()}"]
        log_lines += [
            f"ThrottlingException: Rate exceeded (Service: EC2, region "
            f"{estate.profile.regions[i % len(estate.profile.regions)]})"
            for i in range(min(throttle_events, 5))
        ]

        incomplete: list[str] = []
        if tool == "steampipe":
            tables = [t for t in steampipe_tables() if t in steampipe.TABLES]
            rows = steampipe.write(
                out_dir, estate, tables, keep_tables=len(tables) - 3 if throttled else None
            )
            # A throttled run loses its last three tables; the others are complete.
            incomplete = tables[-3:] if throttled else []
            version = steampipe.TOOL_VERSION
        elif tool == "prowler":
            rows = prowler.write(
                out_dir,
                estate,
                model,
                started,
                str(run_uid),
                drop_share=0.2 if throttled else 0.0,
                failed=failed,
            )
            version = prowler.TOOL_VERSION
        elif tool == "vulnerabilities":
            # A throttled run loses the findings table: it resolves nothing.
            rows = inspector.write(out_dir, estate, keep_findings=not throttled)
            incomplete = [inspector.FINDINGS_TABLE] if throttled else []
            version = inspector.TOOL_VERSION
        else:
            rows = cloudfox.write(out_dir, estate, keep_modules=3 if throttled else None)
            version = cloudfox.TOOL_VERSION

        status: Literal["complete", "partial", "failed"] = "complete"
        exit_code = 0
        if failed:
            status, exit_code = "failed", 1
            log_lines.append("Killed: prowler terminated before the output was closed")
        elif throttled:
            status = "partial"
            log_lines.append(f"{throttle_events} throttling errors; output is incomplete")
        finished = started + timedelta(seconds=int(rows * SECONDS_PER_ROW[tool]) + 5)
        return Outcome(
            status=status,
            exit_code=exit_code,
            tool_version=version,
            started_at=started,
            finished_at=finished,
            region_scope=list(estate.profile.regions),
            throttle_events=throttle_events,
            api_regions=len(estate.profile.regions),
            log_lines=log_lines,
            incomplete_tables=incomplete,
        )
