"""AwsSource: runs one tool against one AWS account into the run's staging directory."""

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

from argus.collection.aws.tools import (
    run_cloudfox,
    run_inspector,
    run_prowler,
    run_steampipe,
    tool_profile,
)
from argus.collection.collect import CollectOptions, CollectTarget, Outcome
from argus.core.manifest import Tool


class AwsSource:
    name: Literal["synthetic", "aws"] = "aws"

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
        if options.aws_access is None:
            raise ValueError("an AWS run needs the connection's access")
        started = datetime.now(UTC)
        regions = list(options.aws_regions)
        credentials = options.aws_access.credentials(session_name=f"argus-{run_uid.hex[:24]}")
        with tool_profile(credentials, regions[0] if regions else "us-east-1") as env:
            if tool == "steampipe":
                result = run_steampipe(out_dir, env, regions, options.steampipe_parallel_tables)
            elif tool == "prowler":
                result = run_prowler(out_dir, env, regions)
            elif tool == "inspector":
                result = run_inspector(out_dir, env, regions, target.account_id)
            else:
                result = run_cloudfox(
                    out_dir, env, target.account_id, options.cloudfox_max_goroutines
                )
        return Outcome(
            status=result.status,  # type: ignore[arg-type]
            exit_code=result.exit_code,
            tool_version=result.tool_version,
            started_at=started,
            finished_at=datetime.now(UTC),
            # The regions asked for. CloudFox ignores the setting and scans every enabled
            # region, as do the others when none is set: an empty scope means every region.
            region_scope=[] if tool == "cloudfox" else regions,
            throttle_events=result.throttle_events,
            api_regions=None if tool == "cloudfox" else len(regions) or None,
            log_lines=result.log_lines,
            denied_actions=result.denied_actions,
            command=result.command,
            incomplete_tables=result.incomplete_tables,
            refused_actions=result.refused_actions,
            not_applicable_tables=result.not_applicable_tables,
            refused_tables=result.refused_tables,
        )
