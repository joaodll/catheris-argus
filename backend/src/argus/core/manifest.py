"""manifest.json: the one definition of a run's manifest (written last, read first).

A run directory without a manifest is incomplete and is never ingested. The manifest lists
every file with its size and SHA-256, so a reader detects a truncated or altered run.
"""

from datetime import date, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

MANIFEST_NAME = "manifest.json"
Tool = Literal["steampipe", "prowler", "cloudfox"]
RunStatus = Literal["complete", "partial", "failed"]
MAX_DENIED_ACTIONS = 200


class ManifestFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(pattern=r"^[A-Za-z0-9_.@:+=,/-]+$")
    bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    run_uid: UUID
    tool: Tool
    tool_version: str
    provider: Literal["aws"] = "aws"
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    source: Literal["synthetic", "aws"]
    snapshot_date: date
    region_scope: list[str]
    started_at: datetime
    finished_at: datetime
    status: RunStatus
    exit_code: int
    throttle_events: int = Field(ge=0)
    api_regions: int | None = None
    log_tail: str = ""
    files: list[ManifestFile]
    # Actions the scanning identity was refused, e.g. "ec2:GetLaunchTemplateData", so the UI
    # can say which data is missing. A botocore message names only the operation.
    denied_actions: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9:*_-]{1,128}$")]] = Field(
        default_factory=list, max_length=MAX_DENIED_ACTIONS
    )
    # The weakest server-side encryption S3 reported for the run's objects (ADR-0031); None
    # when the store does not encrypt (the local volume) or the run has no files.
    raw_encryption: str | None = Field(None, pattern=r"^[A-Za-z0-9:_-]{1,32}$")
    # "gzip": each listed file is archived as <path>.gz; `files` describes the uncompressed
    # content (as staged and ingested). None: stored as listed (the local volume, older runs).
    # The manifest itself is never compressed.
    raw_compression: Literal["gzip"] | None = None
    # Steampipe: the tables carried forward: failed, denied, throttled, not applicable or
    # refused. They resolve nothing; every other table of the run is complete (argus_v8), a
    # complete run included (2026-10-21). Empty on a partial run written before 2026-10-08:
    # then nothing in it is complete.
    incomplete_tables: list[Annotated[str, Field(pattern=r"^aws_[a-z0-9_]{1,80}$")]] = Field(
        default_factory=list, max_length=1000
    )
    # Actions a resource's own policy refused ("because no resource-based policy allows"):
    # not something the role can fix (ADR-0012, second amendment).
    refused_actions: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9:*_-]{1,128}$")]] = Field(
        default_factory=list, max_length=MAX_DENIED_ACTIONS
    )
    # Steampipe: the incomplete tables whose every error said the service does not apply to
    # the account, and those a resource's own policy refused. Both are in incomplete_tables
    # (carried forward) and neither makes the run partial.
    not_applicable_tables: list[Annotated[str, Field(pattern=r"^aws_[a-z0-9_]{1,80}$")]] = Field(
        default_factory=list, max_length=1000
    )
    refused_tables: list[Annotated[str, Field(pattern=r"^aws_[a-z0-9_]{1,80}$")]] = Field(
        default_factory=list, max_length=1000
    )
    # The tool's command line as Argus ran it (temporary paths shortened, no credential in it);
    # "" for the synthetic source and for manifests written before it was recorded.
    command: str = Field("", max_length=1000)
