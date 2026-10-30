"""Runs Steampipe export, Prowler and CloudFox, unmodified (ADR-0001), against one account.

Read-only by construction: each command line below is the complete set of flags. Never add a
Prowler --fixer, --security-hub, --scan-secrets-validate, --shodan or --slack, or a CloudFox
module that acts on a target: they write to the account, push findings out, or use discovered
secrets against live services (CLAUDE.md, read-only rule).

Each tool sees one private AWS profile, written for the run into a temporary home and deleted
after it, and an environment built from nothing: Argus's own variables (database password,
credential keyring) never reach a tool process.
"""

import logging
import os
import pwd
import re
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import IO

from argus.collection.tables import steampipe_tables, table_options
from argus.core.aws import SessionCredentials
from argus.core.manifest import MAX_DENIED_ACTIONS

logger = logging.getLogger("argus.collection")
PROFILE = "argus"
# Absolute paths, as the worker image installs them (backend/Dockerfile, target worker).
PROWLER = "/opt/prowler/bin/prowler"
PROWLER_PYTHON = "/opt/prowler/bin/python"
STEAMPIPE = "/usr/local/bin/steampipe_export_aws"
CLOUDFOX = "/usr/local/bin/cloudfox"
TOOL_TIMEOUT = timedelta(hours=4)
TABLE_TIMEOUT = timedelta(minutes=30)
VERSION_TIMEOUT = 60
LOG_TAIL_LINES = 200
THROTTLING = re.compile(
    r"Throttl|Rate exceeded|TooManyRequests|RequestLimitExceeded|SlowDown", re.IGNORECASE
)
# How the tools report an action the scanning identity may not perform. IAM's own wording
# names the action; the Go SDK (Steampipe, CloudFox) names the service and operation of a 403;
# botocore (Prowler) names the operation only, and Prowler's log line its service module.
# Lengths are capped so a match always fits the manifest's denied_actions pattern.
_DENIED_IAM = re.compile(r"not authorized to perform: ([a-z0-9-]{1,40}:[A-Za-z0-9*]{1,80})\b")
_DENIED_GO = re.compile(
    r"operation error ([A-Za-z0-9 ]{1,40}?): ([A-Za-z0-9]{1,80}), https response error "
    r"StatusCode: 403"
)
_DENIED_BOTO = re.compile(
    r"\((?:AccessDenied\w*|UnauthorizedOperation|AuthorizationError\w*|Forbidden)\) "
    r"when calling the ([A-Za-z0-9]{1,80}) operation"
)
# Prowler's log line names its service module ("[File: glue_service.py:66]"), which gives a
# botocore denial its IAM prefix. Modules named differently from their IAM prefix are mapped;
# those that call more than one service (cloudwatch: logs too, s3: s3control) give none.
_PROWLER_MODULE = re.compile(r"\[File: ([a-z0-9]{1,40})_service\.py:")
_PROWLER_IAM_PREFIX = {
    "apigatewayv2": "apigateway",
    "awslambda": "lambda",
    "directoryservice": "ds",
    "documentdb": "rds",
    "efs": "elasticfilesystem",
    "elb": "elasticloadbalancing",
    "elbv2": "elasticloadbalancing",
    "eventbridge": "events",
    "macie": "macie2",
    "neptune": "rds",
    "opensearch": "es",
    "resourceexplorer2": "resource-explorer-2",
    "ssmincidents": "ssm-incidents",
    "stepfunctions": "states",
    "trustedadvisor": "support",
    "vpc": "ec2",
}
_PROWLER_NO_PREFIX = frozenset({"cloudwatch", "cognito", "s3", "waf"})
# The Go SDK's service names ("operation error Timestream Write: ...") whose IAM prefix is not
# the name lower-cased without spaces. Any other name is lower-cased as it is.
_GO_IAM_PREFIX = {
    "ACM PCA": "acm-pca",
    "API Gateway": "apigateway",
    "ApiGatewayV2": "apigateway",
    "Application Auto Scaling": "application-autoscaling",
    "CloudWatch Logs": "logs",
    "Cognito Identity Provider": "cognito-idp",
    "Config Service": "config",
    "Database Migration Service": "dms",
    "Directory Service": "ds",
    "DocDB": "rds",
    "EFS": "elasticfilesystem",
    "Elastic Load Balancing": "elasticloadbalancing",
    "Elastic Load Balancing v2": "elasticloadbalancing",
    "EventBridge": "events",
    "Kinesis Analytics V2": "kinesisanalytics",
    "MWAA": "airflow",
    "Neptune": "rds",
    "Network Firewall": "network-firewall",
    "OpenSearch": "es",
    "Resource Groups Tagging API": "tag",
    "SESv2": "ses",
    "SFN": "states",
    "SSO Admin": "sso",
    "Timestream Query": "timestream",
    "Timestream Write": "timestream",
}
# IAM's reason when a policy refused the call on purpose: the resource's own policy, or an
# explicit Deny (the scanner role's own denies of secrets, code, logs and API keys, ADR-0018; a
# service control policy). Nothing to add to the role, and nothing that should be.
_RESOURCE_REFUSED = re.compile(
    r"no resource-based policy allows|with an explicit deny in an? [a-z -]{1,40} policy"
)
# Errors that say the service or the call does not apply to this account (ADR-0012, second
# amendment). Only wordings seen on a real account: a wider pattern would hide a real gap.
# Each is anchored to the SDK's error code after the status, so a resource name in the line
# cannot match.
_SDK_ERROR = r"StatusCode: {status}, (?:RequestID: [^,]{{1,100}}, )?(?:api error )?"
NOT_APPLICABLE = re.compile(
    _SDK_ERROR.format(status=400)
    + r"AWSOrganizationsNotInUseException: "
    + "|"
    + _SDK_ERROR.format(status=403)
    + r"AccessDeniedException: Only existing Timestream for LiveAnalytics customers can access "
    r"the service"
)
# CloudFox writes module errors here whatever $TMPDIR says. The worker's /tmp is a tmpfs.
CLOUDFOX_ERROR_LOG = Path("/tmp/.cloudfox/cloudfox-error.log")  # noqa: S108 - CloudFox's path


@dataclass
class ToolResult:
    status: str  # complete | partial | failed
    exit_code: int
    tool_version: str
    log_lines: list[str]
    throttle_events: int
    denied_actions: list[str] = field(default_factory=list)
    command: str = ""  # what Argus ran, for the Runs page (command_line)
    incomplete_tables: list[str] = field(default_factory=list)  # Steampipe only
    refused_actions: list[str] = field(default_factory=list)  # by the resource's own policy
    not_applicable_tables: list[str] = field(default_factory=list)  # Steampipe only
    refused_tables: list[str] = field(default_factory=list)  # Steampipe only


def _denied_action(line: str) -> str | None:
    """The action a line says was denied. A line IAM explains names it; otherwise the SDK's
    service and operation, or the operation."""
    if iam := _DENIED_IAM.search(line):
        return iam.group(1)
    if go := _DENIED_GO.search(line):
        service = _GO_IAM_PREFIX.get(go.group(1), go.group(1).replace(" ", "").lower())
        return f"{service}:{go.group(2)}"
    if boto := _DENIED_BOTO.search(line):
        module = _PROWLER_MODULE.search(line)
        service = module.group(1) if module else None
        if service and service not in _PROWLER_NO_PREFIX:
            return f"{_PROWLER_IAM_PREFIX.get(service, service)}:{boto.group(1)}"
        return boto.group(1)
    return None


@dataclass
class Denials:
    denied: set[str] = field(default_factory=set)  # the role is missing them
    refused: set[str] = field(default_factory=set)  # the resource's own policy refused them


def read_denials(text: str) -> Denials:
    """What a tool's output says the scanning identity could not do, one entry per action.
    A line that says the service does not apply here is neither (NOT_APPLICABLE)."""
    found = Denials()
    for line in text.splitlines():
        if NOT_APPLICABLE.search(line) or not (action := _denied_action(line)):
            continue
        (found.refused if _RESOURCE_REFUSED.search(line) else found.denied).add(action)
    return found


def denied_actions(text: str) -> set[str]:
    """The actions the role is missing, from a tool's output."""
    return read_denials(text).denied


def _denied_list(found: set[str]) -> list[str]:
    return sorted(found)[:MAX_DENIED_ACTIONS]


def command_line(cmd: list[str], out_dir: Path) -> str:
    """What Argus ran, with the run's temporary paths shortened. It holds no credential: the
    tools read them from the private profile."""
    words = [Path(cmd[0]).name, *cmd[1:]]
    return " ".join(w.replace(str(out_dir), "<run>") for w in words)


def _with_denied(lines: list[str], denied: list[str]) -> list[str]:
    """The log tail, ending with what was denied so the operator can fix the permissions."""
    if not denied:
        return lines
    return [*lines, f"argus: {len(denied)} action(s) denied: {', '.join(denied)}"]


@contextmanager
def tool_profile(credentials: SessionCredentials, region: str) -> Iterator[dict[str, str]]:
    """A temporary home holding one AWS profile, and the minimal environment that points at it.
    Deleted with everything a tool wrote there when the run ends."""
    home = Path(tempfile.mkdtemp(prefix="argus-aws-"))  # mode 0700
    try:
        token = (
            f"aws_session_token = {credentials.session_token}\n"
            if credentials.session_token
            else ""
        )
        secrets = home / "credentials"
        secrets.touch(mode=0o600)
        secrets.write_text(
            f"[{PROFILE}]\naws_access_key_id = {credentials.access_key_id}\n"
            f"aws_secret_access_key = {credentials.secret_access_key}\n{token}"
        )
        (home / "config").write_text(f"[profile {PROFILE}]\nregion = {region}\n")
        yield {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "TMPDIR": str(home),
            "LANG": "C.UTF-8",
            "AWS_PROFILE": PROFILE,
            "AWS_SHARED_CREDENTIALS_FILE": str(secrets),
            "AWS_CONFIG_FILE": str(home / "config"),
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_RETRY_MODE": "adaptive",
            "AWS_MAX_ATTEMPTS": "10",
            "STEAMPIPE_INSTALL_DIR": str(home / "steampipe"),
        }
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _run(cmd: list[str], *, env: dict[str, str], log: Path, timeout: timedelta) -> int:
    """Runs a tool in its own process group, output to `log`. Kills the group on timeout."""
    with log.open("ab") as out:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            cmd,
            env=env,
            cwd=env["HOME"],
            stdout=out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=timeout.total_seconds())
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            out.write(f"\nargus: killed after {timeout}\n".encode())
            return -9


def _version(cmd: list[str], env: dict[str, str]) -> str:
    try:
        answer = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd,
            env=env,
            cwd=env["HOME"],
            capture_output=True,
            text=True,
            timeout=VERSION_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    words = answer.stdout.split()
    return words[-1].removeprefix("v") if words else "unknown"


def _read_log(log: Path) -> tuple[list[str], int]:
    """The log's last lines (progress-bar carriage returns split into lines) and how many lines
    report throttling."""
    if not log.exists():
        return [], 0
    lines = log.read_text(errors="replace").replace("\r", "\n").splitlines()
    lines = [line for line in lines if line.strip()]
    return lines[-LOG_TAIL_LINES:], sum(1 for line in lines if THROTTLING.search(line))


def _status(ok: bool, throttle_events: int) -> str:
    # A throttled run may have lost output silently, so it must resolve nothing (ADR-0022).
    if not ok:
        return "failed"
    return "partial" if throttle_events else "complete"


def table_failed(rc: int, errors: str, rows: Path) -> bool:
    """The export can exit 0 after logging errors, and some failures are printed to stdout.
    Any of the three marks the table failed: its rows are not kept. One denied hydrate call
    makes the pinned plugin stop the whole table with [ERROR] (collection/tables.py)."""
    bad_rows = any(not line.startswith("{") for line in rows.read_text().splitlines() if line)
    return rc != 0 or "[ERROR]" in errors or bad_rows


def table_outcome(errors: str) -> str | None:
    """For a table whose export failed: "not_applicable" when every error line says the
    service or call does not apply here, "refused" when every one is a resource's own policy
    (or not applicable), None otherwise (ADR-0012, second amendment)."""
    lines = [line for line in errors.splitlines() if "[ERROR]" in line]
    if not lines:
        return None
    if all(NOT_APPLICABLE.search(line) for line in lines):
        return "not_applicable"
    if all(
        NOT_APPLICABLE.search(line) or (_denied_action(line) and _RESOURCE_REFUSED.search(line))
        for line in lines
    ):
        return "refused"
    return None


@dataclass(frozen=True)
class _TableRun:
    table: str
    rc: int
    errors: str


@dataclass
class _Tables:
    """What a Steampipe run's tables came to (ADR-0012, second amendment)."""

    failed: list[str] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)  # carried forward, whatever the reason
    not_applicable: list[str] = field(default_factory=list)
    refused_tables: list[str] = field(default_factory=list)
    denials: Denials = field(default_factory=Denials)
    throttled: int = 0


def _judge_tables(runs: list[_TableRun], out_dir: Path, log: Path) -> _Tables:
    """Sorts each table's export into its outcome, drops the rows of failed ones and writes one
    line per table that is not complete to the log."""
    t = _Tables()
    for run in runs:
        out = out_dir / f"{run.table}.jsonl"
        found = read_denials(run.errors)
        throttling = sum(1 for line in run.errors.splitlines() if THROTTLING.search(line))
        t.denials.denied |= found.denied
        t.denials.refused |= found.refused
        t.throttled += throttling
        if table_failed(run.rc, run.errors, out):
            # A table only not applicable or refused here carries its rows forward without
            # making the run partial; any other failure does both.
            outcome = None if throttling or found.denied else table_outcome(run.errors)
            t.incomplete.append(run.table)
            if outcome == "not_applicable":
                t.not_applicable.append(run.table)
            elif outcome == "refused":
                t.refused_tables.append(run.table)
            else:
                t.failed.append(run.table)
            with log.open("a") as text:
                text.write(
                    f"table {(outcome or 'failed').replace('_', ' ')}: {run.table} "
                    f"(exit {run.rc})\n{run.errors[-2000:]}\n"
                )
            out.unlink()
        elif found.denied or throttling:
            # A denied or throttled call leaves a column or a region empty: the rows are kept,
            # and the table resolves nothing.
            t.incomplete.append(run.table)
            why = f"{len(found.denied)} denied action(s)" if found.denied else "throttled"
            with log.open("a") as text:
                text.write(f"table partial: {run.table} ({why})\n")
        elif found.refused:
            # A resource refused a column's call: the rows are kept and carried, not partial.
            t.incomplete.append(run.table)
            t.refused_tables.append(run.table)
    return t


def run_steampipe(
    out_dir: Path, env: dict[str, str], regions: list[str], parallel_tables: int = 4
) -> ToolResult:
    """Every column of each table in the versioned list (some narrowed, collection/tables.py),
    one JSONL file per table, `parallel_tables` exports at a time.

    Completeness is per table (decided 2026-10-08, argus_v8): a table that failed, or whose
    export logged a denied call or throttling, is listed in `incomplete_tables` and resolves
    nothing; the run is partial, and every other table is complete."""
    home = Path(env["HOME"])
    config_dir = home / "steampipe" / "config"
    config_dir.mkdir(parents=True)
    region_list = ", ".join(f'"{r}"' for r in regions) if regions else '"*"'
    (config_dir / "aws.spc").write_text(
        f'connection "aws" {{\n  plugin  = "aws"\n  profile = "{PROFILE}"\n'
        f"  regions = [{region_list}]\n}}\n"
    )
    tables = steampipe_tables()

    def export(table: str) -> _TableRun:
        out, err = out_dir / f"{table}.jsonl", home / f"{table}.err"
        with out.open("wb") as rows:
            rc = _run_table(table, config_dir, env, rows, err)
        return _TableRun(table, rc, err.read_text(errors="replace") if err.exists() else "")

    with ThreadPoolExecutor(max_workers=max(1, parallel_tables)) as pool:
        runs = list(pool.map(export, tables))

    log = home / "steampipe.log"
    judged = _judge_tables(runs, out_dir, log)
    failed, incomplete = judged.failed, judged.incomplete
    not_applicable, refused_tables = judged.not_applicable, judged.refused_tables
    denials, throttled = judged.denials, judged.throttled
    lines, _ = _read_log(log)
    partial = set(incomplete) - set(not_applicable) - set(refused_tables)
    if failed and len(failed) == len(tables):
        status = "failed"
    elif partial:
        status = "partial"
    else:
        status = "complete"
    version = _version([STEAMPIPE, "--version"], env)
    denied_list = _denied_list(denials.denied)
    ran = command_line(_table_command("<table>", Path("<config>")), out_dir)
    return ToolResult(
        status,
        1 if failed else 0,
        version,
        _with_denied(lines, denied_list),
        throttled,
        denied_list,
        f"{ran}  (for each of {len(tables)} tables, {parallel_tables} at a time; "
        f"regions = [{region_list}])",
        incomplete_tables=sorted(incomplete),
        refused_actions=_denied_list(denials.refused),
        not_applicable_tables=sorted(not_applicable),
        refused_tables=sorted(refused_tables),
    )


def _table_command(table: str, config_dir: Path) -> list[str]:
    return [
        STEAMPIPE,
        table,
        "--connection",
        "aws",
        "--config-dir",
        str(config_dir),
        "--output",
        "jsonl",
        *table_options(table),
    ]


def _run_table(
    table: str, config_dir: Path, env: dict[str, str], rows: IO[bytes], err: Path
) -> int:
    with err.open("wb") as errors:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            _table_command(table, config_dir),
            env=env,
            cwd=env["HOME"],
            stdout=rows,
            stderr=errors,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=TABLE_TIMEOUT.total_seconds())
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return -9


def run_prowler(out_dir: Path, env: dict[str, str], regions: list[str]) -> ToolResult:
    log = Path(env["HOME"]) / "prowler.log"
    cmd = [
        PROWLER,
        "aws",
        "--profile",
        PROFILE,
        "--output-formats",
        "json-ocsf",
        "csv",
        "--output-directory",
        str(out_dir),
        "--no-banner",
        "--log-level",
        "ERROR",
        # Exit code 3 means "some checks failed", the expected result of a scan.
        "--ignore-exit-code-3",
    ]
    if regions:
        cmd += ["--region", *regions]
    rc = _run(cmd, env=env, log=log, timeout=TOOL_TIMEOUT)
    lines, throttled = _read_log(log)
    # A check whose calls were denied has no result, so it resolves nothing: the run stays
    # complete, and the denied actions are reported.
    denials = read_denials(log.read_text(errors="replace")) if log.exists() else Denials()
    refused = _denied_list(denials.denied)
    # Read from the installed package: `prowler --version` checks GitHub for a newer release.
    version = _version(
        [PROWLER_PYTHON, "-c", "import importlib.metadata as m; print(m.version('prowler'))"], env
    )
    return ToolResult(
        _status(rc == 0, throttled),
        rc,
        version,
        _with_denied(lines, refused),
        throttled,
        refused,
        command_line(cmd, out_dir),
        refused_actions=_denied_list(denials.refused),
    )


def run_cloudfox(
    out_dir: Path, env: dict[str, str], account_id: str, max_goroutines: int
) -> ToolResult:
    """All checks, including env-vars (decided 2026-10-02). --verbosity 1 prints control
    messages only: higher levels print module output, which includes secret values."""
    log = Path(env["HOME"]) / "cloudfox.log"
    cmd = [
        CLOUDFOX,
        "aws",
        "all-checks",
        "--profile",
        PROFILE,
        "--outdir",
        str(out_dir),
        "--verbosity",
        "1",
        "--yes",
        "--max-goroutines",
        str(max_goroutines),
    ]
    errors_from = _size(CLOUDFOX_ERROR_LOG)
    try:
        rc = _run(cmd, env=env, log=log, timeout=TOOL_TIMEOUT)
    finally:
        # CloudFox 2.0.5 also caches what it read (env-var values included) next to its
        # output: it is not output, so it is never archived.
        shutil.rmtree(out_dir / "cached-data", ignore_errors=True)
        _forget_cloudfox_cache(account_id)
    _flatten_cloudfox(out_dir)
    lines, throttled = _read_log(log)
    text = "\n".join(lines)
    # CloudFox 2.0.5 exits 0 even when it cannot authenticate, and its checks fail silently.
    # A non-zero exit, a top-level error, or an empty output directory fails the run.
    ok = (
        rc == 0
        and "Could not get caller's identity" not in text
        and not re.search(r"^Error:", text, re.MULTILINE)
        and any(out_dir.iterdir())
    )
    # Module errors go to CloudFox's own error log, not the console ("0 errors" there). A
    # denied module leaves its findings unseen, so the run is partial and resolves nothing.
    denials = read_denials(_cloudfox_errors(errors_from, account_id))
    refused = _denied_list(denials.denied)
    status = _status(ok, throttled)
    # CloudFox has no per-table scope: any refused call, the role's or a policy's, leaves
    # findings unseen that a complete run would resolve.
    if status == "complete" and (refused or denials.refused):
        status = "partial"
    version = _version([CLOUDFOX, "--version"], env)
    return ToolResult(
        status,
        rc,
        version,
        _with_denied(lines, refused),
        throttled,
        refused,
        command_line(cmd, out_dir),
        refused_actions=_denied_list(denials.refused),
    )


def _flatten_cloudfox(out_dir: Path) -> None:
    """CloudFox nests its output as cloudfox-output/aws/<profile>-<account>/{json,csv,...}.
    The run directory already names the tool, the account and the run, so the inner folders
    move up and the wrappers go: <run>/json/<module>.json. Files are not changed. Any other
    shape is left as CloudFox wrote it."""
    wrapper = out_dir / "cloudfox-output"
    inner = list((wrapper / "aws").iterdir()) if (wrapper / "aws").is_dir() else []
    if len(inner) != 1 or not inner[0].is_dir() or len(list(wrapper.iterdir())) != 1:
        if wrapper.exists():
            logger.warning("cloudfox output left nested: unexpected layout")
        return
    children = list(inner[0].iterdir())
    if any((out_dir / child.name).exists() for child in children):
        logger.warning("cloudfox output left nested: a folder would be overwritten")
        return
    for child in children:
        child.rename(out_dir / child.name)
    shutil.rmtree(wrapper)


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _cloudfox_errors(start: int, account_id: str) -> str:
    """The error-log lines this run added. Two accounts' CloudFox runs can share the log, so
    only lines naming this account are kept (a denial names the principal's ARN). The log
    is left in place: deleting it would break a concurrent run."""
    try:
        with CLOUDFOX_ERROR_LOG.open("rb") as errors:
            errors.seek(start)
            added = errors.read().decode(errors="replace")
    except OSError:
        return ""
    return "\n".join(line for line in added.splitlines() if f":{account_id}:" in line)


def _forget_cloudfox_cache(account_id: str) -> None:
    """CloudFox caches what it read (env-var values included) under the passwd home, ignoring
    $HOME. The worker's home is a tmpfs; this account's cache goes as soon as the run ends."""
    try:
        cache = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".cloudfox"
    except KeyError:  # no passwd entry: CloudFox could not have run, so it cached nothing
        return
    if not cache.is_dir():
        return
    for path in sorted(cache.rglob(f"*{account_id}*"), key=lambda p: len(p.parts)):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink(missing_ok=True)
