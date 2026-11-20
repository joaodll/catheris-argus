"""Runs Steampipe export, Prowler and CloudFox, unmodified (ADR-0001), against one account; and
the same Steampipe export over AWS Inspector's findings (ADR-0042).

Read-only by construction: each command line below is the complete set of flags. Never add a
Prowler --fixer, --security-hub, --scan-secrets-validate, --shodan or --slack, or a CloudFox
module that acts on a target: they write to the account, push findings out, or use discovered
secrets against live services (CLAUDE.md, read-only rule).

Each tool sees one private AWS profile, written for the run into a temporary home and deleted
after it, and an environment built from nothing, so Argus's own variables (database password,
credential keyring) are not passed to it. A tool runs as the worker's user, so the worker also
hides its own environment at start (core.process). What that user can read stays readable: the
worker's disk and, on Compose, another run's profile (docs/security-model.md, Known limits).
"""

import fcntl
import logging
import os
import pty
import pwd
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import IO

from argus.collection.aws.stream import (
    RETRIED,
    THROTTLED,
    LineFate,
    Routing,
    ToolStream,
    pump,
)
from argus.collection.collect import Cancelled, CollectOptions, TimeLimit, span
from argus.collection.prowler_lists import prowler_checks, prowler_frameworks, prowler_services
from argus.collection.tables import (
    INSPECTOR_TABLES,
    inspector_table_options,
    steampipe_tables,
    table_options,
)
from argus.core.aws import SessionCredentials, is_one_word
from argus.core.manifest import BLOCKING_POLICIES, MAX_DENIED_ACTIONS, MAX_TABLE_ERROR_CHARS
from argus.core.memory import MemoryGuard, OutOfMemory
from argus.core.redaction import redact_text

logger = logging.getLogger("argus.collection")
PROFILE = "argus"
# Absolute paths, as the worker image installs them (backend/Dockerfile, target worker).
# Prowler's own entry point, started by a launcher that only lets botocore's retry lines out
# (backend/tools/prowler/launch.py): the live log counts AWS's retries. Prowler is unchanged.
PROWLER = "/opt/prowler/bin/prowler-argus"
PROWLER_PYTHON = "/opt/prowler/bin/python"
STEAMPIPE = "/usr/local/bin/steampipe_export_aws"
CLOUDFOX = "/usr/local/bin/cloudfox"
# What each tool runs. On Kubernetes each tool has its own image (ADR-0046), which carries
# only its own binary: a scan Job checks for it before it claims a run.
TOOL_BINARIES: dict[str, str] = {
    "steampipe": STEAMPIPE,
    "vulnerabilities": STEAMPIPE,
    "prowler": PROWLER,
    "cloudfox": CLOUDFOX,
}
TABLE_TIMEOUT = timedelta(minutes=30)
# Tables that take longer than TABLE_TIMEOUT on a large account. Inspector's findings: every
# open finding of the account, its packages and resources in every row, every region; on a
# large account that is hours, not minutes (2026-11-19). Each stays inside the scan Job's
# deadline (chart scanJobs.activeDeadlineSeconds, 6 h).
TABLE_TIMEOUTS = {"aws_inspector2_finding": timedelta(hours=3)}
# Written into a table's error file when Argus stops it at its limit, so the reason on the Runs
# page says so (table_error) and the table is never taken for "not applicable".
TIMED_OUT_NOTE = "argus: stopped after its time limit of"
# Bytes read at a time when a tool's output file is looked at whole: a large account's tables
# reach gigabytes, which must never sit in the scan Job's memory at once.
READ_BLOCK = 1 << 20
VERSION_TIMEOUT = 60
LOG_TAIL_LINES = 200
# How often a waiting tool is checked for a request to stop.
CANCEL_POLL_SECONDS = 1.0
# How long a tool's output is still read after the tool ended.
READER_JOIN_SECONDS = 10.0
# Attempts per AWS call, retries included, for every tool. The SDKs read it from the profile's
# environment; Prowler builds its own botocore Config (standard mode, 3 attempts in 5.50.0),
# which wins over the environment, so it gets the same number as a flag.
AWS_MAX_ATTEMPTS = 10
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
# IAM's reason for a denial: "because no <policy type> allows the <action> action" when nothing
# allowed it, "with an explicit deny in a(n) <policy type>" when a Deny refused it. The types are
# IAM's own words, matched exactly (case included: "VPC endpoint policy"). Each type goes to one
# answer (owner, 2026-11-05):
#   - identity-based, nothing allowed it: the role is missing it ("denied"; also a line that
#     gives no reason);
#   - identity-based Deny (the scanner role's own denies of secrets, code, logs and API keys,
#     ADR-0018), or the resource's own policy: refused on purpose, nothing to add ("refused");
#   - a policy outside the role (BLOCKING_POLICIES): the data is missing and the fix is in that
#     policy, not the role ("blocked"). Like "denied", it makes the run partial.
_POLICY_TYPES = "|".join(
    re.escape(t) for t in ("identity-based policy", "resource-based policy", *BLOCKING_POLICIES)
)
_IAM_REASON = re.compile(
    rf"because no (?P<allowed>{_POLICY_TYPES}) allows"
    rf"|with an explicit deny in an? (?P<denied>{_POLICY_TYPES})"
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
# On a failed run, this many of the error log's last lines, each cut to this length.
CLOUDFOX_ERROR_LINES = 8
CLOUDFOX_ERROR_LINE_CHARS = 300


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
    blocked_actions: list[str] = field(default_factory=list)  # "<action> (<policy type>)"
    table_errors: list[str] = field(default_factory=list)  # "<table>: <first error line>"


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
    refused: set[str] = field(default_factory=set)  # refused on purpose: nothing to add
    blocked: set[str] = field(default_factory=set)  # "<action> (<policy type>)", outside the role


def _blocking_policy(line: str) -> str | None:
    """The policy outside the role that refused the call, when IAM's reason names one."""
    reason = _IAM_REASON.search(line)
    policy = reason and (reason.group("allowed") or reason.group("denied"))
    return policy if policy in BLOCKING_POLICIES else None


def _refused_on_purpose(line: str) -> bool:
    """The resource's own policy, or an explicit Deny in the role's own policies."""
    reason = _IAM_REASON.search(line)
    if not reason:
        return False
    return "resource-based policy" in (reason.group("allowed"), reason.group("denied")) or (
        reason.group("denied") == "identity-based policy"
    )


def read_denials(text: str) -> Denials:
    """What a tool's output says the scanning identity could not do, one entry per action.
    A line that says the service does not apply here is none of them (NOT_APPLICABLE)."""
    found = Denials()
    for line in text.splitlines():
        if NOT_APPLICABLE.search(line) or not (action := _denied_action(line)):
            continue
        if policy := _blocking_policy(line):
            found.blocked.add(f"{action} ({policy})")
        elif _refused_on_purpose(line):
            found.refused.add(action)
        else:
            found.denied.add(action)
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


def _with_denied(lines: list[str], denied: list[str], blocked: Sequence[str] = ()) -> list[str]:
    """The log tail, ending with what was denied or blocked so the operator can fix it."""
    if denied:
        lines = [*lines, f"argus: {len(denied)} action(s) denied: {', '.join(denied)}"]
    if blocked:
        lines = [
            *lines,
            f"argus: {len(blocked)} action(s) blocked outside the role: {', '.join(blocked)}",
        ]
    return lines


@contextmanager
def tool_profile(credentials: SessionCredentials, region: str) -> Iterator[dict[str, str]]:
    """A temporary home holding one AWS profile, and the minimal environment that points at it.
    Deleted with everything a tool wrote there when the run ends. A value that isn't one word is
    refused, whatever validated it when it was stored: the run fails and no tool starts."""
    values = {
        "access key id": credentials.access_key_id,
        "secret access key": credentials.secret_access_key,
        "session token": credentials.session_token or "-",
        "region": region,
    }
    for name, value in values.items():
        if not is_one_word(value):
            raise ValueError(f"the connection's {name} holds a space or a control character")
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
            "AWS_MAX_ATTEMPTS": str(AWS_MAX_ATTEMPTS),
            "STEAMPIPE_INSTALL_DIR": str(home / "steampipe"),
        }
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _wait(
    process: subprocess.Popen[bytes],
    timeout: timedelta,
    cancel: threading.Event | None,
    guard: MemoryGuard | None = None,
) -> int | None:
    """Waits for a tool that runs in its own process group. Returns its exit code, or None
    after killing the group at the timeout. Kills the group and raises Cancelled as soon as the
    run is asked to stop, or OutOfMemory as soon as the run's memory nears its limit."""
    deadline = time.monotonic() + timeout.total_seconds()
    while True:
        if cancel is not None and cancel.is_set():
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise Cancelled
        if guard is not None and (over := guard.check()) is not None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise OutOfMemory(over)
        left = deadline - time.monotonic()
        try:
            return process.wait(timeout=max(0.0, min(CANCEL_POLL_SECONDS, left)))
        except subprocess.TimeoutExpired:
            if left <= 0:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                return None


def _run(
    cmd: list[str],
    *,
    env: dict[str, str],
    log: Path,
    limit: TimeLimit,
    cancel: threading.Event | None = None,
    stream: ToolStream | None = None,
    guard: MemoryGuard | None = None,
    tty: bool = False,
    routing: Routing | None = None,
) -> int:
    """Runs a tool in its own process group, output to `log` and, line by line, to the live
    log (`stream`), each line where `routing` says (stream.pump). Kills the group at its time
    limit (and marks it reached), or when the run is asked to stop (Cancelled). With `tty`,
    the tool writes to a pseudo-terminal: a progress bar that draws only on a terminal
    (Prowler's) then reaches the live log."""
    with log.open("ab") as out:
        if tty:
            try:
                terminal, tool_end = pty.openpty()
                _plain_terminal(tool_end)
            except OSError as exc:  # no pseudo-terminal here: a bar unseen, never a lost run
                tty = False
                if stream is not None:
                    stream.note(f"no pseudo-terminal ({exc.strerror}): progress bar not shown")
        output: int | IO[bytes] = tool_end if tty else subprocess.PIPE
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                cmd,
                env=env,
                cwd=env["HOME"],
                stdout=output,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        finally:
            if tty:
                os.close(tool_end)  # the tool holds its own copy
        if tty:
            source: IO[bytes] = os.fdopen(terminal, "rb", buffering=0)
        else:
            assert process.stdout is not None  # noqa: S101 - stdout=PIPE above
            source = process.stdout
        reader = threading.Thread(
            target=pump,
            args=(source, out, stream, routing),
            name="tool-output",
            daemon=True,
        )
        reader.start()
        try:
            rc = _wait(process, limit.span, cancel, guard)
        finally:
            # The pipe closes when the tool's group exits; a process of it that outlived the
            # wait (killed or not) is not waited for longer.
            reader.join(timeout=READER_JOIN_SECONDS)
            source.close()
        if rc is None:
            out.write(f"\n{TIMED_OUT_NOTE} {span(limit.span)}\n".encode())
            limit.reached = True
            return -9
        return rc


# The pseudo-terminal a tool draws on: wide enough for Prowler's bar and its service name, and
# no "\n" -> "\r\n" translation or echo, so its lines read as a pipe's.
TERMINAL_ROWS, TERMINAL_COLUMNS = 50, 160


def _plain_terminal(fd: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", TERMINAL_ROWS, TERMINAL_COLUMNS, 0, 0))
    attrs = termios.tcgetattr(fd)
    attrs[1] &= ~termios.ONLCR  # output flags
    attrs[3] &= ~termios.ECHO  # local flags
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


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


# The plugin's own record of an AWS answer to one of its calls, written before the table's
# IgnoreConfig decides whether the answer stops the table: "[ERROR] <ts>: <table>.<function>:
# api_error=...". The plugin writes it for answers it then ignores too, such as CloudFront's
# NoSuchMonitoringSubscription or Shield's ResourceNotFoundException (1.34.1, seen
# 2026-11-05). Only api_error: client_error, connection_error and the like are setup failures.
_PLUGIN_API_ERROR = re.compile(r"^\[ERROR\]\s+\d+: aws_[a-z0-9_]+\.[A-Za-z0-9_]+: api_error=")


def table_timeout(table: str) -> timedelta:
    """How long one table's export may run (TABLE_TIMEOUTS, else TABLE_TIMEOUT)."""
    return TABLE_TIMEOUTS.get(table, TABLE_TIMEOUT)


def table_timed_out(errors: str) -> bool:
    """Whether Argus stopped the table at its time limit (TIMED_OUT_NOTE)."""
    return any(line.startswith(TIMED_OUT_NOTE) for line in errors.splitlines())


def only_json_rows(rows: Path) -> bool:
    """Whether every non-empty line of a table's output starts with "{". Read in blocks, looking
    only at the first byte of each line: the file can be gigabytes (a large account's Inspector
    findings), and holding it whole killed a scan Job (2026-11-19)."""
    at_line_start = True
    with rows.open("rb") as data:
        while block := data.read(READ_BLOCK):
            parts = block.split(b"\n")
            for n, part in enumerate(parts):
                starts_line = at_line_start if n == 0 else True
                if starts_line and part not in (b"", b"\r") and not part.startswith(b"{"):
                    return False
            # The block's last part continues on the next block unless the block ended a line.
            at_line_start = parts[-1] == b""
    return True


def table_failed(rc: int, errors: str, rows: Path) -> bool:
    """Whether the export says the table failed: its rows are not kept. Three signs, any one:
    a non-zero exit; stdout holding anything but JSON rows (some failures are printed there);
    an [ERROR] line other than the plugin's record of an API answer (_PLUGIN_API_ERROR). An
    answer the plugin ignores leaves only that record, exit 0 and every row; one that stops the
    table also exits 1, prints to stdout and, from a hydrate call, logs "callHydrate ...
    finished with error" (owner, 2026-11-05; tests pin each shape for the pinned version)."""
    return rc != 0 or _stopped(errors) or not only_json_rows(rows)


def _stopped(errors: str) -> bool:
    """An [ERROR] line other than the plugin's record of an API answer (table_failed)."""
    return any(
        "[ERROR]" in line and not _PLUGIN_API_ERROR.match(line) for line in errors.splitlines()
    )


def table_outcome(errors: str) -> str | None:
    """For a table whose export failed: "not_applicable" when every error line says the
    service or call does not apply here, "refused" when every one was refused on purpose (or
    not applicable), None otherwise (ADR-0012, second amendment). A call blocked outside the
    role is never "refused": its data is missing and can be fixed (owner, 2026-11-05)."""
    lines = [line for line in errors.splitlines() if "[ERROR]" in line]
    if not lines:
        return None
    if all(NOT_APPLICABLE.search(line) for line in lines):
        return "not_applicable"
    if all(
        NOT_APPLICABLE.search(line) or (_denied_action(line) and _refused_on_purpose(line))
        for line in lines
    ):
        return "refused"
    return None


# What a table's reason keeps of an error line: the SDK's operation, status and AWS's own
# error code and message, which is what tells "not used here" from a real gap (ADR-0012). The
# log prefix, request ids, the principal's and the resource's ARNs and IAM's encoded message
# are dropped: they are long, and the reason fits MAX_TABLE_ERROR_CHARS.
_LOG_PREFIX = re.compile(r"^\[(?:ERROR|WARN|INFO)\]\s+\d+:\s*")
_SDK_ANSWER = re.compile(
    r"operation error (?P<op>[A-Za-z0-9 ]{1,40}: [A-Za-z0-9]{1,80}), .*?"
    r"StatusCode: (?P<status>\d{3}), .*?api error (?P<answer>.+)$"
)
_DROPPED = (
    (re.compile(r"(?:RequestID|HostID): [^,]{0,200}, "), ""),
    (re.compile(r"User: arn:\S+ is not authorized"), "User is not authorized"),
    (re.compile(r" on resource: arn:\S+"), ""),
    (re.compile(r"\.?\s*Encoded authorization failure message:.*$"), ""),
)


def _error_rank(line: str) -> int:
    """Which line of a table's errors says most: AWS's answer on the line that stopped the
    table, then AWS's answer anywhere, then the line that stopped it, then anything."""
    answer = "api error" in line or _denied_action(line) is not None
    return 0 if answer and "[ERROR]" in line else 1 if answer else 2 if "[ERROR]" in line else 3


def table_error(table: str, rc: int, errors: str) -> str:
    """Why a table was left out, for the Runs page: "<table>: <its most telling error line>",
    redacted, on one line and at most MAX_TABLE_ERROR_CHARS (manifest.TABLE_ERROR_PATTERN)."""
    lines = [line.strip() for line in errors.splitlines() if line.strip()]
    if table_timed_out(errors):
        # Argus stopped it: the lines before are what the table met on the way, not why.
        line = next(x for x in lines if x.startswith(TIMED_OUT_NOTE)).removeprefix("argus: ")
    elif rc == -signal.SIGKILL:
        # Killed, and not by Argus (its limit writes TIMED_OUT_NOTE; its memory guard and a
        # cancel end the whole run instead): the kernel's OOM killer, in a scan Job.
        line = "killed by the system (most likely out of memory)"
    else:
        line = min(lines, key=_error_rank) if lines else ""
        line = _LOG_PREFIX.sub("", line)
        if sdk := _SDK_ANSWER.search(line):
            line = f"{sdk['op']} (HTTP {sdk['status']}): {sdk['answer']}"
        for pattern, replacement in _DROPPED:
            line = pattern.sub(replacement, line)
        line = " ".join(redact_text(line).split()).rstrip('"')
    if not line:
        line = (
            f"killed by signal {-rc}, nothing on standard error"
            if rc < 0
            else f"exit code {rc}, nothing on standard error"
        )
    if len(line) > MAX_TABLE_ERROR_CHARS:
        line = line[: MAX_TABLE_ERROR_CHARS - 1] + "\u2026"
    return f"{table}: {line}"


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
    errors: list[str] = field(default_factory=list)  # table_error() of each incomplete table
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
        t.denials.blocked |= found.blocked
        t.throttled += throttling
        missing = found.denied or found.blocked  # data the operator can get back
        if table_failed(run.rc, run.errors, out):
            # A table only not applicable or refused here carries its rows forward without
            # making the run partial; any other failure does both.
            # Stopped at its limit: whatever its errors say, its rows are missing, not "not
            # applicable".
            stopped = throttling or missing or table_timed_out(run.errors)
            outcome = None if stopped else table_outcome(run.errors)
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
        elif missing or throttling:
            # A denied, blocked or throttled call leaves a column or a region empty: the rows
            # are kept, and the table resolves nothing.
            t.incomplete.append(run.table)
            if found.denied:
                why = f"{len(found.denied)} denied action(s)"
            elif found.blocked:
                why = f"{len(found.blocked)} action(s) blocked outside the role"
            else:
                why = "throttled"
            with log.open("a") as text:
                text.write(f"table partial: {run.table} ({why})\n")
        elif found.refused:
            # A resource refused a column's call: the rows are kept and carried, not partial.
            t.incomplete.append(run.table)
            t.refused_tables.append(run.table)
        if t.incomplete and t.incomplete[-1] == run.table:
            t.errors.append(table_error(run.table, run.rc, run.errors))
    return t


def run_steampipe(
    out_dir: Path,
    env: dict[str, str],
    regions: list[str],
    parallel_tables: int = 4,
    cancel: threading.Event | None = None,
    *,
    stream: ToolStream | None = None,
    guard: MemoryGuard | None = None,
) -> ToolResult:
    """Every column of each table in the versioned list (some narrowed, collection/tables.py),
    one JSONL file per table, `parallel_tables` exports at a time.

    Completeness is per table (decided 2026-10-08, argus_v8): a table that failed, or whose
    export logged a denied call or throttling, is listed in `incomplete_tables` and resolves
    nothing; the run is partial, and every other table is complete."""
    return _export_tables(
        out_dir,
        env,
        regions,
        steampipe_tables(),
        table_options,
        parallel_tables,
        cancel=cancel,
        stream=stream,
        guard=guard,
    )


def run_inspector(
    out_dir: Path,
    env: dict[str, str],
    regions: list[str],
    account_id: str,
    cancel: threading.Event | None = None,
    *,
    stream: ToolStream | None = None,
    guard: MemoryGuard | None = None,
) -> ToolResult:
    """The vulnerabilities tool on AWS: Inspector's open findings and its coverage for this
    account (ADR-0042), by the same export binary, one JSONL file per table. Judged as
    Steampipe tables are: the adapter resolves nothing unless the findings table is complete."""
    return _export_tables(
        out_dir,
        env,
        regions,
        INSPECTOR_TABLES,
        lambda table: inspector_table_options(table, account_id),
        len(INSPECTOR_TABLES),
        cancel=cancel,
        stream=stream,
        guard=guard,
    )


def _export_tables(
    out_dir: Path,
    env: dict[str, str],
    regions: list[str],
    tables: Sequence[str],
    options: Callable[[str], tuple[str, ...]],
    parallel_tables: int,
    *,
    cancel: threading.Event | None = None,
    stream: ToolStream | None = None,
    guard: MemoryGuard | None = None,
) -> ToolResult:
    home = Path(env["HOME"])
    config_dir = home / "steampipe" / "config"
    config_dir.mkdir(parents=True)
    region_list = ", ".join(f'"{r}"' for r in regions) if regions else '"*"'
    (config_dir / "aws.spc").write_text(
        f'connection "aws" {{\n  plugin  = "aws"\n  profile = "{PROFILE}"\n'
        f"  regions = [{region_list}]\n}}\n"
    )

    exports = _TableExports(
        out_dir, env, config_dir, tables, options, cancel=cancel, stream=stream, guard=guard
    )
    with ThreadPoolExecutor(max_workers=max(1, parallel_tables)) as pool:
        runs = list(pool.map(exports.export, tables))

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
    denied_list, blocked_list = _denied_list(denials.denied), _denied_list(denials.blocked)
    if options is table_options:  # the inventory: hundreds of tables, one line for all
        ran = command_line(_table_command("<table>", Path("<config>"), ()), out_dir)
        described = (
            f"{ran}  (for each of {len(tables)} tables, {parallel_tables} at a time; "
            f"regions = [{region_list}])"
        )
    else:  # a few tables, each with its own filter: every command as run
        ran = "; ".join(
            command_line(_table_command(t, Path("<config>"), options(t)), out_dir) for t in tables
        )
        described = f"{ran}  (regions = [{region_list}])"
    return ToolResult(
        status,
        1 if failed else 0,
        version,
        _with_denied(lines, denied_list, blocked_list),
        throttled,
        denied_list,
        described,
        incomplete_tables=sorted(incomplete),
        refused_actions=_denied_list(denials.refused),
        not_applicable_tables=sorted(not_applicable),
        refused_tables=sorted(refused_tables),
        blocked_actions=blocked_list,
        table_errors=sorted(judged.errors),
    )


class _TableExports:
    """One run's table exports, each in its own process: what is running (for the heartbeat)
    and how many have ended (for each table's line in the live log)."""

    def __init__(
        self,
        out_dir: Path,
        env: dict[str, str],
        config_dir: Path,
        tables: Sequence[str],
        options: Callable[[str], tuple[str, ...]],
        *,
        cancel: threading.Event | None,
        stream: ToolStream | None,
        guard: MemoryGuard | None,
    ) -> None:
        self.out_dir, self.home, self.config_dir = out_dir, Path(env["HOME"]), config_dir
        self.total, self.options = len(tables), options
        self.cancel, self.stream, self.guard = cancel, stream, guard
        # INFO makes the plugin log every retry ("[INFO] ... BackoffDelay: ..."), counted for
        # the live log; the table's error file still gets only what it got at the default
        # level (WARN and above), so the judgement reads what it always read (_table_fate).
        self.env = {**env, "STEAMPIPE_LOG_LEVEL": "INFO"}
        self.lock = threading.Lock()
        self.done = 0
        self.running: dict[str, tuple[float, Path]] = {}  # table -> (started, its rows file)
        if stream is not None:
            stream.add_status(lambda: _tables_running(self.running, self.lock))

    def export(self, table: str) -> _TableRun:
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled  # a table still waiting its turn never starts
        if self.guard is not None:
            self.guard.stop_if_over()  # nor after the run's memory neared its limit
        out, err = self.out_dir / f"{table}.jsonl", self.home / f"{table}.err"
        command = _table_command(table, self.config_dir, self.options(table))
        if self.stream is not None:
            self.stream.note(f"table {table} started")
        started = time.monotonic()
        with self.lock:
            self.running[table] = (started, out)
        try:
            with out.open("wb") as rows:
                rc = _run_table(
                    command,
                    self.env,
                    rows,
                    err,
                    self.cancel,
                    self.guard,
                    timeout=table_timeout(table),
                    stream=self.stream,
                    table=table,
                )
        finally:
            with self.lock:
                self.running.pop(table, None)
        run = _TableRun(table, rc, err.read_text(errors="replace") if err.exists() else "")
        if self.stream is not None:
            with self.lock:
                self.done += 1
                at = f"({self.done} of {self.total})"
            _say_table(self.stream, run, out, at, time.monotonic() - started)
        return run


# The plugin's log lines (steampipe-plugin-sdk, hclog): "[LEVEL] <ts>: ...". At INFO each
# retry it makes is "[INFO] <ts>: BackoffDelay: attempt=N, retryTime=..., err=..."
# (steampipe-plugin-aws 1.36.0, aws/service.go; seen 2026-11-19).
_PLUGIN_LEVEL = re.compile(r"^\[(TRACE|DEBUG|INFO)\]")
_PLUGIN_RETRY = re.compile(r"^\[INFO\]\s+\d+: BackoffDelay: ")
# hclog writes a multi-line value on lines of its own, each starting "  | ".
_PLUGIN_CONTINUATION = re.compile(r"^\s+\|")


def _table_fate(stream: ToolStream | None, table: str) -> LineFate:
    """Where each line a table's export logs goes: a retry is counted (it may yet succeed);
    any other line below WARN is dropped, so the table's error file, which the judgement
    reads, holds what the default level gave (2026-11-19: at WARN no retry line is logged, and
    a throttling line means the call gave up); WARN, ERROR and the rest go to both, a throttling
    one also counted."""

    entry = ["log"]  # the fate of the entry a continuation line belongs to

    def fate(text: str) -> str:
        if _PLUGIN_CONTINUATION.match(text):
            return entry[0]
        if _PLUGIN_RETRY.match(text):
            if stream is not None:
                stream.count(RETRIED, table)
            entry[0] = "drop"
        elif _PLUGIN_LEVEL.match(text):
            entry[0] = "drop"
        else:
            if THROTTLING.search(text) and stream is not None:
                stream.count(THROTTLED, table)
            entry[0] = "log"
        return entry[0]

    return fate


def _tables_running(running: dict[str, tuple[float, Path]], lock: threading.Lock) -> str | None:
    """The heartbeat's word on the tables running now: how long each has run and how much it
    has written, longest first, at most five named."""
    now = time.monotonic()
    with lock:
        tables = sorted(running.items(), key=lambda item: item[1][0])
    if not tables:
        return None
    named = [
        f"{t} {span(timedelta(seconds=now - began))} {_size_words(out)}"
        for t, (began, out) in tables[:5]
    ]
    more = f" and {len(tables) - 5} more" if len(tables) > 5 else ""
    return f"tables running: {', '.join(named)}{more}"


def _size_words(path: Path) -> str:
    size = _size(path)
    if size >= 1 << 30:
        return f"{size / (1 << 30):.1f} GB"
    return f"{size / (1 << 20):.0f} MB" if size >= 1 << 20 else f"{size // 1024} KB"


def _say_table(stream: ToolStream, run: _TableRun, rows: Path, at: str, seconds: float) -> None:
    """A table's end in the live log, with how long it took. A light look (the judgement, which
    reads every row, is _judge_tables's): the exit code and the error lines."""
    took = span(timedelta(seconds=seconds))
    if run.rc != 0 or _stopped(run.errors):
        why = table_error(run.table, run.rc, run.errors)
        stream.note(f"table {run.table} failed after {took} {at}: {why}")
    else:
        stream.note(f"table {run.table} finished in {took}, {_count_rows(rows)} rows {at}")


def _count_rows(rows: Path) -> int:
    """A JSONL file's rows (its lines), read in blocks."""
    count = 0
    try:
        with rows.open("rb") as data:
            while block := data.read(1 << 20):
                count += block.count(b"\n")
    except OSError:
        return 0
    return count


def _table_command(table: str, config_dir: Path, options: tuple[str, ...]) -> list[str]:
    return [
        STEAMPIPE,
        table,
        "--connection",
        "aws",
        "--config-dir",
        str(config_dir),
        "--output",
        "jsonl",
        *options,
    ]


def _run_table(
    command: list[str],
    env: dict[str, str],
    rows: IO[bytes],
    err: Path,
    cancel: threading.Event | None = None,
    guard: MemoryGuard | None = None,
    *,
    timeout: timedelta = TABLE_TIMEOUT,
    stream: ToolStream | None = None,
    table: str = "",
) -> int:
    """One table's export: rows to `rows`, its log lines to `err` and, as they come, to the
    live log under the table's name (_table_fate)."""
    with err.open("wb") as errors:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            command,
            env=env,
            cwd=env["HOME"],
            stdout=rows,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        assert process.stderr is not None  # noqa: S101 - stderr=PIPE above
        reader = threading.Thread(
            target=pump,
            args=(process.stderr, errors, stream, Routing(_table_fate(stream, table))),
            kwargs={"label": table},
            name="table-errors",
            daemon=True,
        )
        reader.start()
        try:
            rc = _wait(process, timeout, cancel, guard)
        finally:
            reader.join(timeout=READER_JOIN_SECONDS)
            process.stderr.close()
        if rc is None:
            errors.write(f"\n{TIMED_OUT_NOTE} {span(timeout)}\n".encode())
            return -signal.SIGKILL
        return rc


def _prowler_skips(
    skip_services: Sequence[str], skip_checks: Sequence[str]
) -> tuple[list[str], list[str], list[str]]:
    """The skips Prowler gets: names of the installed Prowler only, each once, in order. A name
    it doesn't know (stored before an upgrade removed it) is dropped, never passed, and said in
    the run's log: dropping one means more is checked, never less."""
    known_services, known_checks = set(prowler_services()), set(prowler_checks())
    services = sorted({s for s in skip_services if s in known_services})
    checks = sorted({c for c in skip_checks if c in known_checks})
    dropped = sorted(
        {s for s in skip_services if s not in known_services}
        | {c for c in skip_checks if c not in known_checks}
    )
    notes = (
        [f"argus: not skipped, unknown to this Prowler: {', '.join(dropped)}"] if dropped else []
    )
    return services, checks, notes


def run_prowler(
    out_dir: Path,
    env: dict[str, str],
    regions: list[str],
    options: CollectOptions,
    *,
    stream: ToolStream | None = None,
) -> ToolResult:
    """Every check in the regions set, unless Collection settings skip services or checks.
    Stopped when the run is asked to, near the memory limit, or at its time limit (options).

    A skip changes how Prowler 5.50.0 chooses what to write: with --excluded-* it writes no
    compliance results unless --compliance names the frameworks, and --compliance runs only
    the checks mapped to a framework. So a run that skips anything passes every framework, and
    the 50 checks in no framework don't run while a skip is set (owner, 2026-11-10). Checks
    that don't run resolve nothing: their findings keep their last results."""
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
        # INFO says which service and call Prowler is on (owner, 2026-11-19); a throttled call
        # is still logged, at ERROR, only once its retries ran out. Never DEBUG: botocore then
        # prints requests and answers whole.
        "--log-level",
        "INFO",
        "--aws-retries-max-attempts",
        str(options.prowler_retry_attempts),
        # Exit code 3 means "some checks failed", the expected result of a scan.
        "--ignore-exit-code-3",
    ]
    if regions:
        cmd += ["--region", *regions]
    services, checks, notes = _prowler_skips(
        options.prowler_skip_services, options.prowler_skip_checks
    )
    if services:
        cmd += ["--excluded-service", *services]
    if checks:
        cmd += ["--excluded-check", *checks]
    if services or checks:
        cmd += ["--compliance", *prowler_frameworks()]
    # The Runs page keeps 1,000 characters of the command: the 44 framework names would push
    # out what matters, so the shown command names them by count.
    shown = command_line(cmd, out_dir).replace(
        " ".join(prowler_frameworks()), f"<every AWS framework: {len(prowler_frameworks())}>"
    )
    rc = _run(
        cmd,
        env=env,
        log=log,
        limit=options.time_limit or TimeLimit(),
        cancel=options.cancel,
        stream=stream,
        guard=options.memory_guard,
        tty=True,
        routing=Routing(_prowler_fate(stream), rewrite=prowler_line),
    )
    lines, throttled = _read_log(log)
    lines = [*notes, *lines]
    # A check whose calls were denied has no result, so it resolves nothing: the run stays
    # complete, and the denied actions are reported.
    denials = read_denials(log.read_text(errors="replace")) if log.exists() else Denials()
    refused, blocked = _denied_list(denials.denied), _denied_list(denials.blocked)
    # Read from the installed package: `prowler --version` checks GitHub for a newer release.
    version = _version(
        [PROWLER_PYTHON, "-c", "import importlib.metadata as m; print(m.version('prowler'))"], env
    )
    return ToolResult(
        _status(rc == 0, throttled),
        rc,
        version,
        _with_denied(lines, refused, blocked),
        throttled,
        refused,
        shown,
        refused_actions=_denied_list(denials.refused),
        blocked_actions=blocked,
    )


# Prowler's log lines (prowler/lib/logger.py): "<time> [File: <f>:<n>] \t[Module: <m>]\t
# <LEVEL>: <message>". botocore's "Retry needed, ..." comes through the launcher only.
_PROWLER_INFO = re.compile(r"\]\s+INFO: ")
# The two tabs of that format, around "[Module: <m>]": redact_text drops a line with two tabs
# as a table row (tables print data), so every Prowler log line, errors included, read
# "[table row omitted]" on the Runs page and in the live log (found 2026-11-19). Only these two
# are replaced; a tab inside the message still marks a table row.
_PROWLER_FORMAT_TABS = re.compile(
    r"^(.{0,40}\[File: [^\]\t]{1,200}\]) \t(\[Module: [^\]\t]{1,100}\])\t "
)


def prowler_line(text: str) -> str:
    """A line of Prowler's in one shape redaction reads as text: its log format's own two tabs
    become spaces (_PROWLER_FORMAT_TABS); everything else is as Prowler wrote it."""
    return _PROWLER_FORMAT_TABS.sub(r"\1 \2 ", text, count=1)


_PROWLER_RETRY = re.compile(r"\]\s+DEBUG: Retry needed")


def _prowler_fate(stream: ToolStream | None) -> LineFate:
    """Where each line of Prowler's goes: a retry is counted; an INFO line (the service and
    call it is on) goes to the live log only, so the Runs page's tail keeps its errors; the
    rest, errors included, goes to both."""

    def fate(text: str) -> str:
        if _PROWLER_RETRY.search(text):
            if stream is not None:
                stream.count(RETRIED)
            return "drop"
        if THROTTLING.search(text) and stream is not None:
            stream.count(THROTTLED)
        return "live" if _PROWLER_INFO.search(text) else "log"

    return fate


def run_cloudfox(
    out_dir: Path,
    env: dict[str, str],
    account_id: str,
    options: CollectOptions,
    *,
    stream: ToolStream | None = None,
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
        str(options.cloudfox_max_goroutines),
    ]
    errors_from = _size(CLOUDFOX_ERROR_LOG)
    tail = _ErrorLogTail(errors_from, account_id, stream)
    try:
        with tail:
            rc = _run(
                cmd,
                env=env,
                log=log,
                limit=options.time_limit or TimeLimit(),
                cancel=options.cancel,
                stream=stream,
                guard=options.memory_guard,
            )
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
    why = _cloudfox_failure(rc, text, out_dir)
    ok = why is None
    added = _cloudfox_log_added(errors_from)
    if why is not None:
        # The console at --verbosity 1 rarely says why; CloudFox's own error log often does.
        lines = [*lines, *_cloudfox_error_tail(added, account_id), f"argus: CloudFox failed: {why}"]
    # Module errors go to CloudFox's own error log, not the console ("0 errors" there). A
    # denied module leaves its findings unseen, so the run is partial and resolves nothing.
    denials = read_denials(_cloudfox_errors(added, account_id))
    refused, blocked = _denied_list(denials.denied), _denied_list(denials.blocked)
    status = _status(ok, throttled)
    # CloudFox has no per-table scope: any refused call, the role's or a policy's, leaves
    # findings unseen that a complete run would resolve.
    if status == "complete" and (refused or blocked or denials.refused):
        status = "partial"
    version = _version([CLOUDFOX, "--version"], env)
    return ToolResult(
        status,
        rc,
        version,
        _with_denied(lines, refused, blocked),
        throttled,
        refused,
        command_line(cmd, out_dir),
        refused_actions=_denied_list(denials.refused),
        blocked_actions=blocked,
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


def _cloudfox_failure(rc: int, console: str, out_dir: Path) -> str | None:
    """Why a CloudFox run failed, in a few words, or None when it did not."""
    if rc != 0:
        return f"exit code {rc}"
    if "Could not get caller's identity" in console:
        return "it could not get the caller's identity"
    if re.search(r"^Error:", console, re.MULTILINE):
        return "it printed an error"
    if not any(out_dir.iterdir()):
        return "it wrote no output"
    return None


class _ErrorLogTail:
    """CloudFox's error log in the live log while it runs (owner, 2026-11-19): what a module
    could not read, throttling included (counted too), as CloudFox writes it there and not on
    its console. The same lines as a failed run's tail (_cloudfox_error_tail): only what this
    run added, never a line naming another account, each cut to CLOUDFOX_ERROR_LINE_CHARS."""

    EVERY = 2.0  # seconds between looks at the file

    def __init__(self, start: int, account_id: str, stream: ToolStream | None) -> None:
        self.offset, self.account_id, self.stream = start, account_id, stream
        self.pending = b""
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._follow, name="cloudfox-errors", daemon=True)

    def __enter__(self) -> "_ErrorLogTail":
        if self.stream is not None:
            self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.stream is not None:
            self.stop.set()
            self.thread.join(timeout=READER_JOIN_SECONDS)

    def _follow(self) -> None:
        while not self.stop.wait(self.EVERY):
            self.read()
        self.read(final=True)

    def read(self, *, final: bool = False) -> None:
        try:
            with CLOUDFOX_ERROR_LOG.open("rb") as errors:
                errors.seek(self.offset)
                added = errors.read(1 << 20)
        except OSError:
            return
        self.offset += len(added)
        *lines, self.pending = (self.pending + added).split(b"\n")
        if final:
            lines, self.pending = [*lines, self.pending], b""
        for raw in lines:
            line = raw.decode(errors="replace").strip()
            if not line or any(f != self.account_id for f in _ACCOUNT_IN_LINE.findall(line)):
                continue
            assert self.stream is not None  # noqa: S101 - started only with a stream
            if THROTTLING.search(line):
                self.stream.count(THROTTLED)
            self.stream.capped(f"[error log] {line[:CLOUDFOX_ERROR_LINE_CHARS]}")


def _cloudfox_log_added(start: int) -> str:
    """What this run added to CloudFox's error log. The log is left in place: deleting it
    would break a concurrent run."""
    try:
        with CLOUDFOX_ERROR_LOG.open("rb") as errors:
            errors.seek(start)
            return errors.read().decode(errors="replace")
    except OSError:
        return ""


def _cloudfox_errors(added: str, account_id: str) -> str:
    """The added lines that name this account. Two accounts' CloudFox runs can share the log
    on Compose, and a denial names the principal's ARN."""
    return "\n".join(line for line in added.splitlines() if f":{account_id}:" in line)


# An account id inside an ARN: ":123456789012:".
_ACCOUNT_IN_LINE = re.compile(r":(\d{12}):")


def _cloudfox_error_tail(added: str, account_id: str) -> list[str]:
    """The last lines this run added to CloudFox's error log, for a failed run: a fatal error
    often names no account, so only lines naming another account (a concurrent run's on
    Compose) are left out. Short enough that the Runs page's 4,000 characters keep them and
    the console's last lines too; redacted with the rest of the log on the way to Postgres."""
    kept = [
        line[:CLOUDFOX_ERROR_LINE_CHARS]
        for line in added.splitlines()
        if line.strip() and all(found == account_id for found in _ACCOUNT_IN_LINE.findall(line))
    ][-CLOUDFOX_ERROR_LINES:]
    if not kept:
        return ["argus: CloudFox's error log: nothing added by this run"]
    return ["argus: CloudFox's error log, last lines:", *kept]


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


def missing_tools(tools: Sequence[str]) -> list[str]:
    """The tools among `tools` whose binary this image does not carry, or cannot run."""
    return [
        tool
        for tool in tools
        if tool not in TOOL_BINARIES or not os.access(TOOL_BINARIES[tool], os.X_OK)
    ]
