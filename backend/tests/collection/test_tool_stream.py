"""A tool's output in the live log while it runs (collection/aws/stream.py): the lines arrive
before the tool ends, the log file the run reads is unchanged, progress redraws are collapsed,
and every line is redacted."""

import json
import logging
import stat
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from argus.collection.aws import stream as live
from argus.collection.aws import tools as aws_tools
from argus.collection.aws.stream import ToolStream
from argus.collection.collect import Cancelled, TimeLimit
from argus.core.logging import JsonFormatter
from argus.core.memory import MemoryGuard, OutOfMemory
from argus.core.redaction import TABLE_ROW_OMITTED, redact_text


class _Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []
        self.seen = threading.Event()

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        self.seen.set()

    def messages(self) -> list[str]:
        return [r.getMessage() for r in self.records]


@pytest.fixture
def captured() -> object:
    handler = _Lines()
    log = logging.getLogger("argus.tool")
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    yield handler
    log.removeHandler(handler)


def _tool(path: Path, body: str) -> list[str]:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return [str(path)]


def _env(tmp_path: Path) -> dict[str, str]:
    return {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}


def test_lines_reach_the_live_log_while_the_tool_runs(tmp_path: Path, captured: _Lines) -> None:
    go_on = tmp_path / "go-on"
    cmd = _tool(
        tmp_path / "tool",
        f'echo "-> Scanning ec2 service"\nwhile [ ! -f "{go_on}" ]; do sleep 0.05; done\n'
        'echo "done"\n',
    )
    result: list[int] = []
    with ToolStream("prowler", fields={"run_uid": "r1"}) as stream:
        runner = threading.Thread(
            target=lambda: result.append(
                aws_tools._run(
                    cmd,
                    env=_env(tmp_path),
                    log=tmp_path / "tool.log",
                    limit=TimeLimit(timedelta(seconds=30)),
                    stream=stream,
                )
            )
        )
        runner.start()
        assert captured.seen.wait(10), "no line while the tool was still running"
        assert captured.messages() == ["-> Scanning ec2 service"]
        assert runner.is_alive()
        go_on.touch()
        runner.join(10)
    assert result == [0]
    assert captured.messages() == ["-> Scanning ec2 service", "done"]
    assert captured.records[0].tool == "prowler"  # type: ignore[attr-defined]
    assert captured.records[0].run_uid == "r1"  # type: ignore[attr-defined]


def test_the_log_file_keeps_every_byte_as_the_tool_wrote_it(
    tmp_path: Path, captured: _Lines
) -> None:
    cmd = _tool(tmp_path / "tool", r"printf 'one\r\ntwo\r 10%%\r 20%%\nthree'" + "\n")
    with ToolStream("cloudfox") as stream:
        aws_tools._run(
            cmd,
            env=_env(tmp_path),
            log=tmp_path / "tool.log",
            limit=TimeLimit(timedelta(seconds=30)),
            stream=stream,
        )
    assert (tmp_path / "tool.log").read_bytes() == b"one\r\ntwo\r 10%\r 20%\nthree"
    # "\r\n" ends a line; a lone "\r" is a progress redraw, the first one logged at once.
    assert captured.messages() == ["one", "two", "20%", "three"]


def test_progress_redraws_are_collapsed(captured: _Lines) -> None:
    now = [0.0]
    stream = ToolStream("prowler", clock=lambda: now[0], progress_every=10)
    for second, percent in [(0, 1), (1, 2), (5, 3), (11, 4), (12, 5)]:
        now[0] = float(second)
        stream.progress(f"{percent}%")
    stream.flush()
    assert captured.messages() == ["1%", "4%", "5%"]  # the last one, at the end
    now[0] = 30.0
    stream.progress("6%")
    now[0] = 31.0
    stream.progress("7%")
    stream.line("finished")  # ends the bar: 7% is not logged after it
    stream.flush()
    assert captured.messages() == ["1%", "4%", "5%", "6%", "finished"]


def test_every_line_is_redacted(tmp_path: Path, captured: _Lines) -> None:
    planted = "hunter2-not-a-real-password"
    cmd = _tool(tmp_path / "tool", f'echo "lambda env: DB_PASSWORD={planted}"\n')
    with ToolStream("cloudfox") as stream:
        aws_tools._run(
            cmd,
            env=_env(tmp_path),
            log=tmp_path / "tool.log",
            limit=TimeLimit(timedelta(seconds=30)),
            stream=stream,
        )
    assert captured.records
    assert all(planted not in m for m in captured.messages())
    formatted = [json.loads(JsonFormatter().format(r)) for r in captured.records]
    assert all(planted not in json.dumps(f) for f in formatted)


def test_a_cancelled_tool_is_killed_and_its_output_stops(tmp_path: Path, captured: _Lines) -> None:
    cmd = _tool(tmp_path / "tool", "echo started\nwhile true; do sleep 0.05; done\n")
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    started = time.monotonic()
    with ToolStream("prowler") as stream, pytest.raises(Cancelled):
        aws_tools._run(
            cmd,
            env=_env(tmp_path),
            log=tmp_path / "tool.log",
            limit=TimeLimit(timedelta(seconds=30)),
            cancel=cancel,
            stream=stream,
        )
    assert time.monotonic() - started < 10
    assert not [t for t in threading.enumerate() if t.name == "tool-output"]
    assert captured.messages() == ["started"]


def test_a_child_holding_the_output_open_does_not_hold_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(aws_tools, "READER_JOIN_SECONDS", 0.2)
    cmd = _tool(tmp_path / "tool", "(sleep 3 &)\necho parent done\n")
    started = time.monotonic()
    rc = aws_tools._run(
        cmd, env=_env(tmp_path), log=tmp_path / "tool.log", limit=TimeLimit(timedelta(seconds=30))
    )
    assert rc == 0
    assert time.monotonic() - started < 2.5
    assert b"parent done" in (tmp_path / "tool.log").read_bytes()


def test_a_tool_past_its_time_limit_is_killed_and_the_limit_marked(tmp_path: Path) -> None:
    """The run then fails without a retry (scheduling.runner): the mark is what says so."""
    cmd = _tool(tmp_path / "tool", "echo started\nwhile true; do sleep 0.05; done\n")
    limit = TimeLimit(timedelta(seconds=1))
    started = time.monotonic()
    rc = aws_tools._run(cmd, env=_env(tmp_path), log=tmp_path / "tool.log", limit=limit)
    assert rc == -9 and limit.reached
    assert time.monotonic() - started < 5
    assert b"argus: stopped after its time limit of 1 s" in (tmp_path / "tool.log").read_bytes()


def test_a_tool_that_ends_in_time_leaves_the_limit_unmarked(tmp_path: Path) -> None:
    limit = TimeLimit(timedelta(seconds=30))
    rc = aws_tools._run(
        _tool(tmp_path / "tool", "echo done\n"),
        env=_env(tmp_path),
        log=tmp_path / "t.log",
        limit=limit,
    )
    assert rc == 0 and not limit.reached


def test_a_heartbeat_says_the_tool_is_still_running(captured: _Lines) -> None:
    now = [0.0]
    stream = ToolStream("steampipe", clock=lambda: now[0], status=lambda: "memory 1.0 of 6.0 GiB")
    now[0] = 42 * 60 + 5
    stream.heartbeat()
    now[0] = 2 * 3600 + 7 * 60
    stream.heartbeat()
    assert captured.messages() == [
        "argus: steampipe running 42m, memory 1.0 of 6.0 GiB",
        "argus: steampipe running 2h07m, memory 1.0 of 6.0 GiB",
    ]


def test_the_heartbeat_thread_beats_and_stops(captured: _Lines) -> None:
    with ToolStream("cloudfox", heartbeat_every=0.05):
        time.sleep(0.3)
    beats = len(captured.messages())
    assert beats >= 2
    assert all(m.startswith("argus: cloudfox running 0m") for m in captured.messages())
    time.sleep(0.2)
    assert len(captured.messages()) == beats


def test_a_very_long_line_is_cut(captured: _Lines) -> None:
    ToolStream("prowler").line("checking bucket " * 200)
    assert len(captured.messages()[0]) <= live.MAX_LINE_CHARS
    assert captured.messages()[0].startswith("checking bucket checking")


def test_a_tool_near_the_memory_limit_is_killed(tmp_path: Path) -> None:
    """The guard is read on every look at the tool (a second apart): over the line, the tool's
    group is killed and the run raises, before the kernel would kill the pod."""
    root = tmp_path / "cgroup"
    root.mkdir()
    (root / "memory.max").write_text(str(1 << 30))
    (root / "memory.stat").write_text(f"anon {100 << 20}\nshmem 0\n")
    cmd = _tool(tmp_path / "tool", "echo started\nwhile true; do sleep 0.05; done\n")
    guard = MemoryGuard(root)
    threading.Timer(
        0.5, lambda: (root / "memory.stat").write_text(f"anon {900 << 20}\nshmem 0\n")
    ).start()
    started = time.monotonic()
    with pytest.raises(OutOfMemory):
        aws_tools._run(
            cmd,
            env=_env(tmp_path),
            log=tmp_path / "tool.log",
            limit=TimeLimit(timedelta(seconds=30)),
            guard=guard,
        )
    assert time.monotonic() - started < 10
    assert guard.over is not None


# What the tools print, as seen 2026-11-19 (ids made up): the plugin's retry at INFO, Prowler's
# INFO line and botocore's retry through the launcher.
PLUGIN_RETRY = (
    "[INFO]  1795110796697: BackoffDelay: attempt=1, retryTime=63ms, err=operation error EC2: "
    "DescribeInstances, https response error StatusCode: 400, api error Throttling: Rate exceeded"
)
PLUGIN_GAVE_UP = (
    "[WARN]  1795110796698: error channel received aws: operation error EC2: DescribeInstances, "
    "exceeded maximum number of attempts, 10, api error Throttling: Rate exceeded"
)
PROWLER_INFO = (
    "2026-11-19 18:20:38,438 [File: service.py:63] \t[Module: service]\t INFO: EC2 - Starting "
    "threads for 'describe_instances' function across 17 regions..."
)
PROWLER_RETRY = (
    "2026-11-19 18:20:38,534 [File: standard.py:91] \t[Module: standard]\t DEBUG: Retry needed, "
    "retrying request after delay of: 0.34"
)
PROWLER_ERROR = (
    "2026-11-19 18:20:39,000 [File: service.py:90] \t[Module: service]\t ERROR: us-east-1 -- "
    "ClientError[90]: An error occurred (ThrottlingException) when calling DescribeInstances"
)


def test_a_heartbeat_says_what_was_counted_since_the_last(captured: _Lines) -> None:
    """The owner could not see throttling while a scan ran (2026-11-19): retries and calls
    given up are counted, said once a heartbeat, busiest first, and start again from zero."""
    now = [0.0]
    stream = ToolStream("steampipe", clock=lambda: now[0])
    stream.add_status(lambda: "tables running: aws_s3_bucket 3 min 12 MB")
    for _ in range(3):
        stream.count(live.RETRIED, "aws_ec2_instance")
    stream.count(live.RETRIED, "aws_s3_bucket")
    stream.count(live.THROTTLED, "aws_ec2_instance")
    now[0] = 60.0
    stream.heartbeat()
    now[0] = 120.0
    stream.heartbeat()
    assert captured.messages() == [
        "argus: steampipe running 1m, tables running: aws_s3_bucket 3 min 12 MB, "
        "AWS calls retried in the last 1m: 4 (aws_ec2_instance 3, aws_s3_bucket 1), "
        "calls given up throttled in the last 1m: 1 (aws_ec2_instance 1)",
        "argus: steampipe running 2m, tables running: aws_s3_bucket 3 min 12 MB",
    ]


def test_a_tool_printing_too_fast_is_cut_to_a_number_of_lines_a_second(captured: _Lines) -> None:
    now = [5.0]
    stream = ToolStream("prowler", clock=lambda: now[0])
    for n in range(live.MAX_LINES_PER_SECOND + 7):
        stream.capped(f"line {n}")
    now[0] = 6.0
    stream.capped("next second")
    stream.heartbeat()
    assert len(captured.messages()) == live.MAX_LINES_PER_SECOND + 2
    assert captured.messages()[-2] == "next second"
    assert captured.messages()[-1].endswith("7 lines left out (more than 20 a second)")


def test_with_a_fate_each_line_goes_where_it_says(tmp_path: Path, captured: _Lines) -> None:
    """The log file (the Runs page's tail, the denials) gets whole lines, and a progress bar
    only as the state the tool ended on; a counted line reaches neither; terminal codes are
    stripped."""
    cmd = _tool(
        tmp_path / "tool",
        "printf 'start\\n10%%\\r50%%\\r\\033[31mred error\\033[0m\\n'\n"
        "printf 'live only\\ncounted\\n90%%\\r'\n",
    )
    fates = {"live only": "live", "counted": "drop"}
    log = tmp_path / "tool.log"
    stream = ToolStream("prowler", progress_every=0)
    aws_tools._run(
        cmd,
        env=_env(tmp_path),
        log=log,
        limit=TimeLimit(timedelta(seconds=10)),
        stream=stream,
        routing=live.Routing(lambda text: fates.get(text, "log")),
    )
    stream.flush()
    assert log.read_text() == "start\nred error\n90%\n"  # a line replaces a redraw
    assert captured.messages() == ["start", "10%", "50%", "red error", "live only", "90%"]


def test_a_tool_on_a_terminal_draws_its_bar_into_the_live_log(
    tmp_path: Path, captured: _Lines
) -> None:
    """Prowler draws its progress bar only on a terminal (seen 2026-11-19): with tty, the tool
    sees one, a wide one, and its lines end in "\\n", not "\\r\\n"."""
    cmd = _tool(
        tmp_path / "tool",
        "[ -t 1 ] && echo terminal || echo pipe\nstty -F /proc/self/fd/1 size\n"
        "printf 'a\\rb\\nend\\n'\n",
    )
    log = tmp_path / "tool.log"
    aws_tools._run(
        cmd,
        env=_env(tmp_path),
        log=log,
        limit=TimeLimit(timedelta(seconds=10)),
        stream=ToolStream("prowler", progress_every=0),
        tty=True,
        routing=live.Routing(lambda _t: "log"),
    )
    assert log.read_text() == (
        f"terminal\n{aws_tools.TERMINAL_ROWS} {aws_tools.TERMINAL_COLUMNS}\nb\nend\n"
    )
    assert "terminal" in captured.messages()


@pytest.mark.parametrize(
    ("line", "fate", "counted"),
    [
        (PLUGIN_RETRY, "drop", (live.RETRIED, "aws_ec2_instance")),
        ("[INFO]  1795110796697: listRegions: connection_name=aws", "drop", None),
        ("  | a continuation of the entry above", "drop", None),
        (PLUGIN_GAVE_UP, "log", (live.THROTTLED, "aws_ec2_instance")),
        ("[ERROR] 1: aws_ec2_instance.list: api_error=AccessDenied", "log", None),
        ("Plugin.getSchema failed", "log", None),
    ],
    ids=["retry", "info", "continuation", "gave-up", "error", "no-level"],
)
def test_a_tables_log_line_is_counted_dropped_or_kept(
    line: str, fate: str, counted: tuple[str, str] | None
) -> None:
    """At INFO the plugin logs every retry; its error file, which the judgement reads, still
    gets only what the default level (WARN) gave."""
    stream = ToolStream("steampipe")
    table_fate = aws_tools._table_fate(stream, "aws_ec2_instance")
    table_fate("[INFO]  1: an INFO entry first")  # a continuation follows the entry before it
    assert table_fate(line) == fate
    found = {(what, where) for what, c in stream._counts.items() for where in c}
    assert found == ({counted} if counted else set())


@pytest.mark.parametrize(
    ("line", "fate", "counted"),
    [
        (PROWLER_RETRY, "drop", live.RETRIED),
        (PROWLER_INFO, "live", None),
        (PROWLER_ERROR, "log", live.THROTTLED),
        ("-> Scanning ec2 service", "log", None),
    ],
    ids=["retry", "info", "throttled-error", "console"],
)
def test_a_prowler_line_is_counted_kept_live_or_logged(
    line: str, fate: str, counted: str | None
) -> None:
    stream = ToolStream("prowler")
    assert aws_tools._prowler_fate(stream)(line) == fate
    assert set(stream._counts) == ({counted} if counted else set())


def test_a_prowler_log_line_is_text_to_the_redactor_and_keeps_what_denials_read() -> None:
    """Prowler's log format puts two tabs around "[Module: ...]", and redact_text drops a line
    with two tabs as a table row: every Prowler error read "[table row omitted]" (found
    2026-11-19). Only those two tabs go; a tab-separated message is still dropped."""
    line = aws_tools.prowler_line(PROWLER_ERROR)
    assert "\t" not in line
    assert line.startswith("2026-11-19 18:20:39,000 [File: service.py:90] [Module: service] ERROR:")
    assert redact_text(line) == line
    assert redact_text(PROWLER_ERROR) == TABLE_ROW_OMITTED  # as it was
    data = PROWLER_ERROR.replace("ERROR: ", "ERROR: name\tvalue\tsecret ")
    assert redact_text(aws_tools.prowler_line(data)) == TABLE_ROW_OMITTED
    denied = (
        "2026-11-19 18:20:39,000 [File: glue_service.py:66] \t[Module: glue_service]\t ERROR: "
        "us-east-1 -- ClientError[66]: An error occurred (AccessDeniedException) when calling "
        "the GetDevEndpoints operation"
    )
    assert aws_tools.read_denials(aws_tools.prowler_line(denied)).denied == {"glue:GetDevEndpoints"}


def test_without_a_pseudo_terminal_the_tool_still_runs(
    tmp_path: Path, captured: _Lines, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_terminal() -> tuple[int, int]:
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr(aws_tools.pty, "openpty", no_terminal)
    cmd = _tool(tmp_path / "tool", "[ -t 1 ] && echo terminal || echo pipe\n")
    rc = aws_tools._run(
        cmd,
        env=_env(tmp_path),
        log=tmp_path / "tool.log",
        limit=TimeLimit(timedelta(seconds=10)),
        stream=ToolStream("prowler"),
        tty=True,
        routing=live.Routing(lambda _t: "log"),
    )
    assert rc == 0
    assert captured.messages() == [
        "argus: no pseudo-terminal (No such file or directory): progress bar not shown",
        "pipe",
    ]
