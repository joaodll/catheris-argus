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
from argus.collection.collect import Cancelled
from argus.core.logging import JsonFormatter


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
                    timeout=timedelta(seconds=30),
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
            timeout=timedelta(seconds=30),
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
            timeout=timedelta(seconds=30),
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
            timeout=timedelta(seconds=30),
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
        cmd, env=_env(tmp_path), log=tmp_path / "tool.log", timeout=timedelta(seconds=30)
    )
    assert rc == 0
    assert time.monotonic() - started < 2.5
    assert b"parent done" in (tmp_path / "tool.log").read_bytes()


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
