"""A run's tool output in the process's own log while the tool runs (owner, 2026-11-18): on
Kubernetes `kubectl logs -f` on a scan Job, on Compose `docker compose logs -f worker`, read
like the tool's console.

Every line is redacted here and again by the JSON formatter (core/logging.py), as the Runs
log is on its way to Postgres: a pod's output often leaves the cluster for a log pipeline.
Nothing here raises a tool's verbosity; CloudFox stays at --verbosity 1, below which it prints
module output with secret values.

A progress bar redraws its line with carriage returns many times a second: those updates are
collapsed to one line every PROGRESS_EVERY seconds; the last update held back is logged when
the tool ends, unless a line followed it.
While the tool runs, a heartbeat line every HEARTBEAT_EVERY seconds says it is still running
(and, where a status is given, what else is known, such as its memory and the tables running),
and what was counted since the last one: AWS's retries and the calls that gave up throttled
(owner, 2026-11-19: "not seeing ... if is scanning what resource or doing what or having
throttling"). Counted lines are not printed one by one.

A tool that prints faster than MAX_LINES_PER_SECOND has the rest of that second's lines left
out, and the heartbeat says how many: the log pipeline is not flooded.
"""

import logging
import os
import re
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import IO, Self

from argus.core.redaction import redact_text

logger = logging.getLogger("argus.tool")

PROGRESS_EVERY = 10.0
HEARTBEAT_EVERY = 60.0
# A line longer than this is cut: a tool that prints a whole JSON document on one line would
# otherwise fill the log pipeline.
MAX_LINE_CHARS = 2000
# A pending line with no end yet is logged once it is this long.
_MAX_PENDING = 64 * 1024
_READ_SIZE = 64 * 1024
_SEPARATOR = re.compile(rb"\r\n|\n|\r")
MAX_LINES_PER_SECOND = 20
# A terminal's control sequences (colour, cursor, clear line): a tool run under a
# pseudo-terminal draws with them, and they would hide words from the patterns that read a line.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# What a heartbeat counts, in the order it says them.
RETRIED = "AWS calls retried"
THROTTLED = "calls given up throttled"


def _elapsed(seconds: float) -> str:
    minutes = int(seconds // 60)
    return f"{minutes // 60}h{minutes % 60:02d}m" if minutes >= 60 else f"{minutes}m"


class ToolStream:
    """One run's live log. Use as a context manager: the heartbeat runs inside it."""

    def __init__(
        self,
        tool: str,
        *,
        fields: dict[str, object] | None = None,
        status: Callable[[], str | None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        heartbeat_every: float = HEARTBEAT_EVERY,
        progress_every: float = PROGRESS_EVERY,
    ) -> None:
        self.tool = tool
        self.fields = {"tool": tool, **(fields or {})}
        self.status = status
        self._clock = clock
        self._heartbeat_every = heartbeat_every
        self._progress_every = progress_every
        self._lock = threading.Lock()
        self._progress: str | None = None  # the latest update not logged yet
        self._progress_at: float | None = None  # when one was last logged
        self._started = clock()
        self._stop = threading.Event()
        self._beat: threading.Thread | None = None
        self._statuses: list[Callable[[], str | None]] = [status] if status is not None else []
        self._counts: dict[str, Counter[str]] = {}  # what -> where -> how many, since a beat
        self._second: int | None = None  # the second the line cap counts in
        self._lines_this_second = 0
        self._left_out = 0  # lines left out by the cap since the last heartbeat

    def __enter__(self) -> Self:
        self._started = self._clock()
        self._beat = threading.Thread(target=self._heartbeat, name="tool-heartbeat", daemon=True)
        self._beat.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        if self._beat is not None:
            self._beat.join(timeout=5)
        self.flush()

    def line(self, text: str) -> None:
        """A line the tool printed. A progress update held back is dropped: the line ends it."""
        text = text.strip()
        if text:
            with self._lock:
                self._progress = None
            self._log(text)

    def progress(self, text: str) -> None:
        """A progress update (a line redrawn with a carriage return)."""
        text = text.strip()
        if not text:
            return
        with self._lock:
            now = self._clock()
            if self._progress_at is not None and now - self._progress_at < self._progress_every:
                self._progress = text
                return
            self._progress, self._progress_at = None, now
        self._log(text)

    def note(self, text: str) -> None:
        """Argus's own line about the run, such as a Steampipe table's progress."""
        self._log(f"argus: {text}")

    def count(self, what: str, where: str = "") -> None:
        """One more of `what` (RETRIED, THROTTLED), at `where` (a table): said in the next
        heartbeat, not as a line."""
        with self._lock:
            self._counts.setdefault(what, Counter())[where] += 1

    def add_status(self, status: Callable[[], str | None]) -> None:
        """Something else the heartbeat says, such as the tables running."""
        self._statuses.append(status)

    def flush(self) -> None:
        """Logs the last progress update held back, if any."""
        with self._lock:
            pending, self._progress = self._progress, None
        if pending:
            self._log(pending)

    def heartbeat(self) -> None:
        parts = [f"argus: {self.tool} running {_elapsed(self._clock() - self._started)}"]
        parts += [said for status in self._statuses if (said := status())]
        with self._lock:
            counts, self._counts = self._counts, {}
            left_out, self._left_out = self._left_out, 0
        minute = _elapsed(self._heartbeat_every)
        for what in (RETRIED, THROTTLED):
            if found := counts.get(what):
                parts.append(f"{what} in the last {minute}: {_counted(found)}")
        if left_out:
            parts.append(f"{left_out} lines left out (more than {MAX_LINES_PER_SECOND} a second)")
        self._log(", ".join(parts))

    def _heartbeat(self) -> None:
        while not self._stop.wait(self._heartbeat_every):
            self.heartbeat()

    def _log(self, text: str) -> None:
        logger.info(redact_text(text[:MAX_LINE_CHARS]), extra=self.fields)

    def capped(self, text: str) -> None:
        """A line the tool printed, unless this second's lines are used up (counted instead)."""
        if not text.strip():
            return
        second = int(self._clock())
        with self._lock:
            if second != self._second:
                self._second, self._lines_this_second = second, 0
            self._lines_this_second += 1
            if self._lines_this_second > MAX_LINES_PER_SECOND:
                self._left_out += 1
                return
        self.line(text)


def _counted(found: Counter[str]) -> str:
    """ "214" or "214 (aws_ec2_instance 200, aws_s3_bucket 14)": the busiest five named."""
    total = sum(found.values())
    named = [(where, n) for where, n in found.most_common() if where][:5]
    if not named:
        return str(total)
    return f"{total} ({', '.join(f'{where} {n}' for where, n in named)})"


# How one line of a tool's output is handled: "log" in its log file and the live log, "count"
# counted and kept out of both, "file" in the log file only (the Runs page's tail), "live" in
# the live log only.
LineFate = Callable[[str], str]


@dataclass(frozen=True)
class Routing:
    """How pump routes a tool's lines: `fate` says where each goes; `rewrite` reshapes a line
    before anything reads it (a tool's own fixed log format, prowler_line)."""

    fate: LineFate
    rewrite: Callable[[str], str] | None = None


def _keep(_text: str) -> str:
    return "log"


def pump(
    source: IO[bytes],
    sink: IO[bytes],
    stream: ToolStream | None,
    routing: Routing | None = None,
    label: str = "",
) -> None:
    """Copies a tool's output to its log file and, line by line, to the live log. Without
    `routing`, the file gets the output unchanged. With it, each line goes where its fate says,
    and the file gets whole lines only: a progress bar's redraws never reach it (its last
    state does, when the tool ends on it), so the Runs page's tail keeps the lines that matter.
    Ends when the tool's end of the pipe (or pseudo-terminal) closes; never raises (the run
    reads the file)."""
    pending = b""
    lines = _Lines(sink, stream, routing, label)
    try:
        while chunk := os.read(source.fileno(), _READ_SIZE):
            if routing is None:
                sink.write(chunk)
                if stream is None:
                    continue
            pending += chunk
            pending = _split(pending, lines, final=False)
    except (OSError, ValueError):  # the pseudo-terminal's end (EIO), or a file closed under
        pass  # a tool that outlived the wait
    try:
        _split(pending, lines, final=True)
        lines.end()
    except (OSError, ValueError):
        return


class _Lines:
    """Where pump's lines go: the live log (capped when a fate is given) and, with a fate,
    the log file."""

    def __init__(
        self, sink: IO[bytes], stream: ToolStream | None, routing: Routing | None, label: str
    ) -> None:
        self.sink, self.stream = sink, stream
        self.fate = routing.fate if routing is not None else None
        self.rewrite = routing.rewrite if routing is not None else None
        self.label = f"[{label}] " if label else ""  # which table, in the live log
        self.redraw = ""  # a progress bar's latest state, for the file

    def line(self, text: str) -> None:
        if self.fate is None:
            if self.stream is not None:
                self.stream.line(text)
            return
        self.redraw = ""  # a line ends a bar, as on the screen: its own text is the last state
        if self.rewrite is not None:
            text = self.rewrite(text)
        fate = self.fate(text)
        if fate in {"log", "file"} and text.strip():
            self._to_file(text)
        if fate in {"log", "live"} and self.stream is not None and text.strip():
            self.stream.capped(self.label + text)

    def progress(self, text: str) -> None:
        if self.fate is not None:
            self.redraw = text
        if self.stream is not None:
            self.stream.progress(text)

    def end(self) -> None:
        if self.redraw.strip():
            self._to_file(self.redraw)
            self.redraw = ""

    def _to_file(self, text: str) -> None:
        self.sink.write(text.encode() + b"\n")


def _split(data: bytes, lines: _Lines, *, final: bool) -> bytes:
    """Hands every complete line in `data` on; returns what has no end yet."""
    start = 0
    for match in _SEPARATOR.finditer(data):
        sep = match.group()
        # A carriage return at the very end may be the first half of "\r\n": wait for more.
        if sep == b"\r" and match.end() == len(data) and not final:
            break
        text = _ANSI.sub("", data[start : match.start()].decode(errors="replace"))
        if sep == b"\r":
            lines.progress(text)
        else:
            lines.line(text)
        start = match.end()
    rest = data[start:]
    if final or len(rest) > _MAX_PENDING:
        if rest:
            lines.line(_ANSI.sub("", rest.decode(errors="replace")))
        return b""
    return rest
