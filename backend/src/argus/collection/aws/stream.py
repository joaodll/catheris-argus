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
(and, where a status is given, what else is known, such as its memory).
"""

import logging
import os
import re
import threading
import time
from collections.abc import Callable
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

    def flush(self) -> None:
        """Logs the last progress update held back, if any."""
        with self._lock:
            pending, self._progress = self._progress, None
        if pending:
            self._log(pending)

    def heartbeat(self) -> None:
        running = f"argus: {self.tool} running {_elapsed(self._clock() - self._started)}"
        extra = self.status() if self.status is not None else None
        self._log(f"{running}, {extra}" if extra else running)

    def _heartbeat(self) -> None:
        while not self._stop.wait(self._heartbeat_every):
            self.heartbeat()

    def _log(self, text: str) -> None:
        logger.info(redact_text(text[:MAX_LINE_CHARS]), extra=self.fields)


def pump(source: IO[bytes], sink: IO[bytes], stream: ToolStream | None) -> None:
    """Copies a tool's output to its log file unchanged and, line by line, to the live log.
    Ends when the tool's end of the pipe closes; never raises (the run reads the file)."""
    pending = b""
    try:
        while chunk := os.read(source.fileno(), _READ_SIZE):
            sink.write(chunk)
            if stream is None:
                continue
            pending += chunk
            pending = _split(pending, stream, final=False)
        if stream is not None:
            _split(pending, stream, final=True)
    except (OSError, ValueError):  # the file was closed under a tool that outlived the wait
        return


def _split(data: bytes, stream: ToolStream, *, final: bool) -> bytes:
    """Hands every complete line in `data` to the stream; returns what has no end yet."""
    start = 0
    for match in _SEPARATOR.finditer(data):
        sep = match.group()
        # A carriage return at the very end may be the first half of "\r\n": wait for more.
        if sep == b"\r" and match.end() == len(data) and not final:
            break
        text = data[start : match.start()].decode(errors="replace")
        if sep == b"\r":
            stream.progress(text)
        else:
            stream.line(text)
        start = match.end()
    rest = data[start:]
    if final or len(rest) > _MAX_PENDING:
        stream.line(rest.decode(errors="replace"))
        return b""
    return rest
