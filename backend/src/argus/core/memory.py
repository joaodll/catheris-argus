"""This container's memory, from cgroup v2, and a guard that stops a tool before the kernel
kills the pod (owner, 2026-11-18).

The kernel's OOM killer takes the whole container: the run's claim is then lost, run again, and
lost again, and nothing says how much memory the tool wanted. A scan Job runs one run per pod,
so its cgroup's use is that run's: the guard reads it while the tool runs and, near the limit,
the tool is stopped and the run fails with the numbers.

Use counts anonymous memory and shmem (the /tmp tmpfs, which holds each tool's home), never the
page cache: the kernel reclaims cache before it kills anything, and writing raw output fills
it. Without cgroup v2 or without a limit there is nothing to read, and no guard.
"""

import threading
from dataclasses import dataclass
from pathlib import Path

CGROUP = Path("/sys/fs/cgroup")
GIB = 1 << 30
MIB = 1 << 20
# The tool is stopped when its use comes this close to the limit: the larger of a fixed margin
# and a share of the limit, so a fast-growing tool is caught between two looks a second apart.
MARGIN_MIN = 256 * MIB
MARGIN_SHARE = 0.08


@dataclass(frozen=True)
class Reading:
    used: int  # anon + shmem, in bytes
    shmem: int  # of which tmpfs
    limit: int


def read(root: Path = CGROUP) -> Reading | None:
    """The container's memory now, or None without cgroup v2 or without a limit."""
    try:
        limit = (root / "memory.max").read_text().strip()
        stat = (root / "memory.stat").read_text()
    except OSError:
        return None
    if not limit.isdigit():  # "max": no limit
        return None
    values: dict[str, int] = {}
    for line in stat.splitlines():
        key, _, value = line.partition(" ")
        if value.strip().isdigit():
            values[key] = int(value)
    shmem = values.get("shmem", 0)
    return Reading(used=values.get("anon", 0) + shmem, shmem=shmem, limit=int(limit))


def gib(size: int) -> str:
    return f"{size / GIB:.1f} GiB"


class OutOfMemory(Exception):
    """A tool was stopped near the container's memory limit."""

    def __init__(self, reading: Reading) -> None:
        super().__init__(f"stopped at {gib(reading.used)} of a {gib(reading.limit)} limit")
        self.reading = reading


class MemoryGuard:
    """One run's look at its container's memory: the peak so far, and whether the tool must
    stop. Once over the line it stays over, so every process of the run stops."""

    def __init__(self, root: Path = CGROUP) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._peak: Reading | None = None
        self._over: Reading | None = None

    @classmethod
    def for_this_container(cls, root: Path = CGROUP) -> "MemoryGuard | None":
        return cls(root) if read(root) is not None else None

    def check(self) -> Reading | None:
        """Reads once and keeps the peak. Returns the reading that crossed the line (now or
        earlier), or None."""
        if self._over is not None:
            return self._over
        now = read(self.root)
        if now is None:
            return None
        with self._lock:
            if self._peak is None or now.used > self._peak.used:
                self._peak = now
            if now.used >= now.limit - max(MARGIN_MIN, int(now.limit * MARGIN_SHARE)):
                self._over = now
        return self._over

    def stop_if_over(self) -> None:
        if (over := self.check()) is not None:
            raise OutOfMemory(over)

    @property
    def over(self) -> Reading | None:
        return self._over

    def status(self) -> str | None:
        """For the live log's heartbeat: "memory 3.1 of 6.0 GiB"."""
        self.check()
        now = read(self.root)
        return f"memory {now.used / GIB:.1f} of {gib(now.limit)}" if now else None

    def peak_line(self) -> str | None:
        """For the run's log: the most the run used, and how much of it was /tmp."""
        peak = self._peak
        if peak is None:
            return None
        return f"argus: peak memory {gib(peak.used)} of {gib(peak.limit)} (tmp {gib(peak.shmem)})"
