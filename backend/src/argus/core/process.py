"""Keeps a process's secrets from the programs it starts, and starts one with none of them.

The worker starts third-party tools with an environment built from nothing, but they run as its
user, and any process of a user can read /proc/<pid>/environ of that user's other processes. That
file holds the worker's first environment, the database password and the keyring included, and
removing a variable from os.environ does not change it.

A process that is not dumpable has its /proc files owned by root, so its own user can no longer
read them. The flag is not inherited across exec: a tool starts dumpable, which it needs, and holds
none of Argus's secrets.
"""

import ctypes
import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_PR_SET_DUMPABLE = 4


def hide_from_children() -> None:
    """Call first in a process that starts tools. Raises OSError if the kernel refuses: such a
    process must not go on to start one."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")


# What a child started by run_isolated finds in its environment, and nothing else.
_ISOLATED_PATH = "/usr/local/bin:/usr/bin:/bin"
RESULT_NAME = "out"


class IsolatedRunError(Exception):
    """The child failed, ran too long, or wrote more than allowed. The message is ours: never
    the child's output, which may echo the data it was given."""


@dataclass(frozen=True)
class IsolatedResult:
    output: bytes  # what the child wrote to $HOME/out
    status: str  # its last line on stdout, at most 200 characters


def _tail(path: Path, size: int = 4096) -> str:
    with path.open("rb") as f:
        f.seek(max(path.stat().st_size - size, 0))
        return f.read().decode(errors="replace")


def run_isolated(
    argv: list[str], *, stdin: bytes, timeout: float, max_output: int
) -> IsolatedResult:
    """Runs argv with an environment built from nothing (PATH, LANG, and HOME, TMPDIR and
    XDG_CACHE_HOME on a fresh owner-only folder), no inherited descriptors, in its own session.
    `stdin` goes in whole; the child writes its result to $HOME/out, which is read only if it is
    no larger than `max_output`. The folder is removed afterwards, whatever happened."""
    home = Path(tempfile.mkdtemp(prefix="argus-isolated-"))
    env = {
        "PATH": _ISOLATED_PATH,
        "LANG": "C.UTF-8",
        "HOME": str(home),
        "TMPDIR": str(home),
        "XDG_CACHE_HOME": str(home),
    }
    try:
        # Stdout goes to a file, so a child that prints without end costs disk it is limited
        # on, never the caller's memory; only its tail is read.
        with (home / "stdout").open("wb") as stdout:
            process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                argv,
                env=env,
                cwd=home,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
            try:
                process.communicate(stdin, timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise IsolatedRunError(f"stopped after {int(timeout)} s") from None
        status = _tail(home / "stdout").strip().splitlines()[-1:] or [""]
        if process.returncode != 0:
            raise IsolatedRunError(f"exited with {process.returncode}")
        result = home / RESULT_NAME
        if not result.is_file() or result.is_symlink():
            raise IsolatedRunError("wrote no result")
        if result.stat().st_size > max_output:
            raise IsolatedRunError(f"wrote more than {max_output} bytes")
        return IsolatedResult(output=result.read_bytes(), status=status[0][:200])
    finally:
        shutil.rmtree(home, ignore_errors=True)
