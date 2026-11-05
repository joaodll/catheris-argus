"""Keeps a process's secrets from the programs it starts.

The worker starts third-party tools with an environment built from nothing, but they run as its
user, and any process of a user can read /proc/<pid>/environ of that user's other processes. That
file holds the worker's first environment, the database password and the keyring included, and
removing a variable from os.environ does not change it.

A process that is not dumpable has its /proc files owned by root, so its own user can no longer
read them. The flag is not inherited across exec: a tool starts dumpable, which it needs, and holds
none of Argus's secrets.
"""

import ctypes

_PR_SET_DUMPABLE = 4


def hide_from_children() -> None:
    """Call first in a process that starts tools. Raises OSError if the kernel refuses: such a
    process must not go on to start one."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")
