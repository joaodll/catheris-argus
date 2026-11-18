"""The container's memory from cgroup v2, and the guard that stops a tool near the limit
(core/memory.py)."""

from pathlib import Path

import pytest

from argus.core import memory
from argus.core.memory import MemoryGuard, OutOfMemory

MIB = 1 << 20


def _cgroup(
    root: Path, *, anon: int, shmem: int = 0, file: int = 0, limit: str = "1073741824"
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "memory.max").write_text(f"{limit}\n")
    (root / "memory.stat").write_text(
        f"anon {anon * MIB}\nfile {file * MIB}\nkernel 1048576\nshmem {shmem * MIB}\n"
        "pgfault 12345\n"
    )
    return root


def test_use_is_anon_and_tmpfs_never_page_cache(tmp_path: Path) -> None:
    reading = memory.read(_cgroup(tmp_path, anon=300, shmem=50, file=4000))
    assert reading == memory.Reading(used=350 * MIB, shmem=50 * MIB, limit=1024 * MIB)


@pytest.mark.parametrize(
    "setup",
    [lambda root: None, lambda root: _cgroup(root, anon=1, limit="max")],
    ids=["no-cgroup-v2", "no-limit"],
)
def test_nothing_to_read_means_no_guard(tmp_path: Path, setup: object) -> None:
    setup(tmp_path / "cg")  # type: ignore[operator]
    assert memory.read(tmp_path / "cg") is None
    assert MemoryGuard.for_this_container(tmp_path / "cg") is None


def test_the_guard_keeps_the_peak_and_trips_near_the_limit(tmp_path: Path) -> None:
    root = _cgroup(tmp_path, anon=200, shmem=10)
    guard = MemoryGuard(root)
    assert guard.check() is None and guard.over is None
    _cgroup(root, anon=700, shmem=20)
    assert guard.check() is None  # 720 MiB: below 1024 - 256
    _cgroup(root, anon=300)
    guard.check()
    assert guard.peak_line() == "argus: peak memory 0.7 GiB of 1.0 GiB (tmp 0.0 GiB)"
    _cgroup(root, anon=770)
    over = guard.check()
    assert over is not None and over.used == 770 * MIB
    _cgroup(root, anon=10)
    assert guard.check() is over  # once over, it stays over: every process of the run stops
    with pytest.raises(OutOfMemory, match=r"stopped at 0\.8 GiB of a 1\.0 GiB limit"):
        guard.stop_if_over()


def test_a_large_limit_keeps_a_share_as_its_margin(tmp_path: Path) -> None:
    root = _cgroup(tmp_path, anon=11_000, limit=str(12 * 1024 * MIB))
    guard = MemoryGuard(root)
    assert guard.check() is None  # 8 % of 12 GiB is 983 MiB: the line is at 11,305 MiB
    _cgroup(root, anon=11_400, limit=str(12 * 1024 * MIB))
    assert guard.check() is not None


def test_the_heartbeat_status(tmp_path: Path) -> None:
    guard = MemoryGuard(_cgroup(tmp_path, anon=3200, limit=str(6 * 1024 * MIB)))
    assert guard.status() == "memory 3.1 of 6.0 GiB"
