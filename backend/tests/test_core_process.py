"""A tool runs as the worker's user. It must not be able to read the worker's environment, which
holds the database password and the keyring. Each case runs in its own Python process, because the
flag can't be cleared once set."""

import os
import subprocess
import sys
from collections.abc import Callable
from importlib import import_module
from pathlib import Path

import pytest

from argus.core.process import IsolatedRunError, run_isolated

MARKER = "ARGUS_TEST_WORKER_ONLY"
PARENT = """
import subprocess, sys
{hide}
tool = "tr '\\\\0' '\\\\n' < /proc/$PPID/environ"
done = subprocess.run(["/bin/sh", "-c", tool], env={{"PATH": "/usr/bin:/bin"}},
                      capture_output=True, text=True)
sys.stdout.write(done.stdout)
sys.stderr.write(done.stderr)
sys.exit(done.returncode)
"""


def _worker(hide: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter and a fixed script
        [sys.executable, "-c", PARENT.format(hide=hide)],
        env={**os.environ, MARKER: "yes"},
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_tool_can_read_the_environment_of_a_process_that_does_not_hide() -> None:
    """Without this, the next test could pass for the wrong reason."""
    assert MARKER in _worker("").stdout


def test_a_tool_cannot_read_the_environment_of_a_process_that_hides() -> None:
    done = _worker("from argus.core.process import hide_from_children; hide_from_children()")
    assert MARKER not in done.stdout
    assert "Permission denied" in done.stderr


def test_a_tool_of_a_process_that_hides_still_reads_its_own() -> None:
    """The flag ends at exec, so the tools' own /proc lookups keep working."""
    parent = (
        "import subprocess, sys\n"
        "from argus.core.process import hide_from_children\n"
        "hide_from_children()\n"
        "sys.exit(subprocess.run(['/bin/cat', '/proc/self/environ'], env={'A': 'b'}).returncode)\n"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed script
        [sys.executable, "-c", parent], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0 and "A=b" in done.stdout


class _Hid(Exception):
    pass


@pytest.mark.parametrize("name", ["argus.entrypoints.worker", "argus.entrypoints.job"])
def test_a_process_that_starts_tools_hides_before_anything_else(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    entrypoint = import_module(name)

    def hid() -> None:
        raise _Hid

    def too_soon() -> None:
        pytest.fail("settings were read before the process hid its environment")

    monkeypatch.setattr(entrypoint, "hide_from_children", hid)
    monkeypatch.setattr(entrypoint, "get_settings", too_soon)
    main: Callable[[], int] = entrypoint.main
    with pytest.raises(_Hid):
        main()


# ---- run_isolated: a child with none of the parent's secrets (ADR-0047) ---------------------


def test_an_isolated_child_sees_no_argus_variable_and_writes_its_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_DB_PASSWORD", "parent-only-value")
    script = (
        "import os, sys; d = sys.stdin.read();"
        "names = sorted(k for k in os.environ);"
        "open(os.path.join(os.environ['HOME'], 'out'), 'w').write(d + '|' + ','.join(names));"
        "print('done')"
    )
    result = run_isolated(
        [sys.executable, "-I", "-c", script], stdin=b"ctx", timeout=30, max_output=4096
    )
    text, names = result.output.decode().split("|")
    assert text == "ctx" and result.status == "done"
    assert set(names.split(",")) == {"PATH", "LANG", "HOME", "TMPDIR", "XDG_CACHE_HOME"}
    assert "parent-only-value" not in result.output.decode()


def test_an_isolated_child_is_stopped_and_its_folder_removed(tmp_path: Path) -> None:
    marker = tmp_path / "home"
    script = (
        f"import os, time; open({str(marker)!r}, 'w').write(os.environ['HOME']); time.sleep(30)"
    )
    with pytest.raises(IsolatedRunError, match="stopped after 1 s"):
        run_isolated([sys.executable, "-I", "-c", script], stdin=b"", timeout=1, max_output=10)
    assert not Path(marker.read_text()).exists()


@pytest.mark.parametrize(
    ("script", "message"),
    [
        ("import sys; sys.exit(3)", "exited with 3"),
        ("print('no file')", "wrote no result"),
        (
            "import os; open(os.environ['HOME'] + '/out', 'w').write('x' * 100)",
            "more than 10 bytes",
        ),
    ],
    ids=["exit", "no-result", "too-large"],
)
def test_an_isolated_child_that_fails_is_refused(script: str, message: str) -> None:
    with pytest.raises(IsolatedRunError, match=message):
        run_isolated([sys.executable, "-I", "-c", script], stdin=b"", timeout=30, max_output=10)


def test_an_isolated_child_that_prints_without_end_costs_no_memory() -> None:
    script = (
        "import os, sys; sys.stdout.write('x' * 5_000_000 + '\\nlast line\\n');"
        "open(os.environ['HOME'] + '/out', 'w').write('ok')"
    )
    result = run_isolated(
        [sys.executable, "-I", "-c", script], stdin=b"", timeout=30, max_output=10
    )
    assert result.status == "last line" and result.output == b"ok"
