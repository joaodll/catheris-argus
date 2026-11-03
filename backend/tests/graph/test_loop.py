"""The graph loop's order (ADR-0044, M2): attack paths are evaluated once at start, after a
reconcile or an integrity check that changed Memgraph, and after a failed evaluation; the
integrity check runs before every evaluation, so paths come only from a verified graph."""

import threading
from typing import Any

import pytest

from argus.graph import loop


def _run(monkeypatch: pytest.MonkeyPatch, ticks: list[dict[str, Any]]) -> list[str]:
    """Runs one loop pass per tick: what reconcile returns, whether evaluate fails. Returns the
    calls in order."""
    calls: list[str] = []
    stop = threading.Event()
    tick = iter(ticks)
    now = {"t": 0.0, "tick": ticks[0]}

    def reconcile(_engine: object) -> dict[str, int]:
        calls.append("reconcile")
        return dict(now["tick"].get("reconcile", {"synced": 0, "failed": 0, "removed": 0}))

    def verify(_engine: object) -> dict[str, int]:
        calls.append("verify")
        return {"checked": 1, "drifted": now["tick"].get("drifted", 0)}

    def evaluate(_engine: object) -> dict[str, int]:
        calls.append("evaluate")
        if now["tick"].get("evaluate_fails"):
            raise RuntimeError("Memgraph went away")
        return {"paths": 1}

    def alive() -> None:
        calls.append("|")
        now["t"] += 1.0
        try:
            now["tick"] = next(tick)
        except StopIteration:
            stop.set()

    next(tick)  # the first tick is already current
    monkeypatch.setattr(loop, "reconcile", reconcile)
    monkeypatch.setattr(loop, "verify", verify)
    monkeypatch.setattr(loop, "evaluate_paths", evaluate)
    monkeypatch.setattr(loop.client, "close", lambda: None)
    monkeypatch.setattr(loop.time, "monotonic", lambda: now["t"])
    monkeypatch.setattr(loop, "RECONCILE_EVERY_SECONDS", 0)
    monkeypatch.setattr(loop, "VERIFY_EVERY_SECONDS", 100)
    loop.run(object(), stop, alive=alive)  # type: ignore[arg-type]
    return calls


def test_paths_follow_a_change_and_only_a_verified_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _run(
        monkeypatch,
        [
            {},  # start: verify, then the paths
            {},  # nothing changed, check not due: reconcile only
            {"reconcile": {"synced": 1}},  # a scan landed
            {"reconcile": {"removed": 1}},  # a connection left
            {"reconcile": {"failed": 1}},  # a failed sync changed nothing in Memgraph
        ],
    )
    assert "".join(c[0] if c != "|" else "|" for c in calls) == "rve|r|rve|rve|r|"


def test_a_failed_evaluation_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _run(monkeypatch, [{"evaluate_fails": True}, {}, {}])
    assert "".join(c[0] if c != "|" else "|" for c in calls) == "rve|rve|r|"


def test_drift_found_by_the_periodic_check_re_evaluates(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks: list[dict[str, Any]] = [{}] + [{}] * 99 + [{"drifted": 1}, {}]
    calls = _run(monkeypatch, ticks)
    passes = "".join(c[0] if c != "|" else "|" for c in calls).split("|")
    assert passes[0] == "rve"
    assert set(passes[1:100]) == {"r"}  # the check is not due yet
    assert passes[100] == "rve"  # due: it found drift, so the paths follow
    assert passes[101] == "r"
