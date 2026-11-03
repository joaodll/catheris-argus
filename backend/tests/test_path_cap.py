"""Which paths keep a row when an account has more than the cap (ADR-0044, amended 2026-11-02):
the worst first by assessed severity, then confidence, then fewer steps, and every path that
already has a row. Pure."""

from typing import Any

import pytest

from argus.attackpaths import Chain, FoundPath, PathKind, Step, cap
from argus.attackpaths.confidence import Confidence


def _path(
    name: str,
    *,
    severity: str = "high",
    confidence: Confidence = "supported",
    steps: int = 1,
    connection_id: int = 1,
) -> FoundPath:
    kind = PathKind(
        id=f"kind-{name}",
        version=1,
        name=name,
        category="c",
        severity="high",
        technique="t",
        description="d",
        remediation="r",
        sql="SELECT 1",
    )
    chain = Chain(
        "entry",
        "target",
        tuple(
            Step(i, "a", f"{name}-{i}", "ROUTES_TO", "rule:x@1", confidence) for i in range(steps)
        ),
    )
    return FoundPath(kind, chain, severity, True, False, connection_id, (connection_id,))


@pytest.fixture
def two(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr("argus.attackpaths.engine.MAX_PATHS", 2)


def _names(paths: list[FoundPath]) -> list[str]:
    return [p.kind.name for p in paths]


def test_the_worst_are_kept_by_assessed_severity_then_confidence_then_steps(two: None) -> None:
    low = _path("low", severity="low", confidence="confirmed")
    critical = _path("critical", severity="critical", confidence="candidate", steps=5)
    sure = _path("sure", severity="high", confidence="confirmed", steps=4)
    short = _path("short", severity="high", confidence="supported", steps=1)
    long = _path("long", severity="high", confidence="supported", steps=3)
    kept, cut = cap([low, long, short, sure, critical], stored=set())
    assert _names(kept) == ["critical", "sure"]
    assert cut == {1: {"high": 2, "low": 1}}

    kept, _ = cap([long, short, low], stored=set())
    assert _names(kept) == ["short", "long"]


def test_the_cap_is_per_connection(two: None) -> None:
    paths = [_path(f"{c}-{i}", connection_id=c) for c in (1, 2) for i in range(3)]
    kept, cut = cap(paths, stored=set())
    assert len(kept) == 4
    assert {c: n.total() for c, n in cut.items()} == {1: 1, 2: 1}


def test_a_path_with_a_row_stays_however_it_ranks(two: None) -> None:
    """A new path that matters still gets a row, and the one it displaces keeps its own."""
    old = _path("old", severity="low")
    new = [_path("a", severity="critical"), _path("b", severity="critical")]
    kept, cut = cap([old, *new], stored={old.path_id})
    assert sorted(_names(kept)) == ["a", "b", "old"]
    assert cut == {}


def test_a_latent_path_is_counted_apart(two: None) -> None:
    blocked = _path("blocked", severity="low", confidence="blocked")
    paths = [_path("a"), _path("b"), blocked]
    _, cut = cap(paths, stored=set())
    assert cut == {1: {"latent": 1}}


def test_the_order_does_not_depend_on_the_input(two: None) -> None:
    paths = [_path(f"p{i}") for i in range(6)]
    kept, _ = cap(paths, stored=set())
    again, _ = cap(list(reversed(paths)), stored=set())
    assert _names(kept) == _names(again)
