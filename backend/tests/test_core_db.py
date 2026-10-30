"""The connection cap: each process's pool is hard-capped, and a process whose own peak is above
its cap refuses to start instead of waiting on itself."""

from collections.abc import Iterator

import pytest

from argus.core.config import Settings, get_settings
from argus.core.db import get_engine, require_pool
from argus.scheduling.runner import RUN_CONNECTIONS
from argus.scheduling.worker import connections_needed


@pytest.fixture
def fresh(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """get_settings and get_engine read again, and are put back for later tests."""
    monkeypatch.setenv("ARGUS_DB_PASSWORD", "s3cret-value")
    get_settings.cache_clear()
    get_engine.cache_clear()
    yield
    get_settings.cache_clear()
    get_engine.cache_clear()


def test_the_pool_is_a_hard_cap(fresh: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_DB_POOL_MAX", "3")
    pool = get_engine().pool
    assert pool.size() == 3  # type: ignore[attr-defined]
    assert pool._max_overflow == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize("value", ["0", "51"], ids=["zero", "above-bound"])
def test_a_pool_outside_its_bounds_is_refused(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("ARGUS_DB_PASSWORD", "s3cret-value")
    monkeypatch.setenv("ARGUS_DB_POOL_MAX", value)
    with pytest.raises(ValueError, match="db_pool_max"):
        Settings()


def test_a_process_refuses_a_pool_below_its_peak(
    fresh: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_DB_POOL_MAX", str(RUN_CONNECTIONS - 1))
    with pytest.raises(SystemExit) as exited:
        require_pool(RUN_CONNECTIONS, process="scan job")
    assert exited.value.code == 2

    monkeypatch.setenv("ARGUS_DB_POOL_MAX", str(RUN_CONNECTIONS))
    get_settings.cache_clear()
    require_pool(RUN_CONNECTIONS, process="scan job")  # exactly enough starts


def test_the_default_pool_covers_the_default_worker(fresh: None) -> None:
    settings = get_settings()
    # Two run threads at three each, the test thread, the main loop's two.
    assert connections_needed(settings.worker_threads) == 9
    require_pool(connections_needed(settings.worker_threads), process="worker")
