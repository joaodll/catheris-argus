"""graph-sync's init container: Memgraph not up yet is waited out, a wrong login is not."""

from collections.abc import Iterator

import pytest
from neo4j.exceptions import ClientError

from argus.core.config import get_settings
from argus.graph import client, wait_until_ready


@pytest.fixture
def fresh_driver(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    """A driver built from the settings each test sets, and the suite's own one afterwards."""
    client.close()
    get_settings.cache_clear()
    yield monkeypatch
    client.close()
    monkeypatch.undo()
    get_settings.cache_clear()


def test_ready_when_memgraph_answers() -> None:
    assert wait_until_ready(5.0) is True


def test_gives_up_when_memgraph_stays_away(fresh_driver: pytest.MonkeyPatch) -> None:
    fresh_driver.setenv("ARGUS_GRAPH_URI", "bolt://127.0.0.1:1")
    assert wait_until_ready(0.0) is False


def test_a_wrong_login_raises_instead_of_waiting(fresh_driver: pytest.MonkeyPatch) -> None:
    fresh_driver.setenv("ARGUS_GRAPH_PASSWORD", "not-this-login")
    # Memgraph answers it as a ClientError, not the driver's AuthError.
    with pytest.raises(ClientError, match="Authentication failure"):
        wait_until_ready(60.0)
