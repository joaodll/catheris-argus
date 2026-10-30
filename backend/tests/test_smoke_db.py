import pytest
from sqlalchemy import text

from argus.core.db import get_engine

pytestmark = pytest.mark.db


def test_postgres_is_reachable_and_major_version_17() -> None:
    with get_engine().connect() as conn:
        version_num = conn.execute(text("SHOW server_version_num")).scalar_one()

    assert int(version_num) // 10000 == 17
