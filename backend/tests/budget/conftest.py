"""The budget's estate: 300,000 resources, generated once for every budget module."""

import pytest
from sqlalchemy import Engine, text
from tests.budget.test_query_budget import _generate, _reports


@pytest.fixture(scope="package")
def estate(migrated: Engine) -> Engine:
    # The generator lives with the query budget, whose header describes the estate's shape.
    with migrated.begin() as conn:
        # Building the estate is bulk loading, not a test: on a slow disk one of its inserts
        # takes longer than the test service's statement timeout, which is there to catch a
        # stuck test. The measured queries keep their own limits.
        conn.execute(text("SET LOCAL statement_timeout = 0"))
        conn.execute(
            text(
                "TRUNCATE connection, scan_run, resource, resource_config, edge, "
                "audit_log, metric_daily, compliance_requirement, schedule, "
                "platform_setting, report_request RESTART IDENTITY CASCADE"
            )
        )
        _generate(conn)
        _reports(conn)
    settle(migrated)
    return migrated


def settle(engine: Engine) -> None:
    """A steady-state database: the first reads of freshly written rows would otherwise pay
    for setting their hint bits and flushing the load, and time that instead of the query."""
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        # The test service's statement timeout catches a stuck test, not this: on a slow disk
        # the vacuum of 300,000 resources' tables takes longer than it allows.
        conn.execute(text("SET statement_timeout = 0"))
        conn.execute(text("VACUUM (ANALYZE)"))
        conn.execute(text("CHECKPOINT"))
