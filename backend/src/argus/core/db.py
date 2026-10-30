"""Database engine and session factory."""

import logging
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from argus.core.config import get_settings

log = logging.getLogger("argus.db")

# No server-side prepared statements (psycopg prepares a query after its fifth run). Postgres
# then switches a prepared query to a generic plan, which cannot prune partitions at plan time
# nor pick an index by the connection asked for: the Overview went from 8 ms to 120 ms, with
# a 1.7 s run at the switch (query budget, 2026-10-07). Every query is planned for its values.
CONNECT_ARGS: dict[str, object] = {"connect_timeout": 5, "prepare_threshold": None}
# How long a caller waits for a free connection when the pool is full. Then it fails
# (sqlalchemy.exc.TimeoutError): the API answers 503, a run ends failed and is retried.
POOL_TIMEOUT_SECONDS = 10


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    # A hard cap, no overflow: the pool never opens more than db_pool_max connections, so the
    # chart's sum of every pod's cap is the most Postgres can be asked for (2026-10-28).
    settings = get_settings()
    return create_engine(
        settings.database_url(),
        pool_pre_ping=True,
        pool_size=settings.db_pool_max,
        max_overflow=0,
        pool_timeout=POOL_TIMEOUT_SECONDS,
        connect_args=CONNECT_ARGS,
    )


def require_pool(needed: int, *, process: str) -> None:
    """Refuses to start a process whose pool is below the connections it holds at once at its
    peak: it would wait on itself (a run's heartbeat behind its own ingest) and fail."""
    size = get_settings().db_pool_max
    if size < needed:
        log.error(
            "database pool too small: raise ARGUS_DB_POOL_MAX",
            extra={"component": process, "db_pool_max": size, "needed": needed},
        )
        raise SystemExit(2)


def session_factory() -> sessionmaker[Session]:
    return sessionmaker(get_engine(), expire_on_commit=False)


def like_contains(q: str) -> str:
    """A LIKE pattern matching `q` anywhere, with LIKE's own wildcards taken literally. Use it
    with `ILIKE :p ESCAPE '\\'`."""
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# A text search counts its matches up to this many and reports one more when there are more,
# so a broad search does not read every row twice. The UI says "10,000+ records".
SEARCH_COUNT_CAP = 10_000


def count_sql(select_from: str, *, search: bool) -> str:
    """The count for a list page: exact, or capped at SEARCH_COUNT_CAP + 1 for a text search.
    `select_from` is the list's FROM and WHERE clause, a fixed fragment."""
    if search:
        return f"SELECT count(*) FROM (SELECT 1 {select_from} LIMIT {SEARCH_COUNT_CAP + 1}) s"  # noqa: S608
    return f"SELECT count(*) {select_from}"
