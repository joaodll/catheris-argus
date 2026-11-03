from datetime import date, timedelta

from sqlalchemy import Connection, text

from argus import connections
from argus.metrics.series import HISTORY_DAYS

ALL_CONNECTIONS = 0
# What happened on a day, not how things stood: summed over that day only. Every other metric
# describes a state, and all connections take each connection's latest value (rollup).
FLOW_METRICS = frozenset({"findings.events"})


def put(
    conn: Connection,
    *,
    day: date,
    connection_id: int,
    values: dict[tuple[str, str], float],
    replace: list[str] | None = None,
) -> None:
    """Replaces, for one day and connection, every metric named in values (and in replace,
    so a metric whose every dimension dropped to nothing is cleared, not left stale)."""
    names = sorted({metric for metric, _ in values} | set(replace or ()))
    conn.execute(
        text(
            "DELETE FROM metric_daily WHERE snapshot_date = :d AND connection_id = :c "
            "AND metric = ANY(CAST(:m AS text[]))"
        ),
        {"d": day, "c": connection_id, "m": names},
    )
    if values:
        conn.execute(
            text(
                "INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, "
                "value) VALUES (:d, :c, :m, :dim, :v)"
            ),
            [
                {"d": day, "c": connection_id, "m": m, "dim": dim, "v": v}
                for (m, dim), v in values.items()
            ],
        )


def read(
    conn: Connection, *, day: date, connection_id: int, metrics: list[str]
) -> list[tuple[str, str, float]]:
    """(metric, dimension, value) for one day and connection."""
    rows = conn.execute(
        text(
            "SELECT metric, dimension, value FROM metric_daily WHERE snapshot_date = :d "
            "AND connection_id = :c AND metric = ANY(CAST(:m AS text[]))"
        ),
        {"d": day, "c": connection_id, "m": metrics},
    ).all()
    return [(m, d, float(v)) for m, d, v in rows]


def latest(conn: Connection, *, connection_id: int, metric: str, as_of: date) -> dict[str, float]:
    """{dimension: value} of one metric on its latest day on or before `as_of`, within the
    history kept. Empty when it has none."""
    rows = conn.execute(
        text(
            """
            SELECT dimension, value FROM metric_daily
            WHERE connection_id = :c AND metric = :m AND snapshot_date = (
              SELECT max(snapshot_date) FROM metric_daily
              WHERE connection_id = :c AND metric = :m AND snapshot_date BETWEEN :s AND :e)
            """
        ),
        {"c": connection_id, "m": metric, "s": as_of - timedelta(days=HISTORY_DAYS), "e": as_of},
    ).all()
    return {d: float(v) for d, v in rows}


def carried_days(
    conn: Connection, *, after: date, metrics: list[str], connection_id: int
) -> list[date]:
    """The days after `after` on which all connections has any of the metrics and the rollup
    carried this connection's values of `after`: until its next day with those metrics, however
    far (each account's latest scan counts, however old: owner's decision, 2026-11-01)."""
    return list(
        conn.execute(
            text("""
                SELECT DISTINCT snapshot_date FROM metric_daily
                WHERE connection_id = :all AND snapshot_date > :d
                  AND metric = ANY(CAST(:m AS text[]))
                  AND snapshot_date < coalesce(
                    (SELECT min(snapshot_date) FROM metric_daily
                     WHERE connection_id = :c AND snapshot_date > :d
                       AND metric = ANY(CAST(:m AS text[]))),
                    CAST('infinity' AS date))
                ORDER BY 1
            """),
            {"all": ALL_CONNECTIONS, "d": after, "c": connection_id, "m": metrics},
        ).scalars()
    )


def copy_previous(conn: Connection, *, day: date, connection_id: int, metrics: list[str]) -> int:
    """For a partial or failed run: the day keeps what it already has (a complete run earlier
    that day, or an earlier carry-forward), otherwise the most recent earlier values, however
    old. A run that resolves nothing never erases what a good run of the same day loaded."""
    has_day = conn.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM metric_daily WHERE snapshot_date = :d "
            "AND connection_id = :c AND metric = ANY(CAST(:m AS text[])))"
        ),
        {"d": day, "c": connection_id, "m": metrics},
    ).scalar_one()
    if has_day:
        return 0
    copied: int = conn.execute(
        text("""
            INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
            SELECT :d, connection_id, metric, dimension, value FROM metric_daily
            WHERE connection_id = :c AND metric = ANY(CAST(:m AS text[]))
              AND snapshot_date = (
                SELECT max(snapshot_date) FROM metric_daily
                WHERE connection_id = :c AND metric = ANY(CAST(:m AS text[]))
                  AND snapshot_date < :d)
        """),
        {"d": day, "c": connection_id, "m": metrics},
    ).rowcount
    return copied


def rollup(conn: Connection, *, day: date, metrics: list[str]) -> None:
    """connection 0 = all connections: for each enabled connection, its latest values on or
    before the day, however old, summed. An account scanned 60 days ago still counts today,
    until its next scan (decided 2026-10-08; the 31-day limit lifted 2026-11-01: scans may run
    15 to 60 days apart); a disabled one drops out, and retention is the only age limit.
    FLOW_METRICS sum that day only. Scores are derived from the sums by their owners, never
    averaged.

    Two workers finishing different connections for the same day would otherwise both delete
    (seeing nothing yet) and both insert. A transaction-scoped advisory lock per day serialises
    them; the second reads the first's committed rows once it holds the lock."""
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('argus.metrics.rollup'), :d)"),
        {"d": (day - date(2000, 1, 1)).days},
    )
    conn.execute(
        text(
            "DELETE FROM metric_daily WHERE snapshot_date = :d AND connection_id = 0 "
            "AND metric = ANY(CAST(:m AS text[]))"
        ),
        {"d": day, "m": metrics},
    )
    conn.execute(
        text(f"""
            WITH latest AS (
              SELECT connection_id, metric,
                     CASE WHEN metric = ANY(CAST(:flows AS text[])) THEN CAST(:d AS date)
                          ELSE max(snapshot_date) END AS day
              FROM metric_daily
              WHERE connection_id > 0 AND metric = ANY(CAST(:m AS text[]))
                AND snapshot_date <= :d
              GROUP BY connection_id, metric
            )
            INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
            SELECT :d, 0, md.metric, md.dimension, sum(md.value)
            FROM latest l
            JOIN metric_daily md ON md.connection_id = l.connection_id
                                AND md.metric = l.metric AND md.snapshot_date = l.day
            JOIN ({connections.DIRECTORY_SQL}) c ON c.id = l.connection_id AND c.enabled
            GROUP BY md.metric, md.dimension
        """),  # noqa: S608 - an exported SQL constant only
        {
            "d": day,
            "m": metrics,
            "flows": sorted(FLOW_METRICS),
        },
    )
