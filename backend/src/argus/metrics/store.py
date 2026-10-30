from datetime import date

from sqlalchemy import Connection, text

from argus import connections

ALL_CONNECTIONS = 0
CARRY_FORWARD_DAYS = 31
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


def carried_days(conn: Connection, *, after: date, metrics: list[str]) -> list[date]:
    """The days after the given one, up to CARRY_FORWARD_DAYS, on which all connections has
    any of the metrics: the days whose rollup may have carried that day's values forward."""
    return list(
        conn.execute(
            text(
                "SELECT DISTINCT snapshot_date FROM metric_daily WHERE connection_id = :all "
                "AND snapshot_date > :d AND snapshot_date <= CAST(:d AS date) + :window "
                "AND metric = ANY(CAST(:m AS text[])) ORDER BY 1"
            ),
            {"all": ALL_CONNECTIONS, "d": after, "window": CARRY_FORWARD_DAYS, "m": metrics},
        ).scalars()
    )


def copy_previous(conn: Connection, *, day: date, connection_id: int, metrics: list[str]) -> int:
    """For a partial or failed run: the day keeps what it already has (a complete run earlier
    that day, or an earlier carry-forward), otherwise the most recent earlier values. A run
    that resolves nothing never erases what a good run of the same day loaded."""
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
                  AND snapshot_date < :d AND snapshot_date >= :d - :window)
        """),
        {"d": day, "c": connection_id, "m": metrics, "window": CARRY_FORWARD_DAYS},
    ).rowcount
    return copied


def rollup(conn: Connection, *, day: date, metrics: list[str]) -> None:
    """connection 0 = all connections: for each enabled connection, its latest values on or
    before the day (at most CARRY_FORWARD_DAYS old), summed. An account scanned yesterday
    still counts today, until its next scan (decided 2026-10-08); one not scanned for longer,
    or disabled, drops out. FLOW_METRICS sum that day only. Scores are derived from the sums
    by their owners, never averaged.

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
                AND snapshot_date <= :d AND snapshot_date >= CAST(:d AS date) - :window
              GROUP BY connection_id, metric
            )
            INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
            SELECT :d, 0, md.metric, md.dimension, sum(md.value)
            FROM latest l
            JOIN metric_daily md ON md.connection_id = l.connection_id
                                AND md.metric = l.metric AND md.snapshot_date = l.day
            JOIN ({connections.DIRECTORY_SQL}) c ON c.id = l.connection_id AND c.enabled
            WHERE md.snapshot_date <= :d AND md.snapshot_date >= CAST(:d AS date) - :window
            GROUP BY md.metric, md.dimension
        """),  # noqa: S608 - an exported SQL constant only
        {
            "d": day,
            "m": metrics,
            "flows": sorted(FLOW_METRICS),
            "window": CARRY_FORWARD_DAYS,
        },
    )
