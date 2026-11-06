from datetime import date

from sqlalchemy import Connection, text

from argus import connections

ALL_CONNECTIONS = 0
# What happened on a day, not how things stood: summed over that day only. Every other metric
# describes a state, and all connections take each connection's latest value (rollup).
FLOW_METRICS = frozenset({"findings.events", "misconfigurations.events", "vulnerabilities.events"})


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


def rollup_family(
    conn: Connection, *, day: date, metrics: list[str], marker: tuple[str, str]
) -> None:
    """rollup() for metrics an owner always writes together, with one row (`marker`, a metric
    and dimension) written every time. Each connection's latest day is then one index probe on
    the marker (metric_daily_by_connection), instead of a group-by over every day it has, which
    took about 3 s at 37 accounts counted daily for 180 days (the budget, 2026-11-05). Same
    rules as rollup(): enabled connections, however old; FLOW_METRICS that day only."""
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
    flows = sorted(FLOW_METRICS & set(metrics))
    states = [m for m in metrics if m not in FLOW_METRICS]
    # The planner prices the per-account reads high and JIT-compiles them: 360 ms of compiling
    # for 8 ms of work (the budget, 2026-11-05). Off for this statement, then as it was.
    jit = conn.execute(text("SELECT current_setting('jit')")).scalar_one()
    conn.execute(text("SELECT set_config('jit', 'off', true)"))
    conn.execute(
        text(f"""
            WITH latest AS (
              SELECT c.id AS connection_id,
                     (SELECT max(snapshot_date) FROM metric_daily
                      WHERE connection_id = c.id AND metric = :mm AND dimension = :md
                        AND snapshot_date <= :d) AS day
              FROM ({connections.DIRECTORY_SQL}) c
              WHERE c.enabled AND c.id > 0
            ), days AS (
              SELECT connection_id, day, CAST(:states AS text[]) AS names FROM latest
              WHERE day IS NOT NULL
              UNION ALL
              SELECT connection_id, CAST(:d AS date), CAST(:flows AS text[]) FROM latest
            )
            INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
            SELECT :d, 0, md.metric, md.dimension, sum(md.value)
            FROM days l
            -- Lateral and fenced (OFFSET 0 keeps the planner from flattening it back into a
            -- hash join), so each account's day is read through its own partition's primary
            -- key: the hash join read every partition (4.4 M rows, 1 to 2 s, in the budget).
            CROSS JOIN LATERAL (
              SELECT m.metric, m.dimension, m.value FROM metric_daily m
              WHERE m.snapshot_date = l.day AND m.connection_id = l.connection_id
                AND m.metric = ANY(l.names)
              OFFSET 0
            ) md
            GROUP BY md.metric, md.dimension
        """),  # noqa: S608 - an exported SQL constant only
        {
            "d": day,
            "mm": marker[0],
            "md": marker[1],
            "states": states,
            "flows": flows,
        },
    )
    conn.execute(text("SELECT set_config('jit', :v, true)"), {"v": jit})
