"""The Tag filter's options (migration 0051): per connection and tool, the tag names and values
of the resources that have findings of that tool, so a list's picker offers only tags that match
something in it.

Rebuilt by ingest after a findings load and after an inventory load (the tags move with either),
like finding_facet: a request never aggregates tags. A masked value (core.redaction.REDACTED,
whole or in part) is never an option, so a name whose values are all masked is not offered. A
name with more than TAG_VALUES_LISTED values keeps no value rows (`listed` false): its value is
typed and matched exactly, as a Name tag needs."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from argus.core.db import like_contains
from argus.core.redaction import REDACTED
from argus.inventory import RESOURCE_TAGS_SQL

TAG_VALUES_LISTED = 500
TAG_KEYS_LIMIT = 1000
TAG_VALUES_LIMIT = TAG_VALUES_LISTED


@dataclass(frozen=True)
class TagKey:
    key: str
    listed: bool  # every value is listed; false: typed and matched exactly


def lock_facets(conn: Connection, *, connection_id: int) -> None:
    """One rebuild of a connection's filter options at a time, until the transaction ends. Two
    ingests of one account can run together (a Steampipe and a Prowler Job on Kubernetes): each
    deletes then inserts, and the second's insert would hit the first's rows. Taken before the
    metrics lock on every path (ingest.pipeline), so the two never wait on each other in turn."""
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('argus.finding.facets'), CAST(:c AS int))"),
        {"c": connection_id},
    )


def refresh_tag_facets(conn: Connection, *, connection_id: int) -> None:
    """Rebuilds one connection's tag options from its findings' resources' tags."""
    lock_facets(conn, connection_id=connection_id)
    params = {"c": connection_id, "masked": REDACTED, "cap": TAG_VALUES_LISTED}
    conn.execute(text("DELETE FROM finding_tag_key WHERE connection_id = :c"), params)
    conn.execute(
        text(f"""
        WITH pairs AS (
          SELECT DISTINCT f.tool, t.key, t.value
          FROM finding f JOIN ({RESOURCE_TAGS_SQL}) t ON t.resource_id = f.resource_id
          WHERE f.connection_id = :c AND strpos(t.value, :masked) = 0
        ),
        keys AS (
          INSERT INTO finding_tag_key (connection_id, tool, key, listed)
          SELECT :c, tool, key, count(*) <= :cap FROM pairs GROUP BY tool, key
          RETURNING tool, key, listed
        )
        INSERT INTO finding_tag_value (connection_id, tool, key, value)
        SELECT :c, p.tool, p.key, p.value
        FROM pairs p JOIN keys k ON k.tool = p.tool AND k.key = p.key
        WHERE k.listed
    """),  # noqa: S608 - exported SQL constants only
        params,
    )


def _scope(tools: tuple[str, ...], connection_ids: tuple[int, ...]) -> dict[str, Any]:
    return {"t": list(tools), "c": list(connection_ids) or None}


def tag_keys(
    conn: Connection, *, tools: tuple[str, ...], connection_ids: tuple[int, ...] = ()
) -> list[TagKey]:
    """The tag names these tools' findings' resources carry over these connections (all when
    empty), by name. A name is listed only where every connection lists its values."""
    rows = conn.execute(
        text("""
        SELECT key, bool_and(listed) AS listed FROM finding_tag_key
        WHERE tool = ANY(CAST(:t AS text[]))
          AND (CAST(:c AS bigint[]) IS NULL OR connection_id = ANY(CAST(:c AS bigint[])))
        GROUP BY key ORDER BY key LIMIT :l
    """),
        {**_scope(tools, connection_ids), "l": TAG_KEYS_LIMIT},
    )
    return [TagKey(key=r.key, listed=r.listed) for r in rows]


def tag_values(
    conn: Connection,
    *,
    tools: tuple[str, ...],
    key: str,
    connection_ids: tuple[int, ...] = (),
    q: str | None = None,
) -> tuple[list[str], bool]:
    """One name's listed values, in order, at most TAG_VALUES_LIMIT, and whether there are more:
    each connection lists up to TAG_VALUES_LISTED, so several together can pass it. `q` narrows
    them (contains, any case)."""
    rows = conn.execute(
        text(r"""
        SELECT DISTINCT value FROM finding_tag_value
        WHERE key = :k AND tool = ANY(CAST(:t AS text[]))
          AND (CAST(:c AS bigint[]) IS NULL OR connection_id = ANY(CAST(:c AS bigint[])))
          AND (CAST(:p AS text) IS NULL OR value ILIKE :p ESCAPE '\')
        ORDER BY value LIMIT :l
    """),
        {
            **_scope(tools, connection_ids),
            "k": key,
            "p": like_contains(q) if q else None,
            "l": TAG_VALUES_LIMIT + 1,
        },
    )
    values = [r.value for r in rows]
    return values[:TAG_VALUES_LIMIT], len(values) > TAG_VALUES_LIMIT
