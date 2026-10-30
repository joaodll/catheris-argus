"""Edges are keyed per connection (ADR-0034).

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-09

`edge.edge_key` hashed origin, endpoints, type and attributes, but not the connection. When two
connections derived the same key, the second one's snapshot rows pointed at the first one's
edge, which the second never reads (reads filter `edge.connection_id`). The key now holds the
connection, as `relationships.engine.edge_key()` computes it. Rule and CloudFox edges are
re-keyed in place, so their first-seen dates and snapshots are kept. Manual edges have no
connection and keep their key.

An edge whose recomputed key differs from what ingest computes (a JSON value that does not
round-trip the same) is not an error: the next run inserts a new row, and the old one keeps
its past snapshots. `tests/db/test_edge_rekey.py` proves the two computations agree.

No schema change. The rows are updated in batches of 5,000.
"""

import hashlib
import json
from collections.abc import Callable
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_BATCH = 5000


def per_connection_key(
    connection_id: int,
    origin: str,
    source_uid: str,
    target_uid: str,
    type_: str,
    attributes: dict[str, Any],
) -> bytes:
    """A copy of `relationships.engine.edge_key()` at this revision: a migration never imports
    application code, which keeps changing after it."""
    canonical = json.dumps(
        [connection_id, origin, source_uid, target_uid, type_, attributes],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).digest()


def _shared_key(
    _connection_id: int,
    origin: str,
    source_uid: str,
    target_uid: str,
    type_: str,
    attributes: dict[str, Any],
) -> bytes:
    canonical = json.dumps(
        [origin, source_uid, target_uid, type_, attributes],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).digest()


def _rekey(key: Callable[..., bytes]) -> None:
    bind = op.get_bind()
    last_id = 0
    while True:
        rows = bind.execute(
            sa.text("""
                SELECT id, connection_id, origin, source_uid, target_uid, type, attributes
                FROM edge
                WHERE origin <> 'manual' AND connection_id IS NOT NULL AND id > :last
                ORDER BY id LIMIT :n
            """),
            {"last": last_id, "n": _BATCH},
        ).all()
        if not rows:
            return
        bind.execute(
            sa.text("""
                UPDATE edge SET edge_key = b.k
                FROM unnest(CAST(:ids AS bigint[]), CAST(:keys AS bytea[])) AS b(id, k)
                WHERE edge.id = b.id
            """),
            {
                "ids": [r.id for r in rows],
                "keys": [
                    key(
                        r.connection_id,
                        r.origin,
                        r.source_uid,
                        r.target_uid,
                        r.type,
                        r.attributes or {},
                    )
                    for r in rows
                ],
            },
        )
        last_id = rows[-1].id


def upgrade() -> None:
    _rekey(per_connection_key)


def downgrade() -> None:
    # Fails on the unique key when two connections now hold the same edge, which the old key
    # cannot tell apart: delete one of them by hand first, or stay at this revision.
    _rekey(_shared_key)
