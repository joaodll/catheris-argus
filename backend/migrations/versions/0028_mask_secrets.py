"""Secrets and ExternalIds read ******** (ADR-0024, amended 2026-10-23).

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-23

The owner's choice: a secret is shown as ********, a fixed length, so neither a character nor
the length of the value survives; ExternalIds are hidden the same way. From this release
`core.redaction` writes ******** where it wrote the word REDACTED, and treats an ExternalId key
(`sts:ExternalId` in a trust policy, CloudFox's `ExternalID`, `external_id`) as secret-bearing.
A scanned role's trust policy held Argus's own ExternalId, which ADR-0024 keeps from the API.

This migration rewrites what is already stored, the same way:
- the old marker, as a word, becomes ******** in the JSON of `resource_config`, `resource.tags`
  and `edge.attributes`, and in the redacted text of `finding.detail`, `scan_run.log_tail` and
  `command`, `run_request.error`, `connection_test.message` and `finding_command.command` and
  `note` (both are eight characters: no length check can fail);
- every string or number under an ExternalId key in that JSON becomes ********; booleans stay
  (CloudFox's `external_id` on an edge says whether one is required, and holds no value);
- in that text, a value written after an ExternalId key (`ExternalId: x`, `external_id=x`) or
  the CLI's `--external-id x` becomes ********.

An edge's key is a hash of its attributes (`relationships.engine.edge_key`), so an edge whose
attributes change gets its key again, or the next load would take it for a new edge. Two edges
that differed only by a masked value would now share a key: the second keeps its old key, is not
seen by the next load, and ages out as any edge that disappears does. Manual edges are left as
they are: a person wrote them, and their key is their own.

A configuration keeps its `config_hash`, the hash of what was stored before: the next scan of a
resource stores its configuration once more under the new hash, and nothing compares the two.

`audit_log` is left as it was: it is append-only, and it never held a secret.

Irreversible: a masked ExternalId cannot be restored, and the downgrade does nothing.
"""

import hashlib
import json
import re
from itertools import pairwise
from typing import Any

from alembic import op
from sqlalchemy import Connection, text

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None

MASK = "********"
_BATCH = 5000
# A copy of core.redaction's word split: a migration never imports application code, which
# keeps changing after it.
_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
# The old marker as a word ("https://REDACTED@", "sig=REDACTED"), not inside another word:
# PostgreSQL's spelling, then Python's.
_OLD_SQL = r"\mREDACTED\M"
_OLD_RE = re.compile(r"\bREDACTED\b")
# A value after an ExternalId key in text: "ExternalId": "x", external_id=x, or the CLI's
# --external-id x. A space alone follows only the flag: prose ("an ExternalId condition") stays.
_TEXT_EXTERNAL_ID = r"""(external[_-]?id["']?\s*[:=]\s*["']?|--external-id\s+)[^\s"',;&]+"""
_CANDIDATE = "CAST({0} AS text) ~ :old OR CAST({0} AS text) ~* 'external.?id'"
_TEXT = (
    ("finding", "detail"),
    ("scan_run", "log_tail"),
    ("scan_run", "command"),
    ("run_request", "error"),
    ("connection_test", "message"),
    ("finding_command", "command"),
    ("finding_command", "note"),
)


def is_external_id_key(key: str) -> bool:
    words = [w.lower() for w in _WORD_RE.findall(key)]
    return ("external", "id") in pairwise(words)


def _masked(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _masked(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_masked(v) for v in value]
    if value is None or isinstance(value, bool):
        return value
    return MASK


def mask_document(document: Any) -> Any:
    """The old marker becomes the mask in every string, and every string or number under an
    ExternalId key is masked, at any depth, keeping the shape."""
    if isinstance(document, dict):
        return {
            k: _masked(v) if is_external_id_key(k) else mask_document(v)
            for k, v in document.items()
        }
    if isinstance(document, list):
        return [mask_document(v) for v in document]
    if isinstance(document, str):
        return _OLD_RE.sub(MASK, document)
    return document


def edge_key(
    connection_id: int,
    origin: str,
    source_uid: str,
    target_uid: str,
    type_: str,
    attributes: dict[str, Any],
) -> bytes:
    """A copy of `relationships.engine.edge_key()` at this revision."""
    canonical = json.dumps(
        [connection_id, origin, source_uid, target_uid, type_, attributes],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).digest()


def _documents(conn: Connection, table: str, column: str) -> None:
    """A JSON column whose key is not derived from it: rewritten in place, the marker in one
    statement, ExternalIds row by row (few rows hold one)."""
    conn.execute(
        text(f"""
        UPDATE {table}
        SET {column} = CAST(regexp_replace(CAST({column} AS text), :old, :mask, 'g') AS jsonb)
        WHERE CAST({column} AS text) ~ :old
    """),  # noqa: S608 - fixed names
        {"old": _OLD_SQL, "mask": MASK},
    )
    last = 0
    while True:
        rows = conn.execute(
            text(f"""
            SELECT id, {column} AS doc FROM {table}
            WHERE id > :last AND CAST({column} AS text) ~* 'external.?id'
            ORDER BY id LIMIT :n
        """),  # noqa: S608 - fixed names
            {"last": last, "n": _BATCH},
        ).all()
        if not rows:
            return
        for row in rows:
            masked = mask_document(row.doc)
            if masked != row.doc:
                conn.execute(
                    text(f"UPDATE {table} SET {column} = CAST(:doc AS jsonb) WHERE id = :id"),  # noqa: S608
                    {"doc": json.dumps(masked), "id": row.id},
                )
        last = rows[-1].id


def _edges(conn: Connection) -> None:
    last = 0
    while True:
        rows = conn.execute(
            text(f"""
            SELECT id, connection_id, origin, source_uid, target_uid, type, attributes
            FROM edge
            WHERE id > :last AND origin <> 'manual' AND connection_id IS NOT NULL
              AND ({_CANDIDATE.format("attributes")})
            ORDER BY id LIMIT :n
        """),  # noqa: S608 - fixed fragments
            {"last": last, "old": _OLD_SQL, "n": _BATCH},
        ).all()
        if not rows:
            return
        for r in rows:
            before = r.attributes or {}
            after = mask_document(before)
            if after == before:
                continue
            key = edge_key(r.connection_id, r.origin, r.source_uid, r.target_uid, r.type, after)
            conn.execute(
                text("""
                UPDATE edge SET attributes = CAST(:a AS jsonb),
                  edge_key = CASE WHEN EXISTS (SELECT 1 FROM edge o
                                               WHERE o.edge_key = :k AND o.id <> :id)
                                  THEN edge_key ELSE :k END
                WHERE id = :id
            """),
                {"a": json.dumps(after), "k": key, "id": r.id},
            )
        last = rows[-1].id


def mask_stored(conn: Connection) -> None:
    _documents(conn, "resource_config", "config")
    _documents(conn, "resource", "tags")
    _edges(conn)
    for table, column in _TEXT:
        conn.execute(
            text(f"""
            UPDATE {table}
            SET {column} = regexp_replace(regexp_replace({column}, :old, :mask, 'g'),
                                          :ext, '\\1' || :mask, 'gi')
            WHERE {column} ~ :old OR {column} ~* :ext
        """),  # noqa: S608 - fixed names
            {"old": _OLD_SQL, "mask": MASK, "ext": _TEXT_EXTERNAL_ID},
        )


def upgrade() -> None:
    mask_stored(op.get_bind())


def downgrade() -> None:
    """Nothing to undo: a masked value cannot be restored, and ******** reads the same under
    the older release."""
