"""CloudFront origin custom header values masked in stored configuration (owner, 2026-11-05).

Revision ID: 0043
Revises: 0042
Create Date: 2026-11-05

A CloudFront distribution's origins can carry custom headers, {"HeaderName", "HeaderValue"}. The
usual way an origin checks that a request came through CloudFront is one such header holding a
shared secret, under an ordinary name (X-Origin-Verify), so no redaction rule masked it: the
name/value rule masks only a value whose name reads as secret. `core.redaction` now treats every
key ending in the words header and value as secret-bearing.

This migration applies that one rule to `resource_config.config`, the only place it can be: the
Steampipe distribution table stores origins, and Prowler keeps only an origin's id, domain and
TLS settings. Only rows whose text mentions such a key are read, in pages by id, and only rows
that change are written, so it takes row locks on few rows.

As in migrations 0028 and 0040: a configuration keeps its `config_hash`, because the next scan of
a resource stores its configuration once more under the new hash and nothing compares the two.

The rule is copied here, not imported: a migration never imports application code, which keeps
changing after it.

Irreversible: a masked value cannot be restored, and the downgrade does nothing.
"""

import json
import re
from collections.abc import Iterator
from typing import Any

from alembic import op
from sqlalchemy import Connection, text

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None

MASK = "********"
_BATCH = 2000
_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


def is_header_value(key: str) -> bool:
    """HeaderValue, header_value: the key's last two words, as core.redaction splits them."""
    return [w.lower() for w in _WORD_RE.findall(key)][-2:] == ["header", "value"]


def _mask_value(value: Any) -> Any:
    """core.redaction.redact_value: the shape stays, every leaf goes, an empty string stays."""
    if isinstance(value, dict):
        return {k: _mask_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(v) for v in value]
    return value if value is None or value == "" else MASK


def mask_header_values(document: Any) -> Any:
    if isinstance(document, dict):
        return {
            k: _mask_value(v) if is_header_value(k) else mask_header_values(v)
            for k, v in document.items()
        }
    if isinstance(document, list):
        return [mask_header_values(v) for v in document]
    return document


def _pages(conn: Connection) -> Iterator[list[Any]]:
    last = 0
    while True:
        rows = conn.execute(
            text(
                "SELECT id, config FROM resource_config "
                "WHERE id > :last AND config::text ~* 'header_?value' ORDER BY id LIMIT :n"
            ),
            {"last": last, "n": _BATCH},
        ).all()
        if not rows:
            return
        yield rows
        last = rows[-1].id


def remask_stored(conn: Connection) -> int:
    """Returns how many configurations changed."""
    changed = 0
    for rows in _pages(conn):
        for row in rows:
            masked = mask_header_values(row.config)
            if masked != row.config:
                conn.execute(
                    text("UPDATE resource_config SET config = CAST(:c AS jsonb) WHERE id = :id"),
                    {"c": json.dumps(masked), "id": row.id},
                )
                changed += 1
    return changed


def upgrade() -> None:
    remask_stored(op.get_bind())


def downgrade() -> None:
    """Nothing to undo: a masked value cannot be restored."""
