"""Stored text re-masked with the fixed assignment rule (2026-10-24).

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-24

`core.redaction.redact_text` masked a secret assignment only when no word came before it. In
"ingest failed: password=x" the first match was the key `failed` with the value `password=x`;
`failed` is not a secret name, the match was kept and the scan went on after it, so x was stored.
The same held for "bad row: AWS_SECRET_ACCESS_KEY=x". The rule now scans a non-secret key's value
again, except after a bare ":" (an ARN's parts). Found in the secure code review of the
Kubernetes phase, round 3.

This migration applies the fixed rule to the redacted text written before it, the columns
migration 0028 rewrote: `finding.detail`, `scan_run.log_tail` and `command`,
`run_request.error`, `connection_test.message`, `finding_command.command` and `note`. Only
values of secret-named or environment-style keys change, to ********, and only rows that change
are written. `audit_log` is left as it is: it is append-only, and it never held tool output.

Irreversible: a masked value cannot be restored, and the downgrade does nothing.
"""

import re
from itertools import pairwise

from alembic import op
from sqlalchemy import Connection, text

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None

MASK = "********"
_BATCH = 2000
_TEXT = (
    ("finding", "detail"),
    ("scan_run", "log_tail"),
    ("scan_run", "command"),
    ("run_request", "error"),
    ("connection_test", "message"),
    ("finding_command", "command"),
    ("finding_command", "note"),
)
# A copy of core.redaction's assignment rule as of this migration: a migration never imports
# application code, which keeps changing after it.
_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_SECRET_WORDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "credentials",
        "environment",
        "variables",
        "userdata",
        "passphrase",
    }
)
_SECRET_PAIRS = frozenset(
    {("user", "data"), ("private", "key"), ("api", "key"), ("access", "key"), ("external", "id")}
)
_ASSIGNMENT_RE = re.compile(
    r"""(?P<key>"[A-Za-z_][A-Za-z0-9_.:-]*"|'[A-Za-z_][A-Za-z0-9_.:-]*'|["']?[A-Za-z_][A-Za-z0-9_.-]*["']?)"""
    r"""(?P<sep>\s*[:=]\s*)(?P<value>"[^"]*"|'[^']*'|\S+)"""
)
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def is_secret_key(key: str) -> bool:
    words = [w.lower() for w in _WORD_RE.findall(key)]
    if any(w in _SECRET_WORDS for w in words):
        return True
    return any(pair in _SECRET_PAIRS for pair in pairwise(words))


def _mask_assignment(match: re.Match[str]) -> str:
    key = match["key"].strip("\"'")
    if is_secret_key(key) or _ENV_NAME_RE.fullmatch(key):
        return f"{match['key']}{match['sep']}{MASK}"
    if match["sep"] == ":":
        return match.group(0)
    value = _ASSIGNMENT_RE.sub(_mask_assignment, match["value"])
    return f"{match['key']}{match['sep']}{value}"


def remask(value: str) -> str:
    return "\n".join(_ASSIGNMENT_RE.sub(_mask_assignment, line) for line in value.split("\n"))


def remask_stored(conn: Connection) -> int:
    """Returns how many values changed."""
    changed = 0
    for table, column in _TEXT:
        last = 0
        while True:
            rows = conn.execute(
                text(f"""
                SELECT id, {column} AS value FROM {table}
                WHERE id > :last AND {column} ~ '[:=]'
                ORDER BY id LIMIT :n
            """),  # noqa: S608 - fixed names
                {"last": last, "n": _BATCH},
            ).all()
            if not rows:
                break
            for row in rows:
                masked = remask(row.value)
                if masked != row.value:
                    conn.execute(
                        text(f"UPDATE {table} SET {column} = :v WHERE id = :id"),  # noqa: S608
                        {"v": masked, "id": row.id},
                    )
                    changed += 1
            last = rows[-1].id
    return changed


def upgrade() -> None:
    remask_stored(op.get_bind())


def downgrade() -> None:
    """Nothing to undo: a masked value cannot be restored."""
