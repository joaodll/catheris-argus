"""The audit log: one append-only row per login and per administrative write.

Each row is also written as one structured log line (review F10), so a copy leaves the database
for whatever collects the process's output, and whoever holds the owner role can't change the
history unseen. The line carries "audit": true and the row's fields. Its logger is pinned to
INFO, so a quieter ARGUS_LOG_LEVEL never silences it.

The line is written when the row is inserted, not when the transaction commits: a write rolled
back afterwards still leaves its line. A line without a row is better than a row without a line.
Lines pair with rows by time, actor and action; the worker's role can't read rows back, so a
line carries no row id.

`detail` goes into the line as one JSON string, so the formatter's redact_text() reads all of
it, nested values included. Redaction can mask or drop part of it there; the row stays the full
record.
"""

import json
import logging
from typing import Any

from sqlalchemy import Connection, text

log = logging.getLogger("argus.audit")
log.setLevel(logging.INFO)


def _line(
    *,
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: str = "{}",
    client_ip: str | None = None,
) -> None:
    log.info(
        "audit",
        extra={
            "audit": True,
            "actor": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "client_ip": client_ip,
            "detail": detail,
        },
    )


def record_sign_in_limited(
    conn: Connection, *, actor: str, client_ip: str | None, window_minutes: int
) -> None:
    """A refused sign-in, once per address per window. Each refusal is cheap to cause and reaches
    no password check, and the log is never purged, so one row says what the rest would. The
    line follows the row: a refusal that adds no row writes no line either."""
    added = conn.execute(
        text("""
        INSERT INTO audit_log (actor, action, client_ip)
        SELECT :actor, 'auth.sign_in.limited', CAST(:ip AS inet)
        WHERE NOT EXISTS (
          SELECT 1 FROM audit_log
          WHERE action = 'auth.sign_in.limited'
            AND client_ip IS NOT DISTINCT FROM CAST(:ip AS inet)
            AND occurred_at > now() - CAST(:w AS interval)
        )
    """),
        {"actor": actor, "ip": client_ip, "w": f"{window_minutes} minutes"},
    )
    if added.rowcount == 1:
        _line(actor=actor, action="auth.sign_in.limited", client_ip=client_ip)


def record(
    conn: Connection,
    *,
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict[str, Any] | None = None,
    client_ip: str | None = None,
) -> None:
    detail_json = json.dumps(detail or {})
    conn.execute(
        text(
            "INSERT INTO audit_log (actor, action, target_type, target_id, detail, client_ip) "
            "VALUES (:actor, :action, :tt, :tid, CAST(:detail AS jsonb), CAST(:ip AS inet))"
        ),
        {
            "actor": actor,
            "action": action,
            "tt": target_type,
            "tid": target_id,
            "detail": detail_json,
            "ip": client_ip,
        },
    )
    _line(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail_json,
        client_ip=client_ip,
    )
