"""The audit log: one append-only row per login and per administrative write."""

import json
from typing import Any

from sqlalchemy import Connection, text


def record_sign_in_limited(
    conn: Connection, *, actor: str, client_ip: str | None, window_minutes: int
) -> None:
    """A refused sign-in, once per address per window. Each refusal is cheap to cause and reaches
    no password check, and the log is never purged, so one row says what the rest would."""
    conn.execute(
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
            "detail": json.dumps(detail or {}),
            "ip": client_ip,
        },
    )
