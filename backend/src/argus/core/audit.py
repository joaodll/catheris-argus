"""The audit log: one append-only row per login and per administrative write."""

import json
from typing import Any

from sqlalchemy import Connection, text


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
