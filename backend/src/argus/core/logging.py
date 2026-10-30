"""Structured JSON logging on the standard library, one object per line on stderr.

Every message, string field and exception text passes redact_text() first, as run logs do
before they reach Postgres: on Kubernetes a pod's output often leaves the cluster for a log
pipeline (ADR-0040, review S2), and an exception can quote the data it failed on.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from argus.core.redaction import redact_text

# Attributes every LogRecord has; anything else was passed through `extra=` and is logged.
_RESERVED = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        entry.update(
            {
                k: redact_text(v) if isinstance(v, str) else v
                for k, v in vars(record).items()
                if k not in _RESERVED
            }
        )
        if record.exc_info:
            entry["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(entry, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
