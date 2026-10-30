"""What every synthetic module shares: stable hashes and the resource record."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


def h(*parts: object) -> int:
    """Stable hash (Python's hash() is salted per process)."""
    digest = hashlib.sha256("|".join(map(str, parts)).encode()).digest()
    return int.from_bytes(digest[:8], "big")


def u(*parts: object) -> float:
    """Stable uniform number in [0, 1)."""
    return h(*parts) / 2**64


def hexid(width: int, *parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:width]


@dataclass
class Resource:
    table: str
    region: str
    native_id: str
    name: str
    arn: str
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def uid(self) -> str:
        return self.arn
