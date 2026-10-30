"""Writes the API's OpenAPI document: the only contract between backend and frontend.

    docker compose run --rm openapi        rewrites backend/openapi.json

The frontend generates its client from that file; tests/api/test_openapi.py fails when the
file and the code disagree.
"""

import json
import sys
from pathlib import Path

from argus.api import create_app


def render() -> str:
    return json.dumps(create_app().openapi(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    target = Path((argv or sys.argv[1:] or ["openapi.json"])[0])
    target.write_text(render(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
