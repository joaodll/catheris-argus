import json
from pathlib import Path

from argus.entrypoints.openapi import render

SPEC = Path(__file__).resolve().parents[2] / "openapi.json"


def test_the_committed_openapi_document_is_current() -> None:
    assert SPEC.exists(), "run: docker compose run --rm openapi"
    assert SPEC.read_text(encoding="utf-8") == render(), "run: docker compose run --rm openapi"


def test_every_route_but_health_requires_a_session() -> None:
    spec = json.loads(render())
    open_paths = {"/api/v1/health", "/api/v1/ready", "/api/v1/auth/sign-in"}
    for path, methods in spec["paths"].items():
        if path in open_paths:
            continue
        for method, operation in methods.items():
            names = {p["name"] for p in operation.get("parameters", [])}
            assert "argus_session" in names, f"{method.upper()} {path} has no session check"
