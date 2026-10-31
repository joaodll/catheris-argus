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


def test_the_contract_names_no_provider_scanner() -> None:
    """The vulnerabilities tool is provider-neutral (ADR-0042, amended 2026-10-31): no path,
    schema, field or enum value names one cloud's scanner; a description may."""
    spec = json.loads(render())
    names: list[str] = list(spec["paths"])

    def walk(node: object) -> None:
        if isinstance(node, dict):
            names.extend(str(k) for k in node if k not in ("description", "title"))
            for key, value in node.items():
                if key == "enum":
                    names.extend(str(v) for v in value)
                elif key not in ("description", "title"):
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(spec)
    assert not [n for n in names if "inspector" in n.lower()]
