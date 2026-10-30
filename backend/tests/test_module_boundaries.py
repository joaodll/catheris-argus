"""Modules own their tables (ADR-0017). import-linter guards Python imports; this guards SQL.

A module may embed SQL that the owning module exports (a public `*_SQL` constant or a function
in its interface), but it never names another module's table itself. Then a schema change
touches one module, and every query that depends on the table lives where the table does.
"""

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "argus"

OWNERS: dict[str, set[str]] = {
    "connections": {"connection", "connection_test"},
    "inventory": {"resource", "resource_config", "resource_snapshot"},
    "relationships": {
        "edge",
        "edge_snapshot",
        "edge_load",
        "flow",
        "flow_shape",
        "flow_step",
        "flow_chip",
        "flow_snapshot",
    },
    "findings": {
        "finding",
        "finding_command",
        "finding_check_text",
        "finding_facet",
        "finding_snapshot",
        "finding_event",
        "compliance_requirement",
        "compliance_snapshot",
        "compliance_framework",
        "compliance_rollup",
    },
    "attackpaths": {"attack_path"},
    "metrics": {"metric_daily"},
    "ingest": {"scan_run"},
    "core": {"unresolved_ref", "audit_log"},
    "scheduling": {"run_request", "schedule", "schedule_connection"},
    "settings": {"platform_setting"},
    "auth": {"app_user", "user_session", "login_failure"},
}
ALL_TABLES = set().union(*OWNERS.values())
_SQL_TABLE_RE = re.compile(
    r"\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+(" + "|".join(sorted(ALL_TABLES)) + r")\b"
)


def _modules() -> list[Path]:
    return sorted(p for p in SRC.iterdir() if p.is_dir() and not p.name.startswith("_"))


def test_every_table_has_one_owner() -> None:
    owned = [t for tables in OWNERS.values() for t in tables]
    assert len(owned) == len(set(owned))


@pytest.mark.parametrize("module", _modules(), ids=lambda p: p.name)
def test_a_module_names_only_its_own_tables(module: Path) -> None:
    own = OWNERS.get(module.name, set())
    foreign = []
    for file in sorted(module.rglob("*.py")):
        for number, line in enumerate(file.read_text().splitlines(), start=1):
            for table in _SQL_TABLE_RE.findall(line):
                if table not in own:
                    foreign.append(f"{file.relative_to(SRC)}:{number}: {table}")
    assert not foreign, "use the owning module's exported SQL instead:\n" + "\n".join(foreign)
