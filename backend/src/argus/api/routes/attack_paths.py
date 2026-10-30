"""Investigate -> Attack paths (ADR-0028 fourth amendment): ranked paths, and one path with its
steps, how sure Argus is of each (ADR-0037) and what each tool says about them. A path's
`rule_*` fields name its kind (backend/rules/attack_paths): one search finds every kind."""

from datetime import date
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from argus import attackpaths, ingest, inventory, relationships
from argus.api.deps import Db, Viewer
from argus.api.routes.resource_map import MapEdge, MapNode, with_findings
from argus.core.config import get_settings

router = APIRouter(tags=["attack-paths"])

Severity = Literal["critical", "high", "medium", "low", "informational"]
Order = Literal["severity", "first_seen_desc", "first_seen_asc", "last_seen_desc", "last_seen_asc"]
Text = Annotated[str, Field(min_length=1, max_length=128)]
# A path kind's id: its file name in backend/rules/attack_paths.
KindId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
Confidence = Literal["confirmed", "supported", "candidate", "unknown", "blocked"]


class PathEntryStep(BaseModel):
    """A path's first step, the internet to its entry: what the list says it gets in by (a
    door's ports, a public policy, an outsider, a leaked credential)."""

    type: str
    origin: str
    attributes: dict[str, Any]


class PathOut(BaseModel):
    id: int
    path_id: str
    # The path's kind (its file id and version); a path found before 2026-10-10 names the rule
    # that found it.
    rule_id: str
    rule_version: int
    # The kind's name; null when this release has no file for it any more.
    rule_name: str | None
    category: str
    severity: str
    # Why: the kind's level, raised when the entry is confirmed reachable, lowered when no
    # node has a failing finding. Null for paths not evaluated since 2026-10-08.
    base_severity: str | None
    entry_confirmed: bool | None
    has_failing: bool | None
    # How sure Argus is: its weakest step's level (ADR-0037). Null for a path found before
    # 2026-10-10 by a rule.
    confidence: Confidence | None
    connection_id: int
    connection: str
    entry_uid: str
    target_uid: str
    # The ends' names, when they are in the inventory.
    entry_name: str | None
    target_name: str | None
    node_uids: list[str]
    # Where the steps come from: "rule", "cloudfox", "manual".
    evidence: list[str]
    # Null when the step's edge is no longer stored.
    entry_step: PathEntryStep | None
    state: str
    first_seen: date
    last_seen: date
    resolved_on: date | None


class PathPage(BaseModel):
    items: list[PathOut]
    total: int
    # The scan time the list reflects (newest day ingested); null when nothing is ingested.
    data_through: date | None


class PathKindOut(BaseModel):
    id: str
    # Null when this release has no file for the kind any more.
    name: str | None


class PathFacets(BaseModel):
    categories: list[str]
    # The kinds the paths have, by name.
    kinds: list[PathKindOut]
    # The confidence levels the paths have, weakest first.
    confidences: list[Confidence]


class PathRuleOut(BaseModel):
    name: str
    severity: str
    technique: str
    description: str
    remediation: str


class PathEdge(MapEdge):
    """One step with its evidence: how sure Argus is, why, and where it comes from ("rule
    internet-entry@3", "CloudFox role-trusts", "manual")."""

    confidence: Confidence
    confidence_why: str
    source: str


class PathDetail(PathOut):
    rule: PathRuleOut | None
    # The path's nodes in order, and its edges in order (step i links nodes i and i+1; an
    # edge may point either way, e.g. an instance MEMBER_OF its security group).
    nodes: list[MapNode]
    edges: list[PathEdge]


class PathQuery(BaseModel):
    limit: int = Field(50, ge=1, le=200)
    offset: int = Field(0, ge=0)
    order: Order = "severity"
    connection_id: int | None = None
    state: Literal["open", "resolved"] = "open"
    severity: list[Severity] = Field(default_factory=list, max_length=5)
    category: list[Text] = Field(default_factory=list, max_length=50)
    kind: list[KindId] = Field(default_factory=list, max_length=50)
    # Empty: every level but blocked (latent paths are listed only when asked for).
    confidence: list[Confidence] = Field(default_factory=list, max_length=5)
    # Only paths through this node: "attack paths through a resource".
    through: Annotated[str | None, Field(min_length=1, max_length=2048)] = None


def _kinds() -> dict[str, attackpaths.PathKind]:
    return attackpaths.kinds_by_id(get_settings().rules_dir)


def _family(origin: str) -> str:
    return "rule" if origin.startswith("rule:") else origin


def _rows(conn: Connection, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows with their kind's name, their ends' names, their evidence and their first step:
    two reads for the whole page."""
    kinds = _kinds()
    nodes = inventory.resource_nodes(
        conn, sorted({r[k] for r in rows for k in ("entry_uid", "target_uid")})
    )
    edges = relationships.edges_by_ids(conn, sorted({i for r in rows for i in r["edge_ids"]}))
    return [
        {
            **r,
            "rule_name": kinds[r["rule_id"]].name if r["rule_id"] in kinds else None,
            "entry_name": nodes.get(r["entry_uid"], {}).get("name"),
            "target_name": nodes.get(r["target_uid"], {}).get("name"),
            "evidence": sorted({_family(edges[i]["origin"]) for i in r["edge_ids"] if i in edges}),
            "entry_step": _entry_step(edges, r["edge_ids"]),
        }
        for r in rows
    ]


def _entry_step(edges: dict[int, dict[str, Any]], edge_ids: list[int]) -> dict[str, Any] | None:
    first = edges.get(edge_ids[0]) if edge_ids else None
    if first is None:
        return None
    return {k: first[k] for k in ("type", "origin")} | {"attributes": first["attributes"] or {}}


def _evidence(edge: dict[str, Any]) -> dict[str, Any]:
    level, why = attackpaths.edge_confidence(
        edge["type"], edge["origin"], edge["attributes"] or {}, edge["source_uid"]
    )
    return {
        **edge,
        "confidence": level,
        "confidence_why": why,
        "source": attackpaths.source_label(edge["type"], edge["origin"], edge["attributes"]),
    }


@router.get("/attack-paths")
def list_paths(conn: Db, _user: Viewer, query: Annotated[PathQuery, Query()]) -> PathPage:
    rows, total = attackpaths.list_paths(
        conn,
        limit=query.limit,
        offset=query.offset,
        order=query.order,
        filters=attackpaths.PathFilters(
            connection_id=query.connection_id,
            state=query.state,
            severities=tuple(query.severity),
            categories=tuple(query.category),
            kinds=tuple(query.kind),
            confidences=tuple(query.confidence),
            through_uid=query.through,
        ),
    )
    return PathPage(
        items=[PathOut.model_validate(r) for r in _rows(conn, rows)],
        total=total,
        # Paths are evaluated after every ingest (ADR-0037, second amendment); Steampipe and
        # CloudFox make the edges they walk.
        data_through=ingest.data_through(
            conn, connection_id=query.connection_id, tools=["steampipe", "cloudfox"]
        ),
    )


@router.get("/attack-paths/facets")
def path_facets(conn: Db, _user: Viewer, connection_id: int | None = None) -> PathFacets:
    """The Attack paths filters' options that come from the data."""
    found = attackpaths.path_facets(conn, connection_id=connection_id)
    present = set(found["confidences"])
    kinds = _kinds()
    named = [PathKindOut(id=k, name=kinds[k].name if k in kinds else None) for k in found["kinds"]]
    return PathFacets(
        categories=found["categories"],
        kinds=sorted(named, key=lambda k: (k.name or k.id).lower()),
        confidences=[c for c in attackpaths.LEVELS if c in present],
    )


@router.get("/attack-paths/{path_id}")
def path(path_id: int, conn: Db, _user: Viewer) -> PathDetail:
    found = attackpaths.get_path(conn, path_id)
    if found is None:
        raise LookupError(path_id)
    [row] = _rows(conn, [found])
    rule = _kinds().get(found["rule_id"])
    known = inventory.resource_nodes(conn, list(found["node_uids"]))
    nodes = [
        {
            "uid": uid,
            "kind": relationships.kind_of(uid),
            "resource_id": known.get(uid, {}).get("id"),
            "type": known.get(uid, {}).get("type"),
            "name": known.get(uid, {}).get("name"),
            "region": known.get(uid, {}).get("region"),
            "connection_id": known.get(uid, {}).get("connection_id"),
            "deleted_on": known.get(uid, {}).get("deleted_on"),
            "expanded": False,
            # An attack path is drawn whole: no node is a boundary to stop at.
            "boundary": False,
        }
        for uid in found["node_uids"]
    ]
    edges = relationships.edges_by_ids(conn, list(found["edge_ids"]))
    return PathDetail.model_validate(
        {
            **row,
            "rule": (
                {
                    "name": rule.name,
                    "severity": rule.severity,
                    "technique": rule.technique,
                    "description": rule.description,
                    "remediation": rule.remediation,
                }
                if rule
                else None
            ),
            "nodes": with_findings(conn, nodes),
            "edges": [_evidence(edges[i]) for i in found["edge_ids"] if i in edges],
        }
    )
