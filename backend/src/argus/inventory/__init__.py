"""Inventory: resources, their configurations and their daily snapshots.

Owns resource, resource_config and resource_snapshot. Public interface:
    parse_steampipe()  the Steampipe adapter: one run's raw files -> InventoryBatch (pure)
    load_inventory()   writes a batch for one connection and day, in the caller's transaction
    effective_day()    the snapshot that stands for a day (carry-forward window)
    delete_orphan_configs()   retention's cleanup of unreferenced configurations
    RESOURCES_ON_DAY_SQL, resource_id_sql(), uid_by_native_id()   for other modules' queries
    list_resources(), resource_facets(), resource_names(), resource_at()   the read side
                       (the Resources page, and a resource as of a day)
    RESOURCE_NODES_SQL, resource_nodes()   resources as Resource map nodes, by uid
    is_asset()         whether a resource type counts as an asset (parts, settings and links
                       are stored and searchable, not counted)
"""

from argus.inventory.load import delete_orphan_configs, load_inventory
from argus.inventory.metrics import INVENTORY_METRICS, put_inventory_metrics
from argus.inventory.queries import (
    RESOURCE_NODES_SQL,
    RESOURCES_ON_DAY_SQL,
    ResourceFilters,
    ResourceOrder,
    effective_day,
    list_resources,
    resource_at,
    resource_facets,
    resource_id_sql,
    resource_names,
    resource_nodes,
    uid_by_native_id,
)
from argus.inventory.steampipe import (
    SUPPORTED_VERSIONS,
    InventoryBatch,
    InventoryResource,
    is_asset,
    parse_steampipe,
)

__all__ = [
    "INVENTORY_METRICS",
    "RESOURCES_ON_DAY_SQL",
    "RESOURCE_NODES_SQL",
    "SUPPORTED_VERSIONS",
    "InventoryBatch",
    "InventoryResource",
    "ResourceFilters",
    "ResourceOrder",
    "delete_orphan_configs",
    "effective_day",
    "is_asset",
    "list_resources",
    "load_inventory",
    "parse_steampipe",
    "put_inventory_metrics",
    "resource_at",
    "resource_facets",
    "resource_id_sql",
    "resource_names",
    "resource_nodes",
    "uid_by_native_id",
]
