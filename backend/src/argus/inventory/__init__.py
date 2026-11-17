"""Inventory: resources, their configurations and their daily snapshots.

Owns resource, resource_config, resource_snapshot, resource_load, resource_tag and
role_last_used.
Public interface:
    parse_steampipe()  the Steampipe adapter: one run's raw files -> InventoryBatch (pure)
    load_inventory()   writes a batch for one connection and day, in the caller's transaction
    effective_day()    the inventory that stands for a day: the latest load, however old
    delete_orphan_configs(), delete_loads_before()   retention's cleanup
    RESOURCES_ON_DAY_SQL, RESOURCES_IN_REGIONS_SQL, CURRENT_ASSETS_SQL, TAGGED_RESOURCES_SQL,
    RESOURCE_TAGS_SQL, resource_id_sql(), uid_by_native_id()
                       for other modules' queries
    RESOURCE_NODES_SQL, resource_nodes()   resources as Resource map nodes, by uid
    RESOURCE_TYPES_ON_DAY_SQL, latest_days(), resource_types()   uids and types only, for
                       the attack-path walk and its kinds (ADR-0052)
    list_resources(), resource_facets(), resource_names(), resource_at()   the read side
                       (the Resources page, and a resource as of a day)
    iter_resources()   every resource matching the list's filters, in id batches (reports)
    role_last_used(), UNUSED_ROLES_SQL, RoleLastUsed, RoleUnused   each IAM role's last use as
                       AWS records it (roles.py, migration 0053), for the Resources list
    CURRENT_ROLES_SQL  one connection's current roles, for relationships' workload counts
    is_asset()         whether a resource type counts as an asset (parts, settings and links
                       are stored and searchable, not counted); stored as resource.asset
"""

from argus.inventory.load import delete_orphan_configs, load_inventory
from argus.inventory.metrics import (
    INVENTORY_METRICS,
    put_inventory_metrics,
    rollup_inventory_metrics,
)
from argus.inventory.queries import (
    CURRENT_ASSETS_SQL,
    RESOURCE_NODES_SQL,
    RESOURCE_TAGS_SQL,
    RESOURCE_TYPES_ON_DAY_SQL,
    RESOURCES_IN_REGIONS_SQL,
    RESOURCES_ON_DAY_SQL,
    TAGGED_RESOURCES_SQL,
    ResourceFilters,
    ResourceOrder,
    delete_loads_before,
    effective_day,
    iter_resources,
    latest_days,
    list_resources,
    resource_at,
    resource_facets,
    resource_id_sql,
    resource_names,
    resource_nodes,
    resource_types,
    uid_by_native_id,
)
from argus.inventory.roles import (
    CURRENT_ROLES_SQL,
    ROLE_TYPE,
    TRACKING_DAYS,
    UNUSED_ROLES_SQL,
    RoleLastUsed,
    RoleUnused,
    role_last_used,
)
from argus.inventory.steampipe import (
    SUPPORTED_VERSIONS,
    InventoryBatch,
    InventoryResource,
    RoleReading,
    is_asset,
    parse_steampipe,
)

__all__ = [
    "CURRENT_ASSETS_SQL",
    "CURRENT_ROLES_SQL",
    "INVENTORY_METRICS",
    "RESOURCES_IN_REGIONS_SQL",
    "RESOURCES_ON_DAY_SQL",
    "RESOURCE_NODES_SQL",
    "RESOURCE_TAGS_SQL",
    "RESOURCE_TYPES_ON_DAY_SQL",
    "ROLE_TYPE",
    "SUPPORTED_VERSIONS",
    "TAGGED_RESOURCES_SQL",
    "TRACKING_DAYS",
    "UNUSED_ROLES_SQL",
    "InventoryBatch",
    "InventoryResource",
    "ResourceFilters",
    "ResourceOrder",
    "RoleLastUsed",
    "RoleReading",
    "RoleUnused",
    "delete_loads_before",
    "delete_orphan_configs",
    "effective_day",
    "is_asset",
    "iter_resources",
    "latest_days",
    "list_resources",
    "load_inventory",
    "parse_steampipe",
    "put_inventory_metrics",
    "resource_at",
    "resource_facets",
    "resource_id_sql",
    "resource_names",
    "resource_nodes",
    "resource_types",
    "role_last_used",
    "rollup_inventory_metrics",
    "uid_by_native_id",
]
