"""Administration settings (ADR-0023): everything an administrator configures in the UI.

Owns platform_setting: one row per topic, a JSON value, validated by the topic's model. Values
that bound nothing are plain ranges; values an operator must be able to cap (history days) are
also checked against their environment bound, on write and again at the point of use, so
lowering the bound takes effect for rows written before it.

Settings are read on every use and never cached: there are several processes.
"""

from argus.settings.topics import (
    TOPICS,
    CollectionSettings,
    IdentitySettings,
    RawStorageSettings,
    RetentionSettings,
    SettingsBoundError,
    ToolPrefixes,
    read_collection,
    read_identity,
    read_identity_credentials,
    read_raw_storage,
    read_retention,
    write_identity,
    write_topic,
)

__all__ = [
    "TOPICS",
    "CollectionSettings",
    "IdentitySettings",
    "RawStorageSettings",
    "RetentionSettings",
    "SettingsBoundError",
    "ToolPrefixes",
    "read_collection",
    "read_identity",
    "read_identity_credentials",
    "read_raw_storage",
    "read_retention",
    "write_identity",
    "write_topic",
]
