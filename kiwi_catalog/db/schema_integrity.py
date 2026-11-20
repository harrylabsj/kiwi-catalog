"""Versioned schema checks derived from the catalog migration history."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from functools import lru_cache

from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION, MIGRATIONS
from kiwi_catalog.db.models import INDEXES, SCHEMA

# Buyer-access tables were added without a version bump during v54. A real
# pre-buyer-access v54 is valid, while every v55+ database should have them.
_BUYER_ACCESS_REQUIRED_VERSION = 55
_OBJECTS_SQL = (
    "select type, name from sqlite_schema where name not glob 'sqlite_*'"
    " and type in ('table', 'index', 'trigger', 'view')"
)
_COLUMNS_SQL = (
    "select tables.name, columns.name from sqlite_schema as tables"
    " join pragma_table_xinfo(tables.name) as columns"
    " where tables.type = 'table' and tables.name not glob 'sqlite_*'"
)


def _replayed_schema(version: int, *, snapshot: bool = False) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    with closing(sqlite3.connect(":memory:")) as baseline:
        baseline.row_factory = sqlite3.Row
        if snapshot:
            for statement in SCHEMA:
                baseline.execute(statement)
        for migration in MIGRATIONS:
            if migration.version > version:
                break
            migration.apply(baseline)
        if version >= _BUYER_ACCESS_REQUIRED_VERSION:
            from kiwi_catalog.services.buyer_access import ensure_schema

            ensure_schema(baseline)
        if snapshot:
            for statement in INDEXES:
                baseline.execute(statement)
        objects = {(row[0], row[1]) for row in baseline.execute(_OBJECTS_SQL)}
        columns = {(row[0], row[1]) for row in baseline.execute(_COLUMNS_SQL)}
    return objects, columns


@lru_cache(maxsize=None)
def _expected_schema(version: int) -> tuple[frozenset[tuple[str, str]], frozenset[tuple[str, str]]]:
    # Historical versions must not be held to the current bootstrap snapshot.
    objects, columns = _replayed_schema(version)
    if version == CURRENT_SCHEMA_VERSION:
        snapshot_objects, snapshot_columns = _replayed_schema(version, snapshot=True)
        objects |= snapshot_objects
        columns |= snapshot_columns
    return frozenset(objects), frozenset(columns)


def assert_catalog_schema(conn: sqlite3.Connection, version: int) -> None:
    """Reject missing versioned schema objects before any repair DDL runs."""
    objects = {(row[0], row[1]) for row in conn.execute(_OBJECTS_SQL)}
    if version == 0:
        if objects:
            raise RuntimeError("catalog schema v0 is not empty; restore a valid versioned database")
        return
    expected_objects, expected_columns = _expected_schema(version)
    columns = {(row[0], row[1]) for row in conn.execute(_COLUMNS_SQL)}
    missing = [f"{kind} {name}" for kind, name in sorted(expected_objects - objects)]
    missing.extend(
        f"column {table}.{column}" for table, column in sorted(expected_columns - columns)
        if ("table", table) in objects
    )
    if missing:
        raise RuntimeError(f"catalog schema v{version} is incomplete: missing {', '.join(missing)}")
