"""Pure SQLite row-to-mapping conversion for catalog repositories."""

from __future__ import annotations

import sqlite3
from typing import Any


def row_to_dict(row: sqlite3.Row, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convert a sqlite row and apply explicit projection overrides."""
    result = dict(row)
    if overrides:
        result.update(overrides)
    return result
