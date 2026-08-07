"""kiwi-catalog runtime configuration."""

from __future__ import annotations

from pathlib import Path

DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "kiwi-catalog"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "catalog.sqlite"
