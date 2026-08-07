"""Buyer bootstrap service helpers."""

from __future__ import annotations

from typing import Any


def rate_limit_per_minute(
    raw: Any,
    *,
    default: int,
    maximum: int,
) -> int:
    text = str(raw or "").strip()
    if not text:
        return default
    try:
        limit = int(text)
    except (OverflowError, TypeError, ValueError):
        return default
    if limit < 0:
        return default
    return min(limit, maximum)
