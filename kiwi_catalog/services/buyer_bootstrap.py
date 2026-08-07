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
    # 0 视为误配：limit<=0 在 enforce_rate_limit 里是"禁用限流"——
    # env 误配 0 会静默关闭限流（review P3），回退默认值。
    if limit <= 0:
        return default
    return min(limit, maximum)
