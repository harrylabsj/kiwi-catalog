"""Shared API handler normalization helpers."""

from __future__ import annotations

import math
from typing import Any

from kiwi_catalog.core.errors import ValidationError

MAX_SQLITE_INTEGER = 2**63 - 1


def require_field(payload: dict[str, Any], field: str) -> Any:
    try:
        return payload[field]
    except KeyError as exc:
        raise ValidationError(f"missing required field: {field}") from exc
DEFAULT_RESULT_LIMIT = 50
MAX_RESULT_LIMIT = 100


def bool_from_query(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def non_negative_whole_int(value: Any, field_name: str, default: int = 0) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise ValidationError(f"{field_name} must be a whole number")
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise ValidationError(f"{field_name} must be a whole number")
        number = int(value)
    else:
        try:
            number = int(str(value).strip())
        except ValueError as exc:
            raise ValidationError(f"{field_name} must be a whole number") from exc
    if number < 0:
        raise ValidationError(f"{field_name} must be non-negative")
    if number > MAX_SQLITE_INTEGER:
        raise ValidationError(f"{field_name} must be <= {MAX_SQLITE_INTEGER}")
    return number


def positive_whole_int(value: Any, field_name: str) -> int:
    number = non_negative_whole_int(value, field_name)
    if number <= 0:
        raise ValidationError(f"{field_name} must be greater than 0")
    return number


def result_limit(value: Any, default: int = DEFAULT_RESULT_LIMIT) -> int:
    if value in (None, ""):
        return default
    return min(positive_whole_int(value, "limit"), MAX_RESULT_LIMIT)


def result_offset(value: Any) -> int:
    return non_negative_whole_int(value, "offset", default=0)


def public_merchant_summary(merchant: dict[str, Any]) -> dict[str, Any]:
    summary = dict(merchant)
    summary.pop("contact", None)
    summary.pop("automation_boundaries", None)
    return summary


def public_product_summary(product: dict[str, Any]) -> dict[str, Any]:
    summary = dict(product)
    merchant = summary.get("merchant")
    if isinstance(merchant, dict):
        summary["merchant"] = public_merchant_summary(merchant)
    return summary
