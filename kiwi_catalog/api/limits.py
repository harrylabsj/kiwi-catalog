"""Transport and JSON payload resource limits."""

from __future__ import annotations

import json
import os
from typing import Any

from kiwi_catalog.core.errors import PayloadTooLargeError, ValidationError

DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_ITEMS = 1000
MAX_JSON_STRING_CHARS = 65536
MAX_JSON_NODES = 10000


def max_request_body_bytes() -> int:
    try:
        value = int(str(os.environ.get("SHOPPING_MAX_REQUEST_BODY_BYTES") or DEFAULT_MAX_REQUEST_BODY_BYTES))
    except ValueError:
        return DEFAULT_MAX_REQUEST_BODY_BYTES
    return min(max(value, 1024), 16 * 1024 * 1024)


def validate_payload(payload: Any) -> None:
    try:
        encoded_size = len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("JSON request body contains unsupported values") from exc
    if encoded_size > max_request_body_bytes():
        raise PayloadTooLargeError("request body is too large")

    nodes = 0

    def walk(value: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValidationError(f"JSON request body must contain at most {MAX_JSON_NODES} values")
        if depth > MAX_JSON_DEPTH:
            raise ValidationError(f"JSON request body nesting must be <= {MAX_JSON_DEPTH}")
        if isinstance(value, str):
            if len(value) > MAX_JSON_STRING_CHARS:
                raise ValidationError(f"JSON strings must be <= {MAX_JSON_STRING_CHARS} characters")
        elif isinstance(value, dict):
            if len(value) > MAX_JSON_ITEMS:
                raise ValidationError(f"JSON objects must contain at most {MAX_JSON_ITEMS} fields")
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValidationError("JSON object keys must be strings")
                walk(child, depth + 1)
        elif isinstance(value, list):
            if len(value) > MAX_JSON_ITEMS:
                raise ValidationError(f"JSON arrays must contain at most {MAX_JSON_ITEMS} items")
            for child in value:
                walk(child, depth + 1)

    walk(payload, 0)
