# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
    # 本库 env 名优先，提取遗留的 SHOPPING_ 名兼容回退。
    raw = (
        os.environ.get("KIWI_CATALOG_MAX_REQUEST_BODY_BYTES")
        or os.environ.get("SHOPPING_MAX_REQUEST_BODY_BYTES")
        or DEFAULT_MAX_REQUEST_BODY_BYTES
    )
    try:
        value = int(str(raw))
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
