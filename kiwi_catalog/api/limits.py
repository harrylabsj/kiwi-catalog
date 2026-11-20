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

from kiwi_catalog.api.transport import INQUIRY_TRANSPORT_KEYS as INQUIRY_TRANSPORT_KEYS
from kiwi_catalog.core.errors import PayloadTooLargeError, ValidationError

DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_ITEMS = 1000
MAX_JSON_STRING_CHARS = 65536
MAX_JSON_NODES = 10000
JSON_DEPTH_ERROR = f"JSON request body nesting must be <= {MAX_JSON_DEPTH}"

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


def decode_request_body(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
    except RecursionError as exc:
        raise ValidationError(JSON_DEPTH_ERROR) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("invalid JSON request body") from exc
    if not isinstance(payload, dict):
        raise ValidationError("JSON request body must be an object")
    validate_payload(payload)
    return payload


def validate_payload(payload: Any, *, skip_keys: frozenset[str] = frozenset()) -> None:
    """Validate client JSON limits.

    ``skip_keys`` names top-level transport-injected fields that are not part of
    the client JSON and are bounded by their own handler.  The open-inquiry
    relay injects the original request bytes as one base64 string
    (``_raw_inquiry_body_b64``, up to 87384 chars for a 64 KiB body) plus
    header-derived metadata.  Counting them here would reject every raw body
    above 49152 bytes on the fallback stack only, while the FastAPI stack
    validates the original body before injecting anything.  The relay handler
    separately enforces the raw byte limit, so skipping these fields keeps both
    stacks at the documented 64 KiB.

    ``skip_keys`` must only be supplied by the transport after it has already
    validated the unmodified client body (see ``INQUIRY_TRANSPORT_KEYS``).  It
    must never be derived from the payload itself: a client can send the same
    key names in its JSON.
    """
    visible_payload = payload
    if skip_keys and isinstance(payload, dict):
        visible_payload = {k: v for k, v in payload.items() if k not in skip_keys}
    try:
        encoded_size = len(json.dumps(visible_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except RecursionError as exc:
        raise ValidationError(JSON_DEPTH_ERROR) from exc
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
            raise ValidationError(JSON_DEPTH_ERROR)
        if isinstance(value, str):
            if len(value) > MAX_JSON_STRING_CHARS:
                raise ValidationError(f"JSON strings must be <= {MAX_JSON_STRING_CHARS} characters")
        elif isinstance(value, dict):
            if len(value) > MAX_JSON_ITEMS:
                raise ValidationError(f"JSON objects must contain at most {MAX_JSON_ITEMS} fields")
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValidationError("JSON object keys must be strings")
                if depth == 0 and key in skip_keys:
                    continue
                walk(child, depth + 1)
        elif isinstance(value, list):
            if len(value) > MAX_JSON_ITEMS:
                raise ValidationError(f"JSON arrays must contain at most {MAX_JSON_ITEMS} items")
            for child in value:
                walk(child, depth + 1)

    walk(payload, 0)
