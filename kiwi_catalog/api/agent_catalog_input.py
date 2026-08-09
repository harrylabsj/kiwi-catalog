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

"""Pure register-input validation and optional payload field shaping for catalog writes.

Extracted from ``handlers/agent_catalog.py`` (T8 pure-structure batch): the
input-side leaf behind the register route's CD #8 schema hard rejection and the
moderation routes' optional ``reason`` field.  ``_validate_register_input``
strips the auth/idempotency fields, then validates the remaining payload
against ``contracts/register-input.schema.json``
(``additionalProperties:false`` — unknown fields and merchant private data are
rejected before any idempotency/rate-limit budget is spent).  ``_payload_reason``
shapes the optional operator reason for the §23 audit.

The leaf is side-effect free by construction — it never opens a SQLite
connection, never takes a lock, never touches queues or network, never mutates
state, and never commits a transaction.  The single I/O is the lazy, once-cached
read of the static ``register-input.schema.json`` contract, whose resolved path
is identical to the pre-extraction code.  ``handlers/agent_catalog.py`` (the
facade) re-exports ``_register_input_schema``, ``_validate_register_input`` and
``_payload_reason`` so the module-private compat surface, the
``register payload invalid: …`` error copy, the cached ``Draft7Validator``
identity and the call order are preserved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import ValidationError as SchemaValidationError

from kiwi_catalog.core.errors import ValidationError

# 认证/幂等字段在校验前剥离（与 listings contracts.py 的 _AUTH_FIELDS 同模式）。
_REGISTER_AUTH_FIELDS = {
    "owner_token",
    "_auth_token",
    "admin_token",
    "idempotency_key",
    "_idempotency_key",
}

_REGISTER_INPUT_SCHEMA: jsonschema.Draft7Validator | None = None


def _register_input_schema() -> jsonschema.Draft7Validator:
    """模块级惰性加载 register-input.schema.json（CD #8 schema 硬拒落盘）。"""
    global _REGISTER_INPUT_SCHEMA
    if _REGISTER_INPUT_SCHEMA is None:
        schema_path = (
            Path(__file__).resolve().parent.parent / "contracts" / "register-input.schema.json"
        )
        with open(schema_path, encoding="utf-8") as fh:
            _REGISTER_INPUT_SCHEMA = jsonschema.Draft7Validator(json.load(fh))
    return _REGISTER_INPUT_SCHEMA


def _validate_register_input(payload: dict[str, Any]) -> None:
    """register 输入契约硬校验（additionalProperties:false）。

    完成定义 #8：注册输入只能是 schema 声明的公开字段——私有经营数据
    （成本/底价/私密库存/凭据）在 schema 层拒绝，未知字段一律 422。
    认证/幂等字段剥离后再校验；domain 的 hostname 形态由
    normalize_canonical_domain 负责（schema 只查存在性）。
    """
    candidate = {k: v for k, v in (payload or {}).items() if k not in _REGISTER_AUTH_FIELDS}
    try:
        _register_input_schema().validate(candidate)
    except SchemaValidationError as exc:
        raise ValidationError(f"register payload invalid: {exc.message}") from exc


def _payload_reason(payload: dict[str, Any]) -> str:
    """Optional operator reason from the request body (recorded in §23 audit)."""
    return str((payload or {}).get("reason") or "").strip()


__all__ = [
    "_register_input_schema",
    "_validate_register_input",
    "_payload_reason",
]
