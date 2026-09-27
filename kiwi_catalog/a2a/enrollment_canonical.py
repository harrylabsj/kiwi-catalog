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

"""接入签名的确定性 JSON：匹配 Kiwi TS 的 negotiation/jcs.ts 线协议。

UTF-16 排序、UTF-8 字符串、有限 binary64 数值；指数不带加号，负零保留。
这两项数字约定来自既有 Kiwi 契约，不宣称是标准 RFC 8785 实现。
调用端须在 HTTP JSON 编码后对实际线值计算摘要（JSON.stringify 会把 -0 写为 0）。
整型仅接受 JS 安全整数，以免 Python 的任意精度和 JS 的舍入产生歧义。
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any

from kiwi_catalog.core.errors import ValidationError

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 32
MAX_BYTES = 1024 * 1024


def _string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError("enrollment JSON contains an invalid Unicode surrogate") from exc
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValidationError("enrollment JSON integer exceeds JavaScript safe range")
        return str(value)
    if not math.isfinite(value):
        raise ValidationError("enrollment JSON numbers must be finite")
    if abs(value) > MAX_SAFE_INTEGER:
        raise ValidationError("enrollment JSON number exceeds JavaScript safe range")
    if value == 0:
        return "-0" if math.copysign(1.0, value) < 0 else "0"
    shortest = repr(value).lower()
    if abs(value) >= 1e-6:
        # Python's repr switches to exponent form earlier than ECMAScript.
        fixed = format(Decimal(shortest), "f")
        return fixed.rstrip("0").rstrip(".") if "." in fixed else fixed
    coefficient, exponent = shortest.split("e")
    if coefficient.endswith(".0"):
        coefficient = coefficient[:-2]
    return f"{coefficient}e{int(exponent)}"


def _canonical(value: Any, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise ValidationError("enrollment JSON exceeds maximum nesting depth")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValidationError("enrollment JSON object keys must be strings")
        try:
            keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        except UnicodeEncodeError as exc:
            raise ValidationError("enrollment JSON contains an invalid Unicode surrogate") from exc
        return "{" + ",".join(
            _string(key) + ":" + _canonical(value[key], depth + 1) for key in keys
        ) + "}"
    raise ValidationError("enrollment value is not JSON-compatible")


def canonical_bytes(value: Any) -> bytes:
    """返回规范字节；非法/超限值明确拒绝，不做替代或截断。"""
    encoded = _canonical(value, 0).encode("utf-8")
    if len(encoded) > MAX_BYTES:
        raise ValidationError("enrollment JSON exceeds maximum size")
    return encoded


def canonical_digest(value: Any) -> str:
    """返回与 Runtime card_digest/body_digest 相同形状的 SHA-256 摘要。"""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
