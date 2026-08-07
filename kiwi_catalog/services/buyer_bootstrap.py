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
