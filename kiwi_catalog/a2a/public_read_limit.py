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

"""M3 公开读地址的限流（计划 B3：「公开、限流」）。

稳定读地址（名片 + 绑定声明）是**匿名可读**的，因此不能依赖身份做预算——
按客户端 IP 分桶，复用仓库既有的固定窗口计数器
（`services/rate_limit.SQLiteRateLimitBackend`，表 `agent_catalog_write_rate_limits`，
键加前缀区分不同面，避免为读限流再开一张表）。

为什么绑定声明这一侧更需要限流：每次读取都要**做一次 Ed25519 签名**——不限流
等于把 Catalog 的私钥运算开放给任何匿名来源。

键的取值：`_client_ip`（两栈都按"仅可信代理采信 XFF"解析后注入）。缺失时退化为
`unknown` 桶——**不跳过限流**（缺 IP 不等于无限额），仍受同一预算约束。
"""

from __future__ import annotations

import os
from typing import Any

from kiwi_catalog.core.errors import RateLimitError

#: 每个客户端 IP 每分钟的公开读预算（配置键与默认值）。
_DEFAULT_PER_MINUTE = 120
_MAX_PER_MINUTE = 100_000
_ENV_KEYS = ("KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE",)

#: 限流键前缀：与写限流共用一张表，靠前缀区分面，互不挤占预算。
_KEY_PREFIX = "public-read:"


def public_read_limit_per_minute(environ: dict[str, str] | None = None) -> int:
    """读取预算配置；缺省/误配（0、负数、非数字）一律回退默认值。"""
    source = environ if environ is not None else os.environ
    raw = next((source.get(key) for key in _ENV_KEYS if source.get(key)), "")
    from kiwi_catalog.services.buyer_bootstrap import rate_limit_per_minute

    return rate_limit_per_minute(raw, default=_DEFAULT_PER_MINUTE, maximum=_MAX_PER_MINUTE)


def enforce_public_read_limit(
    conn: Any,
    payload: dict[str, Any] | None,
    *,
    surface: str,
    limit: int | None = None,
    now: Any = None,
) -> None:
    """按客户端 IP 消费一次公开读预算；超限抛 RateLimitError（→ 429）。

    *surface* 只用于错误文案与限流键（如 ``"agent-card read"``）。
    """
    client_ip = str((payload or {}).get("_client_ip") or "").strip() or "unknown"
    budget = public_read_limit_per_minute() if limit is None else limit
    from kiwi_catalog.services.rate_limit import SQLiteRateLimitBackend, enforce_rate_limit

    backend = SQLiteRateLimitBackend(
        conn, table="agent_catalog_write_rate_limits", key_column="actor_key"
    )
    enforce_rate_limit(
        backend,
        key=f"{_KEY_PREFIX}{surface}:{client_ip}",
        limit=budget,
        window_seconds=60,
        description=f"{surface} ({budget}/minute per client)",
        current=now,
    )


__all__ = [
    "RateLimitError",
    "enforce_public_read_limit",
    "public_read_limit_per_minute",
]
