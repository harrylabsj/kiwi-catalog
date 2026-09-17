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

"""Agent 新鲜度（读时按 TTL 降级；merchant-buddy 第 1 版 WP6 / 发布计划 §3.6）。

背景：`catalog_agents.freshness_state` 是**存储态**——注册/验证/心跳写入。商家
服务器下线后没有任何一方会去改它，于是采购专家会一直把该商家标成「可实时询价」，
而实际上没人接单。设计要求「服务离线时不再显示可实时询价，公开资料仍可查」。

做法：读时按 `last_seen_at` 与 TTL 派生**有效新鲜度**：

- 只降不升：存储态是 `stale`/`unreachable` 时原样返回（那是验证管线的结论）；
- 存储态 `fresh` 但 `last_seen_at` 早于 TTL → 返回 `stale`；
- 无 `last_seen_at`（旧数据）→ 原样返回，保持向后兼容；
- 只影响**读投影**，不改存储态——所以商家重新上线心跳一次即可立刻恢复。

TTL 由 ``KIWI_CATALOG_AGENT_FRESH_TTL_SECONDS`` 配置（缺省 900 秒）。商家侧心跳
间隔应显著小于它（kiwi 侧缺省 300 秒）。
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

FRESH_TTL_ENV = "KIWI_CATALOG_AGENT_FRESH_TTL_SECONDS"
DEFAULT_FRESH_TTL_SECONDS = 900
MIN_FRESH_TTL_SECONDS = 60
MAX_FRESH_TTL_SECONDS = 24 * 60 * 60


def agent_fresh_ttl_seconds() -> int:
    raw = str(os.environ.get(FRESH_TTL_ENV) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_FRESH_TTL_SECONDS
    return max(MIN_FRESH_TTL_SECONDS, min(MAX_FRESH_TTL_SECONDS, value))


def _iso_after(instant: str, seconds: int) -> str:
    base = datetime.fromisoformat(str(instant)).astimezone(UTC)
    return (base + timedelta(seconds=seconds)).replace(microsecond=0).isoformat()


def effective_freshness_state(
    record: dict[str, Any],
    *,
    now: str | None = None,
    ttl_seconds: int | None = None,
) -> str:
    """读时有效新鲜度（只降不升，见模块 docstring）。"""
    stored = str(record.get("freshness_state") or "fresh")
    if stored != "fresh":
        return stored
    last_seen = str(record.get("last_seen_at") or "")
    if last_seen == "":
        return stored
    stamp = now or datetime.now(UTC).replace(microsecond=0).isoformat()
    ttl = ttl_seconds if ttl_seconds is not None else agent_fresh_ttl_seconds()
    return "stale" if last_seen < _iso_after(stamp, -ttl) else "fresh"
