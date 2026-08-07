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

"""Listing 治理策略（产品文档 v0.4 §7.1/§21 DoD #12；评审 P2-11 定死两件事）。

Agent suspension/rejection 时**两件事都做**：
1. search join 排除（search.py 的 EXISTS 子查询，suppress 半边）；
2. governance 动作把 owned Listings 置为 SUSPENDED（本模块，标记半边）。

Agent reinstate 时**不自动恢复** Listing（Listing 与 Agent 状态独立，v0.4
§7.2）：行政恢复只解除 Agent 域；publisher 需重新 publish（或显式治理动作
恢复）才回到 ACTIVE。
"""

from __future__ import annotations

import sqlite3

from kiwi_catalog.db.session import now_iso
from kiwi_catalog.listings.domain import SUSPENDED


def suspend_owned_listings(conn: sqlite3.Connection, owner_agent_id: str) -> int:
    """把 owner 名下 ACTIVE Listing 全部置为 SUSPENDED（DoD #12 标记半边）。

    Returns 受影响行数。幂等：已 SUSPENDED/WITHDRAWN 的不再触碰。
    """
    cursor = conn.execute(
        "update commerce_listings set publication_state = ?, updated_at = ?"
        " where owner_agent_id = ? and publication_state = 'ACTIVE'",
        (SUSPENDED, now_iso(), owner_agent_id),
    )
    return cursor.rowcount
